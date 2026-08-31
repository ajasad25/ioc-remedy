"""Self-discovering remediation: scan each branch and fix exactly what is found.

DRY RUN BY DEFAULT. Pass --apply to commit and push.

This trusts no precomputed file list. Every branch of the repository is cloned,
scanned with the ioc-guard engine, and remediated according to what the scanner
actually reports -- which is what you want when the inventory is stale, or when
you are cleaning a repository nobody scanned before.

Per branch:
  payload-carrying file  restore from the newest ancestor commit whose version of
                         that path the scanner passes; if no clean ancestor
                         exists within the history window, cut the padded tail
                         the loader is appended behind; if neither is possible,
                         say so and leave it for a human
  .gitignore             remove the attacker's marker line, restore .env rules
  committed .env         untrack it

Never rewrites history. Never force-pushes. Every branch is re-scanned after
editing and before committing, and a branch the scanner errors on is never
committed.
"""
import os

from .. import gitignore, repotools

NAME = "remediate-auto"
HELP = "scan every branch of a repo and remediate exactly what the scanner finds"

COMMIT_SUBJECT = "fix(security): remove supply-chain worm artefacts"
PUSH_CHUNK = 25


def add_arguments(parser):
    parser.add_argument("repos", nargs="*", metavar="OWNER/NAME",
                        help="repositories to remediate")
    parser.add_argument("--from-inventory", metavar="FILE",
                        help="also take every repo marked infected in this inventory JSON")
    parser.add_argument("--branch", action="append", dest="branches", metavar="NAME",
                        help="limit to this branch; repeatable")
    parser.add_argument("--apply", action="store_true",
                        help="commit and push; without this nothing is written")
    parser.add_argument("--max-history", type=int, default=repotools.MAX_HISTORY,
                        metavar="N",
                        help="commits to search for a clean copy of a file "
                             "(default: %(default)s)")
    parser.add_argument("--committer-name", metavar="NAME",
                        help="git user.name for the fix commits "
                             "(default: whatever git is already configured with)")
    parser.add_argument("--committer-email", metavar="EMAIL",
                        help="git user.email for the fix commits")
    return parser


def _repos_from_inventory(path):
    import json
    with open(path) as handle:
        inventory = json.load(handle)
    return [entry["repo"] for entry in inventory if entry.get("infected")]


def _remediate_branch(config, args, workdir, branch, cache, stats):
    repotools.run(["git", "reset", "-q", "--hard"], cwd=workdir)
    repotools.run(["git", "clean", "-qfd"], cwd=workdir)
    if repotools.run(["git", "switch", "-q", branch], cwd=workdir).returncode != 0:
        stats["failed"] += 1
        return False

    code, output = repotools.scan_tree(config, workdir)
    if code == 0:
        stats["clean"] += 1
        return False
    if code == 2:
        print("    {:<40} scanner ERROR, skipped".format(branch[:40]))
        stats["failed"] += 1
        return False

    found = repotools.parse_findings(output)
    payload_paths = sorted({
        path for path, rule in found
        if (rule.startswith("ioc:") or rule.startswith("heuristic:"))
        and os.path.basename(path) != ".gitignore"})

    notes = []
    for rel in payload_paths:
        full = os.path.join(workdir, rel)
        if not os.path.exists(full):
            continue
        sha = repotools.clean_ancestor(config, workdir, rel, cache, args.max_history)
        if sha:
            if repotools.run(["git", "checkout", sha, "--", rel],
                             cwd=workdir).returncode == 0:
                notes.append("{}: restored from {}".format(rel, sha[:12]))
            continue
        cuts = repotools.strip_payload(full)
        if cuts:
            notes.append("{}: no clean ancestor in {} commits; stripped injected "
                         "tail ({})".format(rel, args.max_history, "; ".join(cuts)))
        else:
            notes.append("{}: NO clean ancestor within {} commits and no padded tail "
                         "to strip -- NEEDS A HUMAN".format(rel, args.max_history))

    notes += repotools.untrack_env_files(workdir)
    notes += _repair_gitignores(workdir)

    if not notes:
        stats["clean"] += 1
        return False

    recode, reoutput = repotools.scan_tree(config, workdir)
    verdict = {0: "CLEAN", 1: "residual", 2: "ERROR"}.get(recode, str(recode))
    print("    {:<40} {}".format(branch[:40], verdict))
    for note in notes[:4]:
        print("        - " + note)

    if recode == 2:
        stats["failed"] += 1
        return False
    if recode == 1:
        stats["residual"] += 1
        for line in [l for l in reoutput.splitlines() if ": [" in l][:2]:
            print("        residual: " + line.strip()[:100])

    if not args.apply:
        stats["fixed"] += 1
        return False

    repotools.run(["git", "add", "-A"], cwd=workdir)
    if not repotools.run(["git", "status", "--porcelain"], cwd=workdir).stdout.strip():
        stats["clean"] += 1
        return False

    message = COMMIT_SUBJECT + "\n\n" + "\n".join("- " + n for n in notes)
    repotools.run(["git", "commit", "-q", "-m", message], cwd=workdir)
    stats["fixed"] += 1
    return True


def _repair_gitignores(workdir):
    """Repair every tracked .gitignore in the working tree.

    The .env rules are restored whenever they are absent, not only when the
    scanner attributed their loss to the attacker: a repository that never
    ignored .env is exposed either way, and the original code reached the same
    behaviour by passing `want_env or True`.
    """
    changed = []
    listing = repotools.run(["git", "ls-files"], cwd=workdir).stdout.splitlines()
    for rel in listing:
        if os.path.basename(rel) != ".gitignore":
            continue
        full = os.path.join(workdir, rel)
        try:
            with open(full, "rb") as handle:
                text = handle.read().decode("utf-8", "replace")
        except OSError:
            continue
        needed, _marker, _env = gitignore.inspect(text)
        if not needed:
            continue
        why = gitignore.reasons(text)
        with open(full, "wb") as handle:
            handle.write(gitignore.repair(text).encode("utf-8"))
        changed.append("{}: {}".format(rel, ", ".join(why)))
    return changed


def _remediate_repo(config, args, repo):
    import shutil
    import tempfile

    stats = {"branches": 0, "fixed": 0, "clean": 0, "failed": 0, "residual": 0}
    tmp = tempfile.mkdtemp(prefix="ioc-remedy-auto-")
    workdir = os.path.join(tmp, "r")
    cache = {}
    try:
        cloned = repotools.run(
            ["gh", "repo", "clone", repo, workdir, "--", "--no-single-branch", "-q"])
        if cloned.returncode != 0:
            print("  CLONE FAILED: {}".format(cloned.stderr.strip()[:120]))
            return stats
        repotools.set_identity(workdir, args.committer_name, args.committer_email)

        branches = repotools.remote_branches(workdir)
        if args.branches:
            wanted = set(args.branches)
            branches = [b for b in branches if b in wanted]

        pushed = []
        for branch in branches:
            stats["branches"] += 1
            if _remediate_branch(config, args, workdir, branch, cache, stats):
                pushed.append(branch)

        if args.apply and pushed:
            for start in range(0, len(pushed), PUSH_CHUNK):
                chunk = pushed[start:start + PUSH_CHUNK]
                proc = repotools.run(["git", "push", "origin"] + chunk, cwd=workdir)
                print("    PUSH {} branch(es) -> rc={} {}".format(
                    len(chunk), proc.returncode,
                    (proc.stderr or "").strip()[:100] if proc.returncode else ""))
                if proc.returncode:
                    stats["failed"] += 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return stats


def run(args, config):
    config.require_engine()

    repos = list(args.repos or [])
    if args.from_inventory:
        try:
            repos += _repos_from_inventory(args.from_inventory)
        except FileNotFoundError:
            raise SystemExit("inventory not found: {}".format(args.from_inventory))
    repos = sorted(set(repos))

    if not repos:
        raise SystemExit("no repositories given; pass OWNER/NAME or --from-inventory FILE")

    overall = {}
    for repo in repos:
        print("\n=== {}".format(repo))
        stats = _remediate_repo(config, args, repo)
        overall[repo] = stats
        print("    -> {branches} branches, {fixed} fixed, {clean} already clean, "
              "{residual} residual, {failed} failed".format(**stats))

    print("\n" + "=" * 72)
    for repo, stats in overall.items():
        print("  {:<46} fixed={:<4} clean={:<4} resid={:<3} fail={}".format(
            repo, stats["fixed"], stats["clean"], stats["residual"], stats["failed"]))
    print("DRY RUN" if not args.apply else "APPLIED")

    if any(s["failed"] or s["residual"] for s in overall.values()):
        return 1
    return 0
