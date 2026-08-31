"""Clone each affected repository and apply the mechanical, verified fixes.

DRY RUN BY DEFAULT. Pass --apply to commit and push.

Unlike `clean` and `fix-gitignore`, which patch single files through the
contents API, this clones the repository and works branch by branch, so a
payload can be restored from a known-clean revision of the same file and the
result re-scanned before anything is committed.

Applies only the mechanical fixes:
  * restore a payload-carrying file from a scanner-verified clean revision
  * remove the attacker's marker line from .gitignore
  * restore the .env protection rules the payload stripped
  * untrack a committed .env file

Deliberately NOT done here, because each needs a human decision:
  CRLF normalisation, history rewriting, closing pull requests, deleting
  branches. Never force-pushes.

Every branch is re-scanned after editing and before committing; a branch the
scanner still flags, or errors on, is left uncommitted and reported.
"""
import json
import os
import shutil
import subprocess
import tempfile

from .. import gitignore, repotools

NAME = "remediate"
HELP = "clone affected repos and apply the mechanical fixes, branch by branch"

COMMIT_SUBJECT = "fix(security): remove supply-chain worm artefacts"


def add_arguments(parser):
    parser.add_argument("--plans", metavar="FILE",
                        help="remediation plans JSON (default: <data-dir>/remediation-plans.json)")
    parser.add_argument("--targets", metavar="FILE",
                        help="JSON naming tip payloads and committed .env files to fix")
    parser.add_argument("--repo", metavar="OWNER/NAME",
                        help="limit to a single repository")
    parser.add_argument("--apply", action="store_true",
                        help="commit and push; without this nothing is written")
    parser.add_argument("--committer-name", metavar="NAME",
                        help="git user.name for the fix commits "
                             "(default: whatever git is already configured with)")
    parser.add_argument("--committer-email", metavar="EMAIL",
                        help="git user.email for the fix commits")
    return parser


def _run(argv, cwd=None, check=True):
    proc = subprocess.run(argv, cwd=cwd, capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise RuntimeError("{} -> {}\n{}".format(
            " ".join(argv[:4]), proc.returncode, proc.stderr[:400]))
    return proc


def _load_targets(path):
    if not path:
        return [], []
    try:
        with open(path) as handle:
            data = json.load(handle)
    except FileNotFoundError:
        raise SystemExit("targets file not found: {}".format(path))
    return data.get("tip_payloads", []), data.get("tracked_env", [])


def _plans_to_branches(path):
    """(repo, branch) -> set of finding kinds, from a remediation plan file."""
    try:
        with open(path) as handle:
            plans = json.load(handle)
    except FileNotFoundError:
        return {}
    out = {}
    for plan in plans:
        for finding in plan.get("findings", []):
            if finding.get("kind") not in ("config-bat", "env-stripped"):
                continue
            branch = finding.get("branch", "")
            # Plan files record aggregate rows like "(all)" that name no real ref.
            if not branch or branch.startswith("("):
                continue
            out.setdefault((plan["repo"], branch), set()).add(finding["kind"])
    return out


def _repair_gitignores(repo_dir, kinds):
    """Repair every tracked .gitignore in the tree. Returns descriptions."""
    changed = []
    listing = subprocess.run(["git", "ls-files"], cwd=repo_dir,
                             capture_output=True, text=True).stdout.splitlines()
    for rel in listing:
        if os.path.basename(rel) != ".gitignore":
            continue
        full = os.path.join(repo_dir, rel)
        try:
            with open(full, "rb") as handle:
                text = handle.read().decode("utf-8", "replace")
        except OSError:
            continue

        needed, marker, env_ok = gitignore.inspect(text)
        # Only restore env rules where the plan says they were stripped.
        if not marker and (env_ok or "env-stripped" not in kinds):
            continue
        if not needed:
            continue

        repaired = gitignore.repair(text) if ("env-stripped" in kinds or not env_ok) \
            else "\n".join(l for l in text.splitlines()
                           if not gitignore.MARKER_LINE.match(l)) + "\n"
        with open(full, "wb") as handle:
            handle.write(repaired.encode("utf-8"))
        changed.append("{}: {}".format(rel, "; ".join(gitignore.reasons(text))))
    return changed


def run(args, config):
    config.require_engine()

    plans_path = args.plans or config.data("remediation-plans.json")
    tip_payloads, tracked_env = _load_targets(args.targets)

    by_repo = {}
    for (repo, branch), kinds in _plans_to_branches(plans_path).items():
        by_repo.setdefault(repo, {})[branch] = set(kinds)
    for entry in tip_payloads:
        by_repo.setdefault(entry["repo"], {}).setdefault(entry["branch"], set()).add("payload")
    for entry in tracked_env:
        by_repo.setdefault(entry["repo"], {}).setdefault(entry["branch"], set()).add("tracked-env")

    if args.repo:
        by_repo = {k: v for k, v in by_repo.items() if k == args.repo}
    if not by_repo:
        print("nothing to do: no plans at {} and no --targets given".format(plans_path))
        return 0

    totals = {"branches": 0, "changed": 0, "clean": 0, "failed": 0}

    for repo in sorted(by_repo):
        print("\n" + "=" * 78)
        print("REPO {}   ({} branch(es))".format(repo, len(by_repo[repo])))
        tmp = tempfile.mkdtemp(prefix="ioc-remedy-remediate-")
        workdir = os.path.join(tmp, "r")
        try:
            _run(["gh", "repo", "clone", repo, workdir, "--", "--no-single-branch", "-q"])
            if args.committer_email:
                _run(["git", "config", "user.email", args.committer_email], cwd=workdir)
            if args.committer_name:
                _run(["git", "config", "user.name", args.committer_name], cwd=workdir)

            pushed = []
            for branch in sorted(by_repo[repo]):
                kinds = by_repo[repo][branch]
                totals["branches"] += 1
                _run(["git", "reset", "-q", "--hard"], cwd=workdir, check=False)
                _run(["git", "clean", "-qfd"], cwd=workdir, check=False)
                switched = _run(["git", "switch", branch], cwd=workdir, check=False)
                if switched.returncode != 0:
                    print("  {:<42} SKIP (cannot switch)".format(branch[:42]))
                    totals["failed"] += 1
                    continue

                notes = []
                for entry in tip_payloads:
                    if entry["repo"] == repo and entry["branch"] == branch:
                        restored = _run(["git", "checkout", entry["clean_sha"],
                                         "--", entry["path"]], cwd=workdir, check=False)
                        notes.append("{}: {}".format(
                            entry["path"],
                            "restored from {}".format(entry["clean_sha"][:12])
                            if restored.returncode == 0 else "RESTORE FAILED"))
                for entry in tracked_env:
                    if entry["repo"] == repo and entry["branch"] == branch:
                        removed = _run(["git", "rm", "--cached", "-q", entry["path"]],
                                       cwd=workdir, check=False)
                        if removed.returncode == 0:
                            notes.append("{}: untracked (credential exposure)".format(
                                entry["path"]))
                notes += _repair_gitignores(workdir, kinds)

                if not notes:
                    print("  {:<42} already clean".format(branch[:42]))
                    totals["clean"] += 1
                    continue

                code, output = repotools.scan_tree(config, workdir)
                verdict = {0: "scan CLEAN", 1: "scan STILL FINDS",
                           2: "scan ERROR"}.get(code, "rc={}".format(code))
                print("  {:<42} {}".format(branch[:42], verdict))
                for note in notes:
                    print("       - " + note)

                if code == 2:
                    print("       !! scanner error, not committing this branch")
                    totals["failed"] += 1
                    continue
                if code == 1:
                    for line in [l for l in output.splitlines() if ": [" in l][:3]:
                        print("       residual: " + line.strip()[:110])

                if not args.apply:
                    totals["changed"] += 1
                    continue

                _run(["git", "add", "-A"], cwd=workdir)
                status = _run(["git", "status", "--porcelain"], cwd=workdir).stdout.strip()
                if not status:
                    totals["clean"] += 1
                    continue
                message = COMMIT_SUBJECT + "\n\n" + "\n".join("- " + n for n in notes)
                _run(["git", "commit", "-q", "-m", message], cwd=workdir)
                pushed.append(branch)
                totals["changed"] += 1

            if args.apply and pushed:
                proc = subprocess.run(["git", "push", "origin"] + pushed,
                                      cwd=workdir, capture_output=True, text=True)
                print("  PUSH {} -> rc={}".format(
                    ",".join(b[:20] for b in pushed), proc.returncode))
                if proc.returncode != 0:
                    print("       " + (proc.stderr or "")[:400])
                    totals["failed"] += 1
        except Exception as exc:
            print("  ERROR: {}".format(exc))
            totals["failed"] += 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 78)
    print("branches: {branches}   changed: {changed}   already clean: {clean}   "
          "failed: {failed}".format(**totals))
    if not args.apply:
        print("\nDry run only. Re-run with --apply to commit and push.")
    return 1 if totals["failed"] else 0
