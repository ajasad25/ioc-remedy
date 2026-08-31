"""Point every force-pushed ref back at its pre-attack commit.

DRY RUN BY DEFAULT. Pass --execute to apply.

Uses the git-refs API (PATCH .../git/refs/heads/<branch> with force), which can
point a ref at any object still in the repository's object store -- including the
orphaned pre-attack commits the attacker's force-push abandoned.

Fully reversible: the attacker SHA displaced by each restore is written to an
undo log. Nothing is deleted, and a ref whose pre-attack object has already been
garbage-collected is skipped rather than guessed at.

Input is a restore manifest: records of {repo, ref, before, after, timestamp,
owned_by_user, owner}, as produced from the audit log of the force-push events.
"""
import collections
import json

from ..ghapi import clients_for

NAME = "restore"
HELP = "reset force-pushed refs to their pre-attack commits (reversible)"


def add_arguments(parser):
    parser.add_argument("--input", metavar="FILE",
                        help="restore manifest (default: <data-dir>/restore-manifest.json)")
    parser.add_argument("--undo-log", metavar="FILE",
                        help="where to record displaced SHAs (default: <data-dir>/undo-log.json)")
    parser.add_argument("--execute", action="store_true",
                        help="actually move the refs; without this nothing changes")
    parser.add_argument("--only-mine", action="store_true",
                        help="restrict to repos the manifest marks as owned by you")
    return parser


def _earliest_per_ref(manifest):
    """The earliest event per (repo, ref) holds the true pre-attack SHA."""
    by_ref = {}
    for record in sorted(manifest, key=lambda r: r["timestamp"]):
        key = (record["repo"], record["ref"])
        by_ref.setdefault(key, record)
    return by_ref


def run(args, config):
    source = args.input or config.data("restore-manifest.json")
    try:
        with open(source) as handle:
            manifest = json.load(handle)
    except FileNotFoundError:
        raise SystemExit("cannot read restore manifest: {}".format(source))

    client = next(iter(clients_for(config).values()))

    print("{}{}\n".format(
        "MODE: EXECUTE" if args.execute else "MODE: DRY RUN (no changes)",
        "  [ONLY REPOS YOU OWN]" if args.only_mine else ""))

    todo, skip = [], []
    for (repo, ref), record in sorted(_earliest_per_ref(manifest).items()):
        if args.only_mine and not record.get("owned_by_user"):
            continue
        before = record.get("before")
        if not before or set(before) == {"0"}:
            skip.append((record, "no pre-attack SHA (branch created by attacker)"))
            continue

        branch = ref.replace("refs/heads/", "")
        if not client.api("repos/{}/git/commits/{}".format(repo, before), jq=".sha").ok:
            skip.append((record, "pre-attack object no longer on GitHub (garbage collected)"))
            continue

        current = client.api("repos/{}/git/ref/heads/{}".format(repo, branch),
                             jq=".object.sha")
        if not current.ok:
            skip.append((record, "branch no longer exists on remote"))
            continue
        if current.stdout == before:
            skip.append((record, "already at pre-attack commit"))
            continue

        record = dict(record, current=current.stdout)
        todo.append(record)

    by_repo = collections.OrderedDict()
    for record in todo:
        by_repo.setdefault(record["repo"], []).append(record)

    for repo, items in by_repo.items():
        owner = "MINE" if items[0].get("owned_by_user") else "owner:{}".format(
            items[0].get("owner", "?"))
        print("  {}   [{}]   {} refs".format(repo, owner, len(items)))
        for record in items[:60]:
            branch = record["ref"].replace("refs/heads/", "")
            print("      {:<46} {}  ->  {}".format(
                branch, record["current"][:10], record["before"][:10]))

    print("\n  refs to restore : {}".format(len(todo)))
    print("  refs skipped    : {}".format(len(skip)))
    for record, why in skip[:25]:
        print("      SKIP {}  {}  ({})".format(
            record["repo"], record["ref"].replace("refs/heads/", ""), why))

    if not args.execute:
        print("\nDry run only. Re-run with --execute to apply.")
        return 0

    undo, restored, failed = [], 0, 0
    print("\n--- applying ---")
    for record in todo:
        repo = record["repo"]
        branch = record["ref"].replace("refs/heads/", "")
        result = client.api("repos/{}/git/refs/heads/{}".format(repo, branch),
                            method="PATCH",
                            fields={"sha": record["before"], "force": True},
                            jq=".object.sha")
        if result.ok and result.stdout.startswith(record["before"][:10]):
            restored += 1
            undo.append({"repo": repo, "branch": branch,
                         "restored_to": record["before"],
                         "was_attacker_sha": record["current"]})
            print("  OK    {}  {}  -> {}".format(repo, branch, result.stdout[:10]))
        else:
            failed += 1
            print("  FAIL  {}  {}  :: {}".format(
                repo, branch, (result.stderr or result.stdout)[:160]))

    undo_path = args.undo_log or config.data("undo-log.json")
    with open(undo_path, "w") as handle:
        json.dump(undo, handle, indent=2)
    print("\n  restored: {}   failed: {}".format(restored, failed))
    print("  undo log: {}".format(undo_path))
    return 1 if failed else 0
