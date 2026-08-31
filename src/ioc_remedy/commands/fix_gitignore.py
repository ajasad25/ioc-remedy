"""Repair .gitignore files the attacker tampered with, via the contents API.

DRY RUN BY DEFAULT. Pass --execute to commit.

Removes the `config.bat` marker and restores the `.env` ignore rules the payload
stripped. Restoring those rules is the urgent half: without them the next
`git add -A` stages a developer's environment file and publishes live
credentials.
"""
import base64
import json

from .. import gitignore
from ..ghapi import clients_for

NAME = "fix-gitignore"
HELP = "restore .env rules and remove the attacker's marker from .gitignore"

COMMIT_MESSAGE = ("security: restore .env ignore rules and remove injected marker")


def add_arguments(parser):
    parser.add_argument("--input", metavar="FILE",
                        help="scan result naming the repo/branch pairs to check "
                             "(default: <data-dir>/infected-configs.json)")
    parser.add_argument("--execute", action="store_true",
                        help="actually commit; without this nothing is written")
    return parser


def run(args, config):
    source = args.input or config.data("infected-configs.json")
    try:
        with open(source) as handle:
            infected = json.load(handle)
    except FileNotFoundError:
        raise SystemExit("cannot read {}: run a scan first".format(source))

    targets = sorted({(r["repo"], r["branch"]) for r in infected})
    client = next(iter(clients_for(config).values()))

    print("{} -- checking .gitignore on {} repo/branch pairs\n".format(
        "EXECUTE" if args.execute else "DRY RUN", len(targets)))

    fixed = skipped = failed = 0
    for repo, branch in targets:
        text = client.contents(repo, ".gitignore", branch)
        if text is None:
            skipped += 1
            continue

        needed, _marker, _env = gitignore.inspect(text)
        if not needed:
            skipped += 1
            continue

        why = "; ".join(gitignore.reasons(text))
        print("  {} {} [{}] :: {}".format(
            "FIX " if args.execute else "WOULD FIX", repo, branch, why))

        if not args.execute:
            fixed += 1
            continue

        sha = client.content_sha(repo, ".gitignore", branch)
        if not sha:
            failed += 1
            print("        FAILED :: cannot read blob sha")
            continue

        repaired = gitignore.repair(text)
        result = client.api_json(
            "repos/{}/contents/.gitignore".format(repo),
            {"message": COMMIT_MESSAGE,
             "content": base64.b64encode(repaired.encode()).decode(),
             "sha": sha,
             "branch": branch},
            jq=".commit.sha", timeout=150)
        if result.ok and result.stdout:
            fixed += 1
            print("        committed {}".format(result.stdout[:10]))
        else:
            failed += 1
            print("        FAILED :: {}".format((result.stderr or result.stdout)[:150]))

    print("\n  {}: {}   already-ok/skipped: {}   failed: {}".format(
        "fixed" if args.execute else "would fix", fixed, skipped, failed))
    if not args.execute:
        print("\nDry run only. Re-run with --execute.")
    return 1 if failed else 0
