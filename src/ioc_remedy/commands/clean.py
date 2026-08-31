"""Strip the injected loader from infected files on GitHub, via the contents API.

DRY RUN BY DEFAULT. Pass --execute to commit.

The payload is appended to an existing line behind a long run of whitespace, so
the original source is recoverable by cutting the line back to where that run
starts. Where the attacker left no whitespace wall, the line is cut at the first
marker and trimmed back to the last plausible statement end.

This edits the branch tip only. It does not rewrite history: an old commit still
holds the payload, which is the correct trade-off for a shared branch. Use
`restore` when the whole ref needs to go back to its pre-attack commit.
"""
import base64
import json
import re
import urllib.parse

from .. import iocs
from ..ghapi import clients_for

NAME = "clean"
HELP = "remove the injected loader from infected files at the branch tip"

WHITESPACE_WALL = re.compile(r"[ \t]{20,}")
COMMIT_MESSAGE = "security: remove injected obfuscated loader from build config"


def add_arguments(parser):
    parser.add_argument("--input", metavar="FILE",
                        help="scan result listing infected files "
                             "(default: <data-dir>/infected-configs.json)")
    parser.add_argument("--execute", action="store_true",
                        help="actually commit; without this nothing is written")
    return parser


def strip_payload(body):
    """Return (cleaned_text, lines_changed), or (None, 0) if nothing to do."""
    lines = body.split("\n")
    changed = 0
    for index, line in enumerate(lines):
        if len(line) <= iocs.LONG_LINE_THRESHOLD:
            continue
        low = line.lower()
        if not iocs.find_markers(line):
            continue

        wall = WHITESPACE_WALL.search(line)
        if wall:
            prefix = line[:wall.start()].rstrip()
        else:
            positions = [low.find(m) for m in iocs.MARKERS if low.find(m) != -1]
            first = min(positions, default=-1)
            if first <= 0:
                continue
            prefix = line[:first].rstrip()
            cut = max(prefix.rfind("};"), prefix.rfind("});"), prefix.rfind(";"))
            if cut != -1:
                prefix = prefix[:cut + (2 if prefix[cut:cut + 2] == "};" else 1)]
        lines[index] = prefix
        changed += 1
    return ("\n".join(lines), changed) if changed else (None, 0)


def run(args, config):
    source = args.input or config.data("infected-configs.json")
    try:
        with open(source) as handle:
            infected = json.load(handle)
    except FileNotFoundError:
        raise SystemExit("cannot read {}: run a scan first".format(source))

    seen, targets = set(), []
    for record in infected:
        key = (record["repo"], record["branch"], record["path"])
        if key not in seen:
            seen.add(key)
            targets.append(record)

    client = next(iter(clients_for(config).values()))
    print("{} -- {} infected file/branch targets\n".format(
        "EXECUTE" if args.execute else "DRY RUN", len(targets)))

    committed = failed = skipped = would = 0
    for target in targets:
        repo, branch, path = target["repo"], target["branch"], target["path"]
        body = client.contents(repo, path, branch)
        if body is None:
            print("  SKIP  {} {} {} :: cannot fetch".format(repo, branch, path))
            skipped += 1
            continue

        cleaned, _count = strip_payload(body)
        if not cleaned:
            print("  SKIP  {} {} {} :: already clean".format(repo, branch, path))
            skipped += 1
            continue

        before = iocs.longest_line(body)
        after = iocs.longest_line(cleaned)
        print("  {}  {} {} {}  longest {} -> {}".format(
            "FIX " if args.execute else "WOULD FIX", repo, branch, path, before, after))

        if not args.execute:
            would += 1
            continue

        sha = client.content_sha(repo, path, branch)
        if not sha:
            print("        FAILED :: cannot read blob sha")
            failed += 1
            continue

        result = client.api_json(
            "repos/{}/contents/{}".format(repo, urllib.parse.quote(path, safe="/")),
            {"message": COMMIT_MESSAGE,
             "content": base64.b64encode(cleaned.encode()).decode(),
             "sha": sha,
             "branch": branch},
            jq=".commit.sha", timeout=150)
        if result.ok and result.stdout:
            committed += 1
            print("        committed {}".format(result.stdout[:10]))
        else:
            failed += 1
            print("        FAILED :: {}".format((result.stderr or result.stdout)[:160]))

    print("\n  {}: {}   skipped: {}   failed: {}".format(
        "committed" if args.execute else "would fix",
        committed if args.execute else would, skipped, failed))
    if not args.execute:
        print("\nDry run only. Re-run with --execute to commit.")
    return 1 if failed else 0
