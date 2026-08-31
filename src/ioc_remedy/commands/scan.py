"""Scan every branch of every reachable repository for the injected payload.

READ-ONLY. Nothing is written to GitHub.

Two selection modes, previously two separate scripts:

  configs  only build-config filenames (tailwind.config.*, vite.config.*, ...).
           Fast. Also flags a config file carrying an unusually long line even
           when no marker matches, because the payload is minified onto one line.

  broad    every JavaScript/TypeScript source file above the minimum payload
           size. Slower, but the original config-only sweep missed the payload
           in ordinary source files (routes/blockedIPs.js, eslint.config.js).

Blob SHAs are content-addressed, so a file identical across thirty branches is
fetched once. In broad mode the size already present in the tree listing rules
out blobs too small to hold the payload, at no extra request.
"""
import json
import sys

from .. import iocs
from ..ghapi import clients_for

NAME = "scan"
HELP = "scan every branch of every reachable repo for the payload (read-only)"


def add_arguments(parser):
    parser.add_argument("--mode", choices=("configs", "broad"), default="configs",
                        help="which files to inspect (default: configs)")
    parser.add_argument("--output", metavar="FILE",
                        help="where to write results (default: <data-dir>/infected-<mode>.json)")
    parser.add_argument("--repo", action="append", dest="repos", metavar="OWNER/NAME",
                        help="limit the sweep to this repo; repeatable")
    return parser


def _select(mode, path, size):
    """True if this tree entry is worth fetching."""
    if any(part in path for part in iocs.SKIP_PATH_PARTS):
        return False
    if mode == "configs":
        return any(hint in path for hint in iocs.CONFIG_HINTS)
    return iocs.is_scannable(path, size)


def _classify(mode, body):
    """(markers, longest_line) if suspicious, else None."""
    hits = iocs.find_markers(body)
    longest = iocs.longest_line(body)
    if hits:
        return (hits, longest)
    # Long-line heuristic applies to build configs only; on arbitrary source
    # files it fires on minified vendored code and is unusable.
    if mode == "configs" and longest > iocs.LONG_LINE_THRESHOLD:
        return ([], longest)
    return None


def run(args, config):
    clients = clients_for(config)

    # Union the repositories visible to each configured account, remembering
    # which client can actually reach each one.
    reachable = {}
    for login, client in clients.items():
        for full_name, is_admin, archived in client.repos():
            if full_name not in reachable:
                reachable[full_name] = (client, is_admin, login)

    names = sorted(reachable)
    if args.repos:
        wanted = set(args.repos)
        names = [n for n in names if n in wanted]
        missing = wanted - set(names)
        for name in sorted(missing):
            print("  not reachable: {}".format(name), file=sys.stderr)

    print("scanning {} repos in {} mode\n".format(len(names), args.mode), file=sys.stderr)

    findings = []
    blob_cache = {}
    fetched = skipped_small = 0

    for index, repo in enumerate(names, 1):
        client, is_admin, via = reachable[repo]
        branches = client.branches(repo)
        if not branches:
            print("  [{}/{}] {:<52} UNREACHABLE".format(index, len(names), repo),
                  file=sys.stderr)
            continue

        hits_here = 0
        for branch in branches:
            for path, sha, size in client.tree(repo, branch):
                if not _select(args.mode, path, size):
                    if args.mode == "broad":
                        skipped_small += 1
                    continue

                if sha not in blob_cache:
                    body = client.blob(repo, sha)
                    fetched += 1
                    blob_cache[sha] = _classify(args.mode, body) if body else None

                result = blob_cache.get(sha)
                if result:
                    markers, longest = result
                    findings.append({"repo": repo, "branch": branch, "path": path,
                                     "blob": sha, "longest_line": longest,
                                     "iocs": markers, "admin": is_admin, "via": via})
                    hits_here += 1

        flag = "  <-- INFECTED ({})".format(hits_here) if hits_here else ""
        print("  [{}/{}] {:<52} {:>3} branches{}".format(
            index, len(names), repo, len(branches), flag), file=sys.stderr)

    out_path = args.output or config.data("infected-{}.json".format(args.mode))
    with open(out_path, "w") as handle:
        json.dump(findings, handle, indent=2)

    _summarise(findings, fetched, skipped_small, out_path)
    return 1 if findings else 0


def _summarise(findings, fetched, skipped_small, out_path):
    by_repo = {}
    for finding in findings:
        by_repo.setdefault(finding["repo"], []).append(finding)

    print("\n" + "=" * 78, file=sys.stderr)
    print("blobs fetched: {}   skipped (too small): {}".format(fetched, skipped_small),
          file=sys.stderr)
    print("INFECTED: {} file/branch combinations across {} repos\n".format(
        len(findings), len(by_repo)), file=sys.stderr)

    for repo in sorted(by_repo):
        rows = by_repo[repo]
        access = "admin" if rows[0]["admin"] else "PUSH-ONLY"
        paths = sorted({r["path"] for r in rows})
        print("  {:<46} {:<10} {} branches, {} files".format(
            repo, access, len({r["branch"] for r in rows}), len(paths)), file=sys.stderr)
        for path in paths:
            print("        {}".format(path), file=sys.stderr)

    print("\nsaved: {}".format(out_path), file=sys.stderr)
