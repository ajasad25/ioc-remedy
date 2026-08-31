"""Scan every branch of every reachable repository using the ioc-guard engine.

READ-ONLY. Same sweep as `scan --mode broad`, but classification is delegated to
ioc-guard's own pattern list and structural heuristics instead of this package's
marker list. Prefer this when it is available: the literal marker list is a
floor, and the structural heuristics catch packed variants whose strings never
appear as plain text.

Requires a checkout of https://github.com/ajasad25/ioc-guard. Point at it with
--engine or IOC_REMEDY_ENGINE; the default is ~/src/ioc-guard.
"""
import json
import pathlib
import sys

from .. import iocs
from ..ghapi import clients_for

NAME = "scan-engine"
HELP = "scan using the ioc-guard pattern engine and heuristics (read-only)"


def add_arguments(parser):
    parser.add_argument("--output", metavar="FILE",
                        help="where to write results (default: <data-dir>/infected-engine.json)")
    parser.add_argument("--repo", action="append", dest="repos", metavar="OWNER/NAME",
                        help="limit the sweep to this repo; repeatable")
    return parser


def _load_engine(config):
    """Import ioc-guard from the configured checkout."""
    config.require_engine()
    sys.path.insert(0, str(config.engine))
    try:
        from ioc_guard.patterns import load_patterns, scan_text
        from ioc_guard.heuristics import run_heuristics
    except ImportError as exc:
        raise SystemExit("found {} but could not import ioc_guard: {}".format(
            config.engine, exc))
    patterns = load_patterns(pathlib.Path(config.engine) / "iocs.txt")
    return patterns, scan_text, run_heuristics


def run(args, config):
    patterns, scan_text, run_heuristics = _load_engine(config)
    clients = clients_for(config)

    reachable = {}
    for login, client in clients.items():
        for full_name, is_admin, archived in client.repos():
            if full_name not in reachable:
                reachable[full_name] = (client, is_admin, login)

    names = sorted(reachable)
    if args.repos:
        wanted = set(args.repos)
        names = [n for n in names if n in wanted]

    print("scanning {} distinct repos across {} account(s)\n".format(
        len(names), len(clients)), file=sys.stderr)

    findings, blob_cache = [], {}
    fetched = 0

    for index, repo in enumerate(names, 1):
        client, is_admin, via = reachable[repo]
        branches = client.branches(repo)
        if not branches:
            print("  [{}/{}] {:<52} UNREACHABLE".format(index, len(names), repo),
                  file=sys.stderr)
            continue

        hits_here = 0
        for branch in branches:
            for path, sha, size in client.tree(repo, branch, timeout=250):
                if not iocs.is_scannable(path, size):
                    continue
                if sha not in blob_cache:
                    body = client.blob(repo, sha)
                    fetched += 1
                    rules = None
                    if body:
                        found = scan_text(body, patterns, path) + run_heuristics(body, path)
                        if found:
                            rules = sorted({f.rule for f in found})
                    blob_cache[sha] = rules

                rules = blob_cache.get(sha)
                if rules:
                    findings.append({"repo": repo, "branch": branch, "path": path,
                                     "blob": sha, "rules": rules,
                                     "admin": is_admin, "via": via})
                    hits_here += 1

        flag = "  <-- INFECTED ({})".format(hits_here) if hits_here else ""
        print("  [{}/{}] {:<52} {:>3} branches{}".format(
            index, len(names), repo, len(branches), flag), file=sys.stderr)

    out_path = args.output or config.data("infected-engine.json")
    with open(out_path, "w") as handle:
        json.dump(findings, handle, indent=2)

    by_repo = {}
    for finding in findings:
        by_repo.setdefault(finding["repo"], []).append(finding)

    print("\n" + "=" * 78, file=sys.stderr)
    print("blobs fetched: {}".format(fetched), file=sys.stderr)
    print("INFECTED: {} file/branch combos across {} repos\n".format(
        len(findings), len(by_repo)), file=sys.stderr)
    for repo in sorted(by_repo):
        rows = by_repo[repo]
        access = "admin" if rows[0]["admin"] else "PUSH-ONLY"
        print("  {:<46} {:<10} {} branches, {} files".format(
            repo, access, len({r["branch"] for r in rows}),
            len({r["path"] for r in rows})), file=sys.stderr)
    print("\nsaved: {}".format(out_path), file=sys.stderr)
    return 1 if findings else 0
