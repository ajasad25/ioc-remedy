"""Verify that nothing the attacker left behind survives on any branch.

READ-ONLY. Exit code 1 if anything is still dirty, so this works as a CI gate.

For every affected repository, every branch is checked for:

  1. .gitignore carrying the attacker's `config.bat` marker, or having lost its
     .env rules -- the payload strips those so that a subsequent commit stages
     the developer's environment file
  2. a committed .env file
  3. the payload itself in any build-config file, by marker match or by the
     long-line heuristic

The repository list comes from a scan result or a restore manifest. Before the
refactor this read a hardcoded per-session scratch path that no longer exists,
which left this tool unrunnable.
"""
import json

from .. import iocs
from ..ghapi import clients_for

NAME = "verify"
HELP = "check every branch of affected repos for surviving attacker artefacts"

MAX_CONFIGS_PER_BRANCH = 25


def add_arguments(parser):
    parser.add_argument("--input", metavar="FILE",
                        help="scan result or restore manifest listing the repos to check "
                             "(default: <data-dir>/infected-configs.json)")
    parser.add_argument("--repo", action="append", dest="repos", metavar="OWNER/NAME",
                        help="check this repo instead of reading a file; repeatable")
    return parser


def _repos_from(path):
    with open(path) as handle:
        records = json.load(handle)
    return sorted({r["repo"] for r in records if isinstance(r, dict) and "repo" in r})


def run(args, config):
    if args.repos:
        repos = sorted(set(args.repos))
    else:
        source = args.input or config.data("infected-configs.json")
        try:
            repos = _repos_from(source)
        except FileNotFoundError:
            raise SystemExit(
                "no repo list: {} does not exist.\n"
                "Run a scan first, or pass --repo OWNER/NAME.".format(source))

    client = next(iter(clients_for(config).values()))
    findings = []
    checked_branches = checked_files = 0

    for repo in repos:
        branches = client.branches(repo)
        if not branches:
            findings.append((repo, "-", "-", "COULD NOT LIST BRANCHES"))
            continue

        for branch in branches:
            checked_branches += 1

            gitignore = client.contents(repo, ".gitignore", branch)
            if gitignore is not None:
                low = gitignore.lower()
                if "config.bat" in low:
                    findings.append((repo, branch, ".gitignore",
                                     "ATTACKER MARKER config.bat"))
                if ".env" not in low:
                    findings.append((repo, branch, ".gitignore",
                                     ".env no longer ignored"))

            env = client.api("repos/{}/contents/.env?ref={}".format(repo, branch),
                             jq=".size")
            if env.ok and env.stdout.strip().isdigit():
                findings.append((repo, branch, ".env",
                                 "COMMITTED SECRET FILE ({} bytes)".format(env.stdout)))

            configs = [path for path, _sha, _size in client.tree(repo, branch, timeout=120)
                       if path.endswith(iocs.CONFIG_SUFFIXES)
                       and not any(part in path for part in iocs.SKIP_PATH_PARTS)]
            for path in configs[:MAX_CONFIGS_PER_BRANCH]:
                body = client.contents(repo, path, branch)
                if body is None:
                    continue
                checked_files += 1
                suspicious, reasons = iocs.looks_infected(body)
                if suspicious:
                    findings.append((repo, branch, path, "; ".join(reasons)))
            if len(configs) > MAX_CONFIGS_PER_BRANCH:
                findings.append((repo, branch, "-",
                                 "NOT FULLY CHECKED: {} config files, only the first "
                                 "{} inspected".format(len(configs), MAX_CONFIGS_PER_BRANCH)))

    print("\nchecked {} branches across {} repos, {} config files\n".format(
        checked_branches, len(repos), checked_files))
    if not findings:
        print("  PASS -- no attacker artefacts found on any branch of any affected repo.")
        return 0

    print("  {} ISSUE(S) REMAIN:\n".format(len(findings)))
    for repo, branch, path, why in findings:
        print("    {:<44} {:<28} {:<34} {}".format(repo, branch, path, why))
    return 1
