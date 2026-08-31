"""Roll preventative controls out across every repository you administer.

DRY RUN BY DEFAULT. Pass --apply to make changes.

Two independent phases:

  workflow  add a CI workflow that scans every push and pull request
  ruleset   forbid force-pushes and branch deletion on all branches, and require
            a passing scan plus a pull request on the default branch

The ruleset phase is the one that would have prevented this incident: the payload
arrived by force-push onto existing branches, rewriting commits in place while
keeping the original author and timestamp.

Repositories whose plan forbids rulesets (private repos on the free plan) are
reported as blocked with the reason, never silently skipped -- those repos have
no server-side protection at all, and saying so is the point.
"""
import sys

from ..ghapi import clients_for

NAME = "rollout"
HELP = "add scanning CI and force-push protection to every repo you administer"

WORKFLOW_PATH = ".github/workflows/ioc-scan.yml"
DEFAULT_WORKFLOW_REF = "ajasad25/ioc-guard/.github/workflows/scan.yml@main"

# Captured from a real completed check-run, not derived from the workflow name.
DEFAULT_CHECK_CONTEXT = "ioc-scan / scan"

NO_FORCE_PUSH = {
    "name": "no-force-push",
    "target": "branch",
    "enforcement": "active",
    "bypass_actors": [],
    "conditions": {"ref_name": {"include": ["~ALL"], "exclude": []}},
    "rules": [{"type": "non_fast_forward"}, {"type": "deletion"}],
}


def add_arguments(parser):
    parser.add_argument("--phase", required=True, choices=("workflow", "ruleset"),
                        help="which control to roll out")
    parser.add_argument("--apply", action="store_true",
                        help="actually make changes; without this nothing is written")
    parser.add_argument("--workflow-ref", default=DEFAULT_WORKFLOW_REF, metavar="REF",
                        help="reusable workflow to call (default: %(default)s)")
    parser.add_argument("--check-context", default=DEFAULT_CHECK_CONTEXT, metavar="NAME",
                        help="status check the default branch must pass "
                             "(default: %(default)s)")
    parser.add_argument("--skip", action="append", dest="skips", default=[],
                        metavar="OWNER/NAME",
                        help="repo to leave alone; repeatable. Use for a fork whose "
                             "upstream code trips the scanner, where a required check "
                             "could never pass and would block every merge")
    return parser


def workflow_body(workflow_ref):
    return ("name: IOC Scan\n"
            "on:\n"
            "  push:\n"
            "  pull_request:\n"
            "  schedule:\n"
            "    - cron: '17 4 * * *'\n"
            "jobs:\n"
            "  ioc-scan:\n"
            "    uses: {}\n".format(workflow_ref))


def protect_default(check_context):
    return {
        "name": "protect-default",
        "target": "branch",
        "enforcement": "active",
        "bypass_actors": [],
        "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
        "rules": [
            {"type": "pull_request",
             "parameters": {"required_approving_review_count": 0,
                            "dismiss_stale_reviews_on_push": True,
                            "require_code_owner_review": False,
                            "require_last_push_approval": False,
                            "required_review_thread_resolution": False}},
            {"type": "required_status_checks",
             "parameters": {"strict_required_status_checks_policy": True,
                            "required_status_checks": [{"context": check_context}]}},
        ],
    }


def admin_repos(client, skips):
    result = client.api(
        "user/repos?affiliation=owner,collaborator,organization_member&per_page=100",
        jq=r'.[] | select(.permissions.admin == true) | select(.archived == false) '
           r'| "\(.full_name)\t\(.private)\t\(.default_branch)"',
        paginate=True, timeout=300)
    if not result.ok:
        raise SystemExit("cannot list repos: " + result.stderr)
    repos = []
    for line in result.lines():
        parts = line.split("\t")
        if len(parts) != 3 or parts[0] in skips:
            continue
        repos.append({"name": parts[0], "private": parts[1] == "true",
                      "branch": parts[2]})
    return sorted(repos, key=lambda r: r["name"])


def phase_workflow(client, args, repos):
    import base64
    body = workflow_body(args.workflow_ref)
    changed = current = failed = 0
    print("{:<52} {:<8} {}".format("REPO", "VIS", "ACTION"))
    for repo in repos:
        visibility = "private" if repo["private"] else "public"
        existing = client.api("repos/{}/contents/{}".format(repo["name"], WORKFLOW_PATH))
        data = existing.json() if existing.ok else None
        if data:
            import base64 as b64
            text = b64.b64decode(data["content"]).decode("utf-8", "replace")
            if text.strip() == body.strip():
                print("{:<52} {:<8} up to date".format(repo["name"], visibility))
                current += 1
                continue
        action = "update" if data else "add"
        if not args.apply:
            print("{:<52} {:<8} would {}".format(repo["name"], visibility, action))
            changed += 1
            continue
        payload = {"message": "ci: add ioc-guard scan on push and pull request",
                   "content": base64.b64encode(body.encode()).decode(),
                   "branch": repo["branch"]}
        if data:
            payload["sha"] = data["sha"]
        put = client.api_json(
            "repos/{}/contents/{}".format(repo["name"], WORKFLOW_PATH), payload)
        ok, err = put.ok, put.stderr
        if ok:
            print("{:<52} {:<8} {} ok".format(repo["name"], visibility, action))
            changed += 1
        else:
            print("{:<52} {:<8} FAILED: {}".format(repo["name"], visibility, err[:70]))
            failed += 1
    print("\n{} changed, {} already correct, {} failed".format(changed, current, failed))
    return 1 if failed else 0


def phase_ruleset(client, args, repos):
    applied = blocked = failed = 0
    print("{:<52} {}".format("REPO", "RESULT"))
    for repo in repos:
        name = repo["name"]
        listing = client.api("repos/{}/rulesets".format(name))
        if not listing.ok:
            if "Upgrade to GitHub Pro" in listing.stderr:
                print("{:<52} SKIPPED -- private repo on free plan".format(name))
                blocked += 1
            else:
                print("{:<52} FAILED -- {}".format(name, listing.stderr[:50]))
                failed += 1
            continue

        existing = {r["name"]: r["id"] for r in (listing.json() or [])}
        if not args.apply:
            print("{:<52} would apply (existing: {})".format(
                name, sorted(existing) or "none"))
            applied += 1
            continue

        results = []
        for body in (NO_FORCE_PUSH, protect_default(args.check_context)):
            rid = existing.get(body["name"])
            if rid:
                put = client.api_json("repos/{}/rulesets/{}".format(name, rid), body)
            else:
                put = client.api_json("repos/{}/rulesets".format(name), body,
                                      method="POST")
            results.append((put.ok, put.stderr))

        if all(ok for ok, _ in results):
            print("{:<52} applied".format(name))
            applied += 1
        else:
            err = next((e for ok, e in results if not ok), "")
            print("{:<52} FAILED -- {}".format(name, err[:50]))
            failed += 1

    print("\n{} applied, {} blocked by plan, {} failed".format(applied, blocked, failed))
    if blocked:
        print("\n{} repo(s) have NO server-side force-push protection.".format(blocked))
        print("They rely on a local pre-push hook only, and only from one machine.")
        print("A paid GitHub plan closes this gap; re-run this phase afterwards.")
    return 1 if failed else 0


def run(args, config):
    client = next(iter(clients_for(config).values()))
    skips = set(args.skips or [])
    repos = admin_repos(client, skips)
    if skips:
        print("skipping {} repo(s) by request: {}\n".format(
            len(skips), ", ".join(sorted(skips))), file=sys.stderr)
    if args.phase == "workflow":
        return phase_workflow(client, args, repos)
    return phase_ruleset(client, args, repos)
