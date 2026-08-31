"""Thin wrapper around the `gh` CLI.

Every pre-refactor script defined its own `gh()` helper -- seven near-identical
copies with different timeouts, different return shapes (some returned
(stdout, rc), one returned (rc, stdout, stderr)) and inconsistent error
handling. They are unified here.

Nothing in this module raises on a failed call: GitHub is flaky and a sweep
across hundreds of repositories must survive individual failures. Callers check
the returncode.
"""
import base64
import json
import subprocess
import urllib.parse

DEFAULT_TIMEOUT = 120


class Result:
    """Outcome of one `gh` invocation."""

    __slots__ = ("stdout", "stderr", "returncode")

    def __init__(self, stdout="", stderr="", returncode=1):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode

    @property
    def ok(self):
        return self.returncode == 0

    def __bool__(self):
        return self.ok

    def lines(self):
        """Non-empty stdout lines, or [] on failure."""
        if not self.ok:
            return []
        return [line for line in self.stdout.splitlines() if line.strip()]

    def json(self, default=None):
        try:
            return json.loads(self.stdout)
        except Exception:
            return default


class GitHub:
    """Calls `gh`, optionally as a specific authenticated account."""

    def __init__(self, token=None, timeout=DEFAULT_TIMEOUT):
        self.token = token
        self.timeout = timeout

    # --- plumbing ----------------------------------------------------------

    def run(self, args, timeout=None):
        import os
        env = dict(os.environ)
        if self.token:
            env["GH_TOKEN"] = self.token
        try:
            proc = subprocess.run(["gh"] + list(args), capture_output=True, text=True,
                                  timeout=timeout or self.timeout, env=env)
            return Result(proc.stdout.strip(), proc.stderr.strip(), proc.returncode)
        except Exception as exc:                      # timeout, gh missing, ...
            return Result("", str(exc), 1)

    def api(self, path, jq=None, paginate=False, method=None, fields=None,
            input_file=None, timeout=None):
        args = ["api"]
        if method:
            args += ["-X", method]
        args.append(path)
        if paginate:
            args.append("--paginate")
        for key, value in (fields or {}).items():
            flag = "-F" if isinstance(value, bool) else "-f"
            args += [flag, "{}={}".format(key, value)]
        if input_file:
            args += ["--input", input_file]
        if jq:
            args += ["--jq", jq]
        return self.run(args, timeout=timeout)

    def api_json(self, path, body, method="PUT", jq=None, timeout=None):
        """Call the API with a JSON request body sent on stdin.

        Large payloads must not go through `-f key=value`: the base64 body of a
        real build-config file exceeds the argv length limit and GitHub returns
        HTTP 400. Passing the body via --input is the only reliable route, and
        it also removes any need to URL-encode branch names -- a branch such as
        "feature/api+auth-fixes" decodes to a space as a query parameter and
        404s.
        """
        import os
        args = ["api", "-X", method, path, "--input", "-"]
        if jq:
            args += ["--jq", jq]
        env = dict(os.environ)
        if self.token:
            env["GH_TOKEN"] = self.token
        try:
            proc = subprocess.run(["gh"] + args, input=json.dumps(body),
                                  capture_output=True, text=True,
                                  timeout=timeout or self.timeout, env=env)
            return Result(proc.stdout.strip(), proc.stderr.strip(), proc.returncode)
        except Exception as exc:
            return Result("", str(exc), 1)

    # --- convenience -------------------------------------------------------

    @staticmethod
    def token_for(login):
        """The stored gh token for *login*, or None."""
        res = GitHub().run(["auth", "token", "-u", login])
        return res.stdout if res.ok and res.stdout else None

    def repos(self, timeout=400):
        """Every repo reachable by this token, as (full_name, is_admin, archived)."""
        res = self.api(
            "user/repos?affiliation=owner,collaborator,organization_member&per_page=100",
            jq=r'.[] | "\(.full_name)\t\(.permissions.admin)\t\(.archived)"',
            paginate=True, timeout=timeout)
        out = []
        for line in res.lines():
            parts = line.split("\t")
            if len(parts) == 3:
                out.append((parts[0], parts[1] == "true", parts[2] == "true"))
        return out

    def branches(self, repo, timeout=None):
        res = self.api("repos/{}/branches?per_page=100".format(repo),
                       jq=".[].name", paginate=True, timeout=timeout)
        return res.lines()

    def tree(self, repo, ref, timeout=200):
        """(path, sha, size) for every blob on *ref*."""
        quoted = urllib.parse.quote(ref, safe="")
        res = self.api("repos/{}/git/trees/{}?recursive=1".format(repo, quoted),
                       jq=r'.tree[] | select(.type=="blob") | "\(.path)\t\(.sha)\t\(.size)"',
                       timeout=timeout)
        out = []
        for line in res.lines():
            parts = line.split("\t")
            if len(parts) == 3:
                out.append(tuple(parts))
        return out

    def blob(self, repo, sha, timeout=None):
        """Decoded blob text by SHA, or None."""
        res = self.api("repos/{}/git/blobs/{}".format(repo, sha),
                       jq=".content", timeout=timeout)
        return _decode(res)

    def contents(self, repo, path, ref, timeout=None):
        """Decoded file text at a ref, or None."""
        quoted_path = urllib.parse.quote(path, safe="/")
        quoted_ref = urllib.parse.quote(ref, safe="")
        res = self.api("repos/{}/contents/{}?ref={}".format(repo, quoted_path, quoted_ref),
                       jq=".content", timeout=timeout)
        return _decode(res)



    def content_sha(self, repo, path, ref, timeout=None):
        """Blob SHA of a file at a ref, needed to update it. None if absent."""
        quoted_path = urllib.parse.quote(path, safe="/")
        quoted_ref = urllib.parse.quote(ref, safe="")
        res = self.api("repos/{}/contents/{}?ref={}".format(repo, quoted_path, quoted_ref),
                       jq=".sha", timeout=timeout)
        return res.stdout if res.ok and res.stdout else None

def _decode(res):
    if not res.ok or not res.stdout:
        return None
    try:
        return base64.b64decode(res.stdout).decode("utf-8", "replace")
    except Exception:
        return None


def clients_for(config):
    """One GitHub client per configured account, keyed by login.

    With no accounts configured, returns a single client using whatever gh is
    currently authenticated as -- so the tools work out of the box for someone
    who just ran `gh auth login`.
    """
    if not config.accounts:
        return {"<default>": GitHub()}
    clients = {}
    for login in config.accounts:
        token = GitHub.token_for(login)
        if token:
            clients[login] = GitHub(token=token)
    if not clients:
        return {"<default>": GitHub()}
    return clients
