"""Helpers for working inside a cloned repository.

Shared by the two remediation commands so their notion of "is this clean" and
"where does an untampered copy of this file live" cannot diverge.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

# Variant A appends its loader to the line carrying the config's closing `};`,
# separated by a long run of spaces -- 507 in every sample observed.
PAD_RUN = re.compile(r" {300,}")
PAD_MIN_TAIL = 1000

# How far back to look for an untampered copy of a file.
MAX_HISTORY = 60

ENV_FILE = re.compile(r"(^|/)\.env$")
ENV_VARIANT = re.compile(r"(^|/)\.env\.(local|production|development)$")

FINDING_LINE = re.compile(r"^(.+?):(\d+): \[([^\]]+)\]")


def run(argv, cwd=None, timeout=900):
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def scan_tree(config, root, timeout=900):
    """Run the ioc-guard engine over a directory. Returns (returncode, stdout).

    Exit codes are the engine's: 0 clean, 1 findings, 2 error. An exit code of 2
    is never a pass -- callers must not commit a tree the scanner errored on.
    """
    env = dict(os.environ, PYTHONPATH=str(config.engine))
    proc = subprocess.run(
        [sys.executable, "-m", "ioc_guard", "--root", root,
         "--iocs", str(config.engine / "iocs.txt")],
        capture_output=True, text=True, env=env, timeout=timeout)
    return proc.returncode, proc.stdout


def parse_findings(output):
    """Engine output -> [(path, rule)]."""
    found = []
    for line in output.splitlines():
        match = FINDING_LINE.match(line)
        if match:
            found.append((match.group(1), match.group(3)))
    return found


def blob_is_clean(config, workdir, sha, path, cache):
    """True if this historical version of *path* passes the scanner."""
    key = (sha, path)
    if key in cache:
        return cache[key]
    show = run(["git", "show", "{}:{}".format(sha, path)], cwd=workdir)
    if show.returncode != 0:
        cache[key] = False
        return False
    tmp = tempfile.mkdtemp(prefix="ioc-remedy-blob-")
    try:
        dest = os.path.join(tmp, os.path.basename(path) or "f")
        with open(dest, "wb") as handle:
            handle.write(show.stdout.encode("utf-8", "surrogateescape"))
        code, _ = scan_tree(config, tmp)
        cache[key] = (code == 0)
        return cache[key]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def clean_ancestor(config, workdir, path, cache, max_history=MAX_HISTORY):
    """Newest ancestor commit whose version of *path* the scanner passes."""
    log = run(["git", "log", "--format=%H", "-n", str(max_history), "--", path],
              cwd=workdir)
    # Skip [0]: that is the current, infected commit.
    for sha in log.stdout.split()[1:]:
        if blob_is_clean(config, workdir, sha, path, cache):
            return sha
    return None


def strip_payload(full_path):
    """Cut the injected tail from a file with no clean ancestor.

    Everything before the whitespace wall is the original line, so cutting there
    restores the file without a clean revision to copy from. Returns notes
    describing each cut, or [] if there was nothing to cut.
    """
    try:
        with open(full_path, "rb") as handle:
            text = handle.read().decode("utf-8", "replace")
    except OSError:
        return []

    newline = "\r\n" if "\r\n" in text else "\n"
    lines, cuts = [], []
    for number, line in enumerate(text.split("\n"), 1):
        bare = line.rstrip("\r")
        wall = PAD_RUN.search(bare)
        if wall and len(bare) - wall.start() > PAD_MIN_TAIL:
            lines.append(bare[:wall.start()].rstrip())
            cuts.append("line {}: {} chars -> {}".format(number, len(bare), wall.start()))
        else:
            lines.append(bare)

    if not cuts:
        return []
    body = newline.join(lines).rstrip(newline) + newline
    with open(full_path, "wb") as handle:
        handle.write(body.encode("utf-8"))
    return cuts


def untrack_env_files(workdir):
    """git rm --cached every committed environment file. Returns notes."""
    notes = []
    listing = run(["git", "ls-files"], cwd=workdir).stdout.splitlines()
    for rel in listing:
        if ENV_FILE.search(rel) or ENV_VARIANT.search(rel):
            if run(["git", "rm", "--cached", "-q", rel], cwd=workdir).returncode == 0:
                notes.append("{}: untracked (credential exposure)".format(rel))
    return notes


def remote_branches(workdir):
    """Every remote branch name, without the origin/ prefix."""
    listing = run(["git", "branch", "-r", "--format=%(refname:short)"],
                  cwd=workdir).stdout.splitlines()
    names = set()
    for line in listing:
        name = line.strip()
        if not name or "->" in name or name in ("origin", "origin/HEAD"):
            continue
        names.add(name.replace("origin/", "", 1))
    return sorted(names)


def set_identity(workdir, name=None, email=None):
    """Configure the commit identity, leaving git's own default when unset."""
    if email:
        run(["git", "config", "user.email", email], cwd=workdir)
    if name:
        run(["git", "config", "user.name", name], cwd=workdir)
