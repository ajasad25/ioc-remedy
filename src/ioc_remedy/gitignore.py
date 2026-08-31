"""Detect and repair the attacker's .gitignore tampering.

Two distinct edits were made to victim .gitignore files, and both matter:

  * `config.bat` appended as a marker line
  * the `.env` ignore rules stripped, so that the next `git add -A` a developer
    ran would stage their environment file and publish live credentials

The second is the damaging one and is easy to miss, because the repository keeps
building normally. Both this module's callers -- the standalone `fix-gitignore`
command and the clone-based `remediate` command -- share this logic so the two
cannot drift apart.
"""
import re

MARKER = "config.bat"
MARKER_LINE = re.compile(r"^\s*config\.bat\s*$", re.IGNORECASE)

# Any of these means "the environment file is ignored".
ENV_PATTERNS = (".env", ".env*", ".env.*", "*.env")

# What to restore when no env rule survives.
ENV_RULES = [".env", ".env.*", "!.env.example"]
ENV_COMMENT = "# local env files (restored after security incident)"


def has_marker(text):
    return any(MARKER_LINE.match(line) for line in text.splitlines())


def ignores_env(text):
    return any(line.strip() in ENV_PATTERNS for line in text.splitlines())


def inspect(text):
    """Return (needs_repair, has_marker, ignores_env)."""
    marker = has_marker(text)
    env = ignores_env(text)
    return (marker or not env), marker, env


def reasons(text):
    """Human-readable list of what is wrong with this .gitignore."""
    out = []
    if has_marker(text):
        out.append("remove {} marker".format(MARKER))
    if not ignores_env(text):
        out.append("restore .env ignore rules")
    return out


def repair(text):
    """Return the corrected .gitignore text, preserving the original line ending."""
    newline = "\r\n" if "\r\n" in text else "\n"
    lines = [line for line in text.splitlines() if not MARKER_LINE.match(line)]

    if not any(line.strip() in ENV_PATTERNS for line in lines):
        while lines and not lines[-1].strip():
            lines.pop()
        lines += ["", ENV_COMMENT] + ENV_RULES

    body = newline.join(lines)
    if body and not body.endswith(newline):
        body += newline
    return body
