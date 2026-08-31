# Architecture

## Shape

```
src/ioc_remedy/
  cli.py         argparse entry point; discovers subcommands, owns no command list
  config.py      path and account resolution -- the only module holding defaults
  iocs.py        the marker registry and the classifiers built on it
  ghapi.py       every call to the `gh` CLI
  gitignore.py   detection and repair of the attacker's .gitignore tampering
  repotools.py   working-tree helpers: scan, clean-ancestor search, tail-strip
  commands/      one module per subcommand
```

Dependencies point inwards. A command may use any shared module; no shared module
imports a command; nothing imports `cli` except the entry point.

## Why it is shaped this way

The package is a refactor of fourteen standalone scripts. Each design choice
below answers a specific defect those scripts had, and the tests pin the fix.

**Commands are discovered, not registered.** `cli.discover()` walks
`ioc_remedy.commands` with `pkgutil`. Adding a file adds a command. There is no
list to forget to update — which matters here because the original scripts were
found by `ls`, and two of them had silently stopped working.

**One marker registry.** The marker list was copy-pasted into five scripts and
drifted: 15 entries in one, 10 in another, 11 in a third, with different
contents. Of the 18 distinct markers across them, 11 were missing from at least
one scanner, so a file flagged by one tool was reported clean by another.
`iocs.py` is the union, and it was generated from those scripts rather than
retyped, so no marker was lost in transcription.

**One place that knows about paths.** Every script hardcoded absolute paths into
one developer's home directory. Two of them pointed at a per-session scratch
directory that no longer existed, so `verify_clean.py` and `restore.py` were
simply broken. `config.py` resolves everything from flag, then environment, then
a default relative to the working directory, and
`tests/test_config.py::test_no_absolute_developer_paths_remain_in_the_package`
fails the build if an absolute home path reappears anywhere in `src/`.

**One HTTP layer.** There were seven near-identical `gh()` helpers with three
different return shapes and inconsistent timeouts. `ghapi.py` unifies them behind
one `Result`. Calls never raise: a sweep over hundreds of repositories has to
survive individual failures, so callers check `returncode` instead.

Two bugs are fixed there once, rather than in each caller:

- **Large bodies go on stdin.** Sending a base64 file body as `-f content=...`
  exceeds the argv length limit for a real build config and GitHub returns HTTP
  400. `api_json()` sends the body via `--input -`.
- **Refs are URL-encoded.** A branch named `feature/api+auth-fixes` decodes
  to a space as a query parameter and 404s.

An entire script, `retry_failed.py`, existed only to work around those two
faults by hand. It is replaced by nothing.

## Two remediators, deliberately

`remediate` works from a known plan; `remediate-auto` derives the work itself by
scanning each branch. The second is the one to reach for — the first is kept
because a plan file lets you review exactly what will change before it happens,
which is what you want when acting on someone else's repository.

Both share `repotools`, so their notion of "clean" and their search for an
untampered copy of a file cannot diverge.

## Invariants worth preserving

- **A scanner exit code of 2 is never a pass.** It means the scan errored, not
  that the tree is clean. Both remediators refuse to commit such a branch.
- **Dry-run is the default everywhere that writes.** This is what made the tools
  safe to iterate on mid-incident, and `tests/test_cli.py` asserts it for every
  destructive command.
- **No history rewriting, no force-pushing.** `clean` fixes the branch tip and
  leaves the payload in an old commit; that is deliberate on a shared branch.
- **Report, do not guess.** A file with no clean ancestor and no strippable tail
  comes back as "NEEDS A HUMAN". Silent truncation is a bug: `verify` inspected
  only the first 25 config files per branch and said nothing, so a branch could
  report PASS with unchecked infected files on it. It now reports the truncation
  as a finding.

## Adding a command

Create `src/ioc_remedy/commands/<name>.py` with:

```python
"""One-paragraph description; becomes the --help body."""

NAME = "my-command"
HELP = "one line, shown in the command list"

def add_arguments(parser):   # optional
    parser.add_argument("--thing")

def run(args, config):       # required; return an exit code
    return 0
```

Common flags (`--workdir`, `--data-dir`, `--engine`, `--account`) are attached
for you. `tests/test_cli.py` will require a docstring and a `HELP` string, and
if the command writes anything, add it to the dry-run-by-default assertion.
