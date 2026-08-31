# Contributing

## Getting set up

```bash
git clone https://github.com/ajasad25/ioc-remedy
cd ioc-remedy
pip install -e ".[dev]"
pytest
```

`pytest` also works without installing anything — `pythonpath` is set in
`pyproject.toml`, so a fresh clone runs the suite as-is. No test touches the
network.

Most commands shell out to the [GitHub CLI](https://cli.github.com/), so you
need `gh auth login` to run the tool against real repositories. Several commands
also use the [ioc-guard](https://github.com/ajasad25/ioc-guard) engine:

```bash
git clone https://github.com/ajasad25/ioc-guard ~/src/ioc-guard
```

## Adding a command

Create `src/ioc_remedy/commands/<name>.py`. The CLI discovers it automatically —
there is no registry to update:

```python
"""One paragraph. This becomes the --help body."""

NAME = "my-command"
HELP = "one line, shown in the command list"

def add_arguments(parser):   # optional
    parser.add_argument("--thing")

def run(args, config):       # required; return an exit code
    return 0
```

The common flags (`--workdir`, `--data-dir`, `--engine`, `--account`) are
attached for you. `tests/test_cli.py` will fail the build if the module has no
docstring or no `HELP`.

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) explains how the pieces fit and why
each one exists.

## Rules that are not negotiable

This tool writes to repositories people depend on. These are enforced by tests
and by review, and a change that breaks one will not be merged:

1. **Dry run is the default.** Anything that writes takes an explicit
   `--execute` or `--apply`. `tests/test_cli.py` asserts this for every
   destructive command; add yours to that list.
2. **A scanner exit code of 2 is never a pass.** It means the scan errored, not
   that the tree is clean. Never commit a branch on a 2.
3. **No history rewriting and no force-pushing.** Fix the branch tip; leave the
   old commit alone. On a shared branch that is the correct trade-off.
4. **Report, do not guess.** If the tool cannot determine a safe repair, it says
   so and leaves the file for a human. Silent truncation is a bug — if you bound
   coverage, say so in the output.
5. **No absolute paths.** Everything resolves through `ioc_remedy.config`.
   `tests/test_config.py` fails the build if a home-directory path appears
   anywhere in `src/`.

## Adding a marker

Extend `MARKERS` in `src/ioc_remedy/iocs.py` — do not copy the list into a new
module. That list was previously duplicated across five scripts and drifted
apart, so the same file could be flagged by one tool and cleared by another.
Markers are compared against a lowercased body, so they must be lowercase.

The literal list is a floor, not a guarantee. Packed variants keep their strings
out of plain text, which is why the structural heuristics in the engine matter
more than the markers.

## Commit messages

Conventional-commit subject, and a body explaining *why* rather than what. If
you are changing behaviour that someone might be relying on, say so explicitly.
