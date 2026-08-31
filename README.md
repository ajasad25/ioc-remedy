# ioc-remedy

[![tests](https://github.com/ajasad25/ioc-remedy/actions/workflows/tests.yml/badge.svg)](https://github.com/ajasad25/ioc-remedy/actions/workflows/tests.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python: 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)

Find, verify and remediate an injected supply-chain payload across every branch
of every GitHub repository you can reach.

This grew out of a real incident response against a self-propagating worm that
appended an obfuscated loader to build-config and source files. The tools worked,
but they were single-purpose scripts wired to one machine. This is the same
logic, made re-runnable by anyone against their own repositories.

**[ioc-guard](https://github.com/ajasad25/ioc-guard) detects; ioc-remedy acts.**
ioc-guard is the pattern-and-heuristic engine that decides whether one file is
compromised. ioc-remedy applies it across every branch of every repository you
can reach, then verifies, cleans and hardens them. You can run ioc-remedy without
the engine -- it ships its own marker registry -- but `scan-engine` and both
remediators use it, and it is the more reliable classifier.

## Why this is not just a grep

The payload is designed to survive a casual check:

- **Commits are tampered in place.** The attacker reuses the real author,
  subject and timestamp and changes only the tree, so the branch reports an
  ordinary `[ahead 1, behind 1]` that reads like a routine rebase collision.
- **The host files are ones your build already executes.** `eslint.config.js`,
  `tailwind.config.js`, `vite.config.js` — a single `lint` or `build` runs it.
  There is no step for a careful person to skip.
- **Literal string matching is not enough.** In the packed variant the marker
  strings never appear as plain text, so a marker list alone returns a false
  clean. The reliable signals are structural: a line over 3000 characters in a
  build config, a long run of spaces before the closing `};`, dense `\u00XX`
  escapes. Prefer `scan-engine`, which applies those heuristics.
- **The damage is not only the loader.** It also strips the `.env` rules from
  `.gitignore`, so the next `git add -A` commits live credentials while the
  repository keeps building normally.

## Install

Requires Python 3.8+ and the [GitHub CLI](https://cli.github.com/), authenticated:

```bash
gh auth login
pip install -e .
```

Several commands classify files using the
[ioc-guard](https://github.com/ajasad25/ioc-guard) engine. Clone it anywhere and
point at it:

```bash
git clone https://github.com/ajasad25/ioc-guard ~/src/ioc-guard
export IOC_REMEDY_ENGINE=~/src/ioc-guard     # default is already ~/src/ioc-guard
```

## Use

```bash
ioc-remedy scan                      # every reachable repo, build configs only
ioc-remedy scan --mode broad         # every JS/TS source file (slower, wider)
ioc-remedy scan-engine               # ioc-guard patterns + structural heuristics
ioc-remedy verify                    # is anything the attacker left still there?
```

`scan` and `verify` are strictly read-only. Everything that writes is **dry-run
by default** and needs an explicit flag:

```bash
ioc-remedy clean                     # show what would change
ioc-remedy clean --execute           # actually commit

ioc-remedy remediate-auto OWNER/REPO           # dry run
ioc-remedy remediate-auto OWNER/REPO --apply   # commit and push
```

A typical sequence:

```bash
ioc-remedy scan --mode broad         # find it       -> data/infected-broad.json
ioc-remedy remediate-auto OWNER/REPO # fix it        (add --apply when happy)
ioc-remedy verify --repo OWNER/REPO  # prove it      (exit 1 if anything remains)
ioc-remedy rollout --phase ruleset   # stop it recurring (add --apply)
```

### Commands

| command | writes? | what it does |
|---|---|---|
| `scan` | no | every branch of every reachable repo, by marker match and long-line heuristic |
| `scan-engine` | no | the same sweep, classified by ioc-guard's patterns and structural heuristics |
| `verify` | no | checks every branch for a surviving payload, the attacker's `.gitignore` marker, lost `.env` rules, and committed `.env` files. Exit 1 if dirty, so it gates CI |
| `clean` | `--execute` | strips the loader from a file at the branch tip, via the contents API |
| `fix-gitignore` | `--execute` | restores `.env` rules and removes the attacker's marker |
| `restore` | `--execute` | points force-pushed refs back at their pre-attack commits; records an undo log |
| `remediate` | `--apply` | clones and applies fixes from a known plan, branch by branch |
| `remediate-auto` | `--apply` | clones, scans every branch, and fixes exactly what the scanner finds. Start here |
| `rollout` | `--apply` | adds scanning CI, then forbids force-pushes and requires a passing check on the default branch |

### Configuration

Every path resolves from a flag, then an environment variable, then a default
relative to the working directory. No path is baked into the code.

| flag | variable | default |
|---|---|---|
| `--workdir` | `IOC_REMEDY_HOME_DIR` | current directory |
| `--data-dir` | `IOC_REMEDY_DATA_DIR` | `<workdir>/data` |
| `--engine` | `IOC_REMEDY_ENGINE` | `~/src/ioc-guard` |
| `--account` | `IOC_REMEDY_ACCOUNTS` | whatever `gh` is authenticated as |

`--account` is repeatable. Give it several logins and the sweep unions the
repositories each can reach, which matters when your repositories are split
across personal and organisation accounts.

## Safety

- Nothing writes without an explicit `--execute` or `--apply`.
- Nothing force-pushes, and nothing rewrites history. `clean` fixes the branch
  tip; an old commit still holds the payload, which is the right trade-off on a
  shared branch.
- `restore` records every displaced SHA to an undo log, and refuses to guess when
  a pre-attack object has already been garbage-collected.
- Remediation re-scans each branch after editing and before committing. A branch
  the scanner **errors** on is never committed — a non-zero scanner exit is never
  treated as a pass.
- A file with no clean ancestor and no strippable tail is reported as needing a
  human rather than being guessed at.

## Develop

```bash
pip install -e ".[dev]"
pytest                     # also works with no install; pythonpath is set in pyproject.toml
```

No test touches the network. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the package fits together
and why it is shaped this way, and [CONTRIBUTING.md](CONTRIBUTING.md) for how to
add a command and the rules that are not negotiable.

## Reporting a security issue

Please use [private vulnerability
reporting](https://github.com/ajasad25/ioc-remedy/security/advisories/new)
rather than a public issue. [SECURITY.md](SECURITY.md) explains what counts as a
vulnerability here — a scanner reporting a compromised file as clean is the most
damaging failure this tool has, and it is treated as one.

## Provenance

This was extracted from the private repository the tooling was written in during
a live incident, with fresh history. That repository also held the record of the
incident itself, which is not published and is not reachable from here.

## License

[MIT](LICENSE).
