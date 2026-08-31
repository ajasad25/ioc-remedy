# Security policy

## Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/ajasad25/ioc-remedy/security/advisories/new)
rather than opening a public issue.

Include what you can: the version, what you ran, what happened, and what you
expected. A proof of concept helps but is not required.

Expect an acknowledgement within a week. Fixes for anything that could damage a
user's repositories are prioritised over everything else.

## What counts as a vulnerability here

This tool writes to other people's repositories, so its threat model is unusual.
Treat any of the following as a security issue, not a bug:

- **A write without consent.** Anything that commits, pushes or moves a ref
  without an explicit `--execute` or `--apply`. Dry-run is the default on every
  destructive command and that is a security boundary.
- **A false clean.** A scanner reporting a compromised file as safe. This is the
  most damaging failure mode the tool has: it ends an investigation early.
- **Silent truncation or skipping.** Any path where coverage is bounded but the
  output does not say so. A partial scan that presents as complete is a false
  clean wearing a different hat.
- **Destructive behaviour beyond what is documented.** History rewriting, a
  force-push, or a branch deletion. None of these should ever happen.
- **Credential handling.** Any path that logs, writes or transmits a token, or
  that commits a file matching the environment-file patterns.

## What is not a vulnerability

- **Marker strings in this repository's own source.** `src/ioc_remedy/iocs.py`
  contains the indicators the tool searches for. A scanner pointed at this
  repository will flag it. That is expected, and it is why the tool's own
  scanner skips known security-tooling filenames.
- **A false positive.** Over-reporting is the safe direction. Please still file
  it as a normal issue — the long-line heuristic in particular is deliberately
  limited to build configs because it is unusable on minified source.
- **Findings requiring an already-compromised machine.** If an attacker can
  already run code as you, they do not need this tool.

## Scope

This policy covers the `ioc-remedy` package. The detection engine lives in
[ioc-guard](https://github.com/ajasad25/ioc-guard); report engine issues there.
