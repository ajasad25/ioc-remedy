# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-08-31

First public release. Extracted from the private incident-response repository the
tooling was written in, with fresh history.

### Added

- Nine subcommands behind one `ioc-remedy` entry point, discovered automatically
  from `ioc_remedy.commands` — adding a module adds a command.
- `scan` (`--mode configs|broad`), `scan-engine` and `verify`: read-only sweeps
  across every branch of every reachable repository.
- `clean`, `fix-gitignore` and `restore`: targeted repairs through the GitHub
  contents and git-refs APIs.
- `remediate` and `remediate-auto`: clone-based repair, branch by branch.
  `remediate-auto` trusts no precomputed inventory and restores each file from
  the newest ancestor commit the scanner passes.
- `rollout`: adds scanning CI, then forbids force-pushes and requires a passing
  check on the default branch.
- A single marker registry (`ioc_remedy.iocs`) shared by every scanner.
- 37 tests requiring no network access.

### Fixed

Carried over from the scripts this was extracted from:

- **Scanners disagreed with each other.** The marker list had been copy-pasted
  into five scripts and drifted; of the 18 distinct markers across them, 11 were
  missing from at least one scanner, so a file flagged by one tool could be
  reported clean by another.
- **Large file bodies failed to write.** Sending base64 content as `-f
  content=...` exceeds the argv length limit on a real build config and returns
  HTTP 400. Bodies now go over stdin.
- **Branch names containing `+` 404'd**, because refs were not URL-encoded.
- **Silent truncation in verification.** Only the first 25 config files per
  branch were inspected, with no indication, so a branch could report PASS while
  unchecked files still carried the payload. Truncation is now a finding.
- **Hardcoded paths and commit identity.** Every path came from one developer's
  home directory, and every fix commit was attributed to a fixed name and email.

### Security

- Every command that writes is dry-run by default and requires an explicit
  `--execute` or `--apply`.
- Nothing force-pushes and nothing rewrites history.
- A scanner exit code of 2 is treated as an error, never as a pass.

[Unreleased]: https://github.com/ajasad25/ioc-remedy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ajasad25/ioc-remedy/releases/tag/v0.1.0
