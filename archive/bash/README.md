# Retired Bash implementation

This directory preserves the former single-file Bash implementation and its
review/tooling context for historical comparison only.

**Status: abandoned, frozen, and unsupported.** It is not the release
implementation, not the behavioral oracle, and must not receive security fixes.
The canonical Rust implementation lives at the repository root. Any useful
historical finding must be implemented and tested in Rust instead.

Contents:

- `aur-safe` — final Bash implementation
- `design-ledger.md` — Bash-era architecture ledger
- `AGENTS.md` — obsolete contributor instructions
- `.shellcheckrc` — exclusions used by the retired script
- `ralph-loop` — retired Bash-specific issue relay

The archived selftest may be run for archaeology, but its success has no bearing
on current release readiness.
