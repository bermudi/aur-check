# AGENTS.md

## Scope

This directory is the Rust rewrite of `aur-safe`. The root Bash implementation
remains the behavioral oracle while the rewrite is validated.

## Trust-path invariants

- `accepted/<pkgbase>` advances only to the exact immutable SHA that was audited,
  built under the generated wrapper, and freshly confirmed in pacman's root-owned
  local database.
- Capture the candidate SHA once. Classify, stash evidence, and stage that SHA;
  never re-resolve mutable `origin/<branch>` after audit.
- Every candidate tree leaf must be a regular committed blob. The makepkg seam
  repeats this check and rejects all untracked files.
- Whole-candidate audit requires review for arbitrary extra package files.
- Added `SKIP` checksums, dynamic/arbitrary `install=` assignments, non-boring
  removals, and maintainer identity changes cannot auto-clear.
- All Rust-owned Git calls use `git::safe_git`: absolute `/usr/bin/git`, no
  inherited `GIT_*`, isolated global/system config, safe output options, and
  HTTP(S)-only transports. The wrapper separately hardens helper-side Git.
- The `llm` crate is advisory. It may explain findings or verify only a
  deterministic `BoringEdge`; it can never clear hard, review, or unavailable
  results. No Pi process/dependency.

## Verification

Run after every trust-path change:

```sh
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo run --quiet -- selftest
bash -n assets/wrapper.sh
zsh -n assets/wrapper.sh
```

A useful live missing-cache exercise, with disposable state/caches, is
`check ventoy-bin`; expected result is review (`2`), not clean.
