# AGENTS.md

## Project

`aur-gate` is a deterministic pre-install gate for Arch Linux AUR updates. The
Rust implementation at the repository root is canonical and release-supported.
The retired Bash implementation is frozen under `archive/bash/`; it is history,
not an oracle and must not receive fixes.

Read before changing the trust path:

- `docs/design-ledger.md` — canonical architecture and settled policy
- `docs/threat-model.md` — attacker model and defensive principles
- `docs/findings/` — durable security findings

## Stack and layout

Rust 2021, Git, util-linux `flock`, curl, pacman, and yay or paru. The generated
cross-shell wrapper is `assets/wrapper.sh`. Runtime state is
`~/.cache/aur-gate/`.

- `src/engine.rs` — cached/missing-cache gate orchestration
- `src/classifier.rs`, `src/pkgbuild.rs`, `src/rules.rs` — deterministic policy
- `src/state.rs` — accepted/staged records and transaction locking
- `src/commands.rs` — command flows and makepkg guard
- `src/git.rs` — isolated HTTP(S)-only Git boundary
- `src/srcinfo.rs`, `src/rpc.rs` — pacman evidence and AUR identity
- `src/llm_client.rs` — advisory direct `llm` integration
- `tests/` — subprocess, HTTP, wrapper, and production-boundary coverage

## Trust invariants

- `accepted/<pkgbase>` advances only to the exact immutable SHA audited, built
  through the wrapper guard, and freshly confirmed by pacman's root-owned DB.
- Capture the candidate SHA once; never re-resolve a mutable branch after audit.
- Every candidate tree leaf is a regular committed blob. The makepkg seam repeats
  the check and rejects every untracked file.
- Whole-candidate audit requires review for arbitrary additional package files.
- Added `SKIP`, arbitrary/dynamic `install=`, non-boring removals, and maintainer
  identity changes never auto-clear.
- All Rust Git calls go through `git::safe_git`; HTTP(S) only, isolated config and
  environment, explicit origin validation.
- LLM output is advisory. It may only auto-clear deterministic `BoringEdge`; it
  never overrides hard, review, or audit-unavailable outcomes.
- State directories are current-user-owned real directories with mode `0700`.
- The wrapper owns the complete gate → helper → accept lock transaction and strips
  lock/staging capabilities before untrusted build code runs. Re-sourcing must
  recover pinned external helper paths even when an older wrapper already defines
  `yay`/`paru`; yay review suppression uses the supported boolean forms
  `--diffmenu=false --editmenu=false`.

## Verification

After every meaningful change:

```sh
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo run --quiet -- selftest
bash -n assets/wrapper.sh
zsh -n assets/wrapper.sh
```

For a controlled live missing-cache boundary, use disposable state/caches and
`check ventoy-bin`; expected result is review (`2`), never clean.

## Security conventions

- Fail closed at every external boundary; do not swallow exceptions.
- Validate package names and external input before path/URL use.
- No `any`-style type escapes or hidden global test overrides.
- Do not weaken transport, state, or pacman evidence checks for fixtures.
- Do not add name blacklists; detect structural behavior.
- A blocked update must never advance accepted state.
- Open GitHub issues are live tracking; durable lessons belong in
  `docs/findings/` when closed.
