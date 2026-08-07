# aur-gate design ledger

This is the canonical design ledger for the supported Rust implementation.
The retired Bash-era ledger is preserved at `archive/bash/design-ledger.md` for
historical investigation only.

## Release decision (2026-08-04)

Rust became the primary implementation after a parity review and controlled live
missing-cache smoke test. Bash was intentionally retired rather than kept as a
second implementation: several divergences were real Bash trust gaps, not Rust
parity bugs. The Rust policy is now the oracle.

The live smoke used isolated state and helper caches while retaining production
`/usr/bin/git`, curl, and pacman query boundaries. `check ventoy-bin` cloned from
AUR and returned mandatory review (`2`); empty-state `accept` returned `0`; the
generated wrapper parsed in Bash and Zsh. No package was built or installed.

The installation smoke then exposed two shell-integration bugs hidden by fake
helpers: re-sourcing over the retired wrapper resolved its `yay`/`paru` functions
instead of the external binaries, and yay 13 rejects the removed
`--nodiffmenu`/`--noeditmenu` options. The wrapper now resolves external helper
paths explicitly in both shells and uses `--diffmenu=false --editmenu=false`.
Fresh Bash and Zsh sessions confirmed pinned `/usr/bin/yay` and `/usr/bin/paru`,
gated bare/`-Syu` classification, and successful helper version dispatch.

## Threat model

An attacker controls an AUR candidate repository, including history, blobs,
filenames, Git attributes, PKGBUILD shell, install hooks, and timing of a commit
published between gate and helper fetch. They may attempt output/config/env
injection at Git, helper, terminal, and LLM boundaries. See
`docs/threat-model.md` for the sourced narrative.

Single-user state is not a privilege boundary against code already executing as
the same user. It is nevertheless created as current-user-owned, non-symlinked
`0700` directories to prevent accidental redirection and cross-user exposure.

## Central invariant

`~/.cache/aur-gate/accepted/<pkgbase>` means the exact commit that was both:

1. audited by deterministic policy, and
2. built under the generated wrapper's exact-staged-SHA guard and freshly
   confirmed in pacman's root-owned local database.

`staged/<pkgbase>` is temporary candidate evidence, never trust. A blocked,
stale, moved, malformed, or uninstalled candidate cannot advance `accepted`.

## Transaction

The generated Bash/Zsh wrapper resolves the real helper and aur-gate binary once,
validates state, and holds fd 9 across:

1. `gate` or explicit-install `begin` + `audit`;
2. yay/paru fetch, guarded makepkg, and installation;
3. `accept`, but only after a zero helper status. Failed helper/guard runs call
   `abort` to rotate the manifest without any promotion attempt.

The helper child closes fd 9 and loses lock/staging capabilities. It receives only
pinned pacman/git/gpg/sudo programs, fixed fresh-build flags, and the aur-gate
binary as `--makepkg`. `cmd_makepkg` requires manifest membership and a valid
staged SHA, then materializes the exact audited tree into a private build
directory (`~/.cache/aur-gate/build/<pkgbase>/`) using `git archive <staged_sha>`
and `tar -x`. It runs real `makepkg` in that directory with `PKGDEST` pointing
back at the helper checkout, so package discovery via `makepkg --packagelist`
finds the built artifacts. The helper checkout's index, worktree, refs, and HEAD
are not used for the build surface.

## Gate paths

### Cached

Derive the canonical origin from validated application configuration, replace
repo-local `.git/config` with the fixed generated checkout config, fetch an
explicit HTTP(S) URL/refspec, capture the candidate SHA once, and diff
`accepted..candidate`. A config-reset failure, invalid/missing anchor, fetch
failure, or malformed Git output blocks.

### Missing cache

Clone fresh over HTTP(S). If retained history contains the installed version,
run the shared diff pipeline from that baseline, then still require review of
the whole candidate because retained AUR history is attacker-rewritable. Without
a baseline, whole-candidate review is mandatory. Hard/audit failures never stage.

## Deterministic policy

- Hard rules block known payload/execution structures.
- A positive grammar auto-clears only narrow inert metadata.
- Parser-ambiguous inert metadata becomes `BoringEdge`; an opt-in LLM verifier
  may clear only this class with exact output `VERDICT: BORING_EDGE_OK`.
- Review rules, source-authority anomalies, arbitrary files, `SKIP`, arbitrary
  `install=`, maintainer identity changes, and non-boring removals require human
  review.
- NUL, non-regular blobs, opaque evidence, failed commands, and malformed
  framing are audit-unavailable and block.

The stricter Rust behavior is deliberate. It supersedes Bash behavior that
allowed deletion-only control-flow changes, repointed cached origins, arbitrary
whole-candidate files, narrow untracked checks, and helper Git environment
inheritance.

## External boundaries

- Git: absolute `/usr/bin/git`, isolated `GIT_*` and config, safe rendering
  options, HTTP(S)-only transport, generated repo-local config with an exact
  fail-closed contract, private command-scoped Git metadata views, and purge
  of commit-graph, object alternates, and replacement/graft state before
  helper-facing resets.
- RPC: typed JSON, exact pkgname match, validated pkgbase, bounded curl timeout.
- Pacman: installed version, pkgname, pkgbase, build time, and install time must
  match staged `.SRCINFO` claims and freshness threshold.
- Terminal: untrusted bytes are escaped for display; raw evidence remains on
  disk. Paging preserves structural newlines through a fixed pager over escaped
  content and reports pager failure.
- LLM: direct `llm` crate, no Pi process; secrets remain environment-only;
  advisory output cannot override deterministic decisions. Large advisory
  evidence includes bounded head and tail with an explicit omission marker.

## Deliberately retained limitation

A malicious repository can consume substantial time, memory, network, or disk
before Git/process limits intervene. This is an availability risk, not a path to
run the helper: the wrapper waits for a successful complete audit and failures do
not stage. Git/resource ceilings remain tracked as GitHub #17 and must fail
closed when implemented; classifier input must never be silently truncated.

## Verification model

- Rust unit tests cover policy, framing, state, Git isolation, pacman parsing,
  and exact-SHA guards.
- Standard integration tests execute the production binary startup and real
  curl/RPC/HTTP clone boundary.
- Harness integration scenarios cover command flows, missing-cache HTTP, and
  complete wrapper → helper → guard → install evidence → accept transactions.
- `cargo run -- selftest` is the embedded deterministic corpus.
- `archive/bash/aur-safe selftest` is historical evidence only, not a release
  gate or behavioral oracle.
