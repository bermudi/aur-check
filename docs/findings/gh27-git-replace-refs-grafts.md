# GH #27 — Git replace refs split auditor/builder views; grafts rewrite ancestry

**Source:** adversarial review (Review 2 H7; Cohort 3), GitHub issue #27
**Status:** fixed (2026-08-04)
**Severity:** high
**Lines:** `src/git.rs` (`safe_git_command`, `isolate_git_env`), `src/main.rs` (`isolate_process_environment`), `assets/wrapper.sh` (`_aur_gate_run_helper`)

## What happens

Two repository-local Git mechanisms were not isolated:

- `refs/replace/<object>` can substitute an arbitrary object for the object
  named by an audited SHA, including a commit with a different tree.
- `.git/info/grafts` can rewrite commit parents. It does not change the tree
  for an exact SHA, but it changes ancestry walks and range selection such as
  `rev-list` and `~` expressions.

`src/git.rs` did not pass `--no-replace-objects` or set
`GIT_NO_REPLACE_OBJECTS=1`. The wrapper's helper sanitizer removed
`GIT_REPLACE_REF_BASE` but did not disable replacement resolution, and it left
`info/grafts` active.

A malicious PKGBUILD `build()` running as the user can write these artifacts to
the cached AUR clone (the helper cache or `~/.cache/aur-gate/`). With a replace
ref, the next run could split the auditor and builder views:

1. The gate's `git show <audited-sha>:PKGBUILD` resolves through the replacement
   and audits a clean PKGBUILD.
2. The helper's separate `git checkout` of the same branch resolves the same
   replacement and builds the malicious commit.

The gate could therefore stage the audited SHA while the user installs a
different tree — a TOCTOU view split across the auditor/builder boundary.
Grafts are a related ancestry-view split, not an alternate tree for an exact
SHA; they can nevertheless corrupt baseline and history-derived evidence if
one Git caller honors them and another does not. The retired Bash implementation
kept `--no-replace-objects` in its allowed Git pre-options; the Rust port dropped
that protection and had no graft isolation.

## Fix

1. **Disable both mechanisms on every Rust Git call.** `safe_git_command()` now
   prepends `--no-replace-objects` and `isolate_git_env()` sets
   `GIT_NO_REPLACE_OBJECTS=1`. Because Git has no `--no-grafts` option,
   `isolate_git_env()` also sets `GIT_GRAFT_FILE=/dev/null`.
2. **Propagate the isolation to the helper.** `_aur_gate_run_helper` in
   `assets/wrapper.sh` exports both fixed values, and the Rust process
   environment (`src/main.rs::isolate_process_environment`) does the same.
3. **Purge repository-local state at every trust reset.** `reset_local_config()`
   now removes loose `refs/replace/*`, replacement entries in `packed-refs`, and
   `.git/info/grafts`, rejecting symlinked/nonregular or malformed packed
   state rather than following it. The reset is used before cached fetch/helper
   handoff, at the
   makepkg guard, and before accept. This is hygiene, not the sole boundary:
   Rust Git still uses `--no-replace-objects` plus `GIT_GRAFT_FILE=/dev/null`,
   and the helper still receives the fixed environment because same-user build
   code can create new artifacts after any purge.

## Verification

- `cargo test --all-targets` —
  `git::tests::replace_objects_are_disabled_by_git_command` verifies replace
  refs and `git::tests::grafts_are_disabled_by_safe_git` verifies that a forged
  parent is ignored; purge tests cover loose/packed refs, grafts, and symlink
  rejection.
- `cargo clippy --all-targets -- -D warnings` clean.
- `cargo run --quiet -- selftest` passes.
- `bash -n assets/wrapper.sh` and `zsh -n assets/wrapper.sh` clean.

## Lesson

Git replacement and graft mechanisms are first-class repository state, not
obscure corners. A gate that audits immutable SHA-anchored evidence must disable
them at every process boundary: its own Git wrapper, the helper's runtime
environment, and the Rust process environment. Purging stale repository state
reduces accidental view splits, but flags and the fresh makepkg/accept resets
remain the structural controls because attacker-writable files can reappear.
