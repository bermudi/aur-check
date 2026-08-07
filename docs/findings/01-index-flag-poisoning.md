# Finding 1 — poisoned index flags bypass working-tree checks

**Source:** 2026-08-04 trust-path review (Phase 2, private build checkout)
**Status:** fixed by private build checkout
**Severity:** critical
**Surface:** helper checkout index, makepkg guard

## What happens

Git index flags such as `--skip-worktree` and `--assume-unchanged` tell `git
diff` and `git checkout-index` to trust the recorded index entry and ignore the
bytes actually present in the working tree. A same-user attacker (or a helper
run that modifies the checkout after the gate) can set these flags on `PKGBUILD`
and then replace the working-tree content. Guards that rely on `git diff --quiet
HEAD` or `git diff --cached --quiet HEAD` see a "clean" result and allow
`makepkg` to source attacker-controlled bytes.

## Why it mattered

The makepkg guard ran several separate Git invocations against the mutable helper
checkout and then `exec`ed `makepkg`. Between the last clean-index/worktree check
and `makepkg` actually reading `PKGBUILD`, a same-user writer could flip index
flags and swap working-tree bytes. `git diff` trusted the flags, so the check
was blind to the swap. The class is not fully closed by checking the flags
(e.g., `git ls-files -v`) because the check itself is another separate operation
in a race window.

## Implemented mechanism

`cmd_makepkg` no longer asks Git about the helper checkout's index or worktree
at all. It reads the staged SHA from the transaction state, validates that the
tree has only regular blob surfaces, and materializes the tree into a private
build directory with `git archive <staged_sha> | tar -x`. The materialized
directory is created fresh under `~/.cache/aur-gate/build/<pkgbase>/` and is
swept at transaction boundaries. `makepkg` runs in that directory; the helper's
working tree and index are not the build surface. Index flags are therefore
irrelevant.

`git archive` resolves the commit by its immutable SHA with `core.commitGraph`
`false`, `--no-replace-objects`, and the `GIT_NO_REPLACE_OBJECTS` environment
binding, so a poisoned commit-graph or replace refs cannot substitute a different
tree for the staged SHA.

## Verification

- `commands::tests::makepkg_guard_ignores_index_flags` sets
  `--skip-worktree` and `--assume-unchanged` on `PKGBUILD` and asserts the
  private build directory still contains the audited bytes.
- `commands::tests::makepkg_guard_ignores_helper_worktree_changes` covers
  dirty worktree, staged changes, and untracked files.
- `commands::tests::makepkg_guard_builds_staged_sha_not_helper_head` covers
  a moved `HEAD` and verifies the staged tree is built.
- `git::tests::safe_git_ignores_poisoned_commit_graph` ensures object-view
  substitution is disabled for `git archive`.
