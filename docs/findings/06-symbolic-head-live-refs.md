# Finding 6 — live refs and symbolic HEAD re-resolve to a moved branch

**Source:** 2026-08-04 trust-path review (Phase 2, private build checkout)
**Status:** fixed by private build checkout
**Severity:** critical
**Surface:** helper checkout refs, makepkg guard

## What happens

`TrustedGitView` builds a private Git metadata view for each `safe_git` call. It
copies `config`, `HEAD`, and `index` into a temporary `GIT_DIR`, but it symlinks
`refs/` and `packed-refs` from the real checkout so that `git fetch` can persist
remote-tracking updates. Because the private view's `HEAD` file is a snapshot and
the `refs/` directory is live, a branch ref moved after the staged-SHA check can
re-resolve: `HEAD` still points to `refs/heads/master`, but `refs/heads/master`
now resolves to a different commit. `git rev-parse HEAD` or `git show HEAD:...`
can therefore return the new, unaudited commit even though the guard already
validated a staged SHA.

## Why it mattered

The previous makepkg guard performed staged-SHA validation and then used `HEAD`
during `package_surfaces_are_regular` and `makepkg` execution. A same-user writer
who could move a branch ref between those two points in time could redirect the
build to a newer commit. The window is small but real; the reviewer warned that
checking mutable checkout state across several Git invocations cannot establish
one atomic build view.

## Implemented mechanism

`cmd_makepkg` no longer resolves `HEAD` for the build. It uses the staged SHA
record from the transaction state as the only commit identity. Materialization is
done with `git archive <staged_sha> | tar -x` against the helper's object store.
`git archive` resolves the commit by its immutable SHA, not by a ref; it does not
read `HEAD` or `refs/heads/...` at all. The private build directory is created
from the archived tree, and `makepkg` is run there. Branch moves, packed-ref
updates, or `HEAD` changes in the helper checkout cannot redirect the build.

The `TrustedGitView` still symlinks `refs/` for non-makepkg commands (e.g.,
`git fetch` in the gate path) because remote-tracking updates must persist across
calls. The makepkg seam is the only place that must not trust live refs, and it
no longer does.

## Verification

- `commands::tests::makepkg_guard_builds_staged_sha_not_helper_head` commits a
  new `PKGBUILD` after the staged commit and verifies `cmd_makepkg` builds the
  staged tree, not the new `HEAD`.
- `wrapper_transaction::wrapper_window_commit_builds_staged_sha_not_helper_head`
  runs the full wrapper with a helper that moves `HEAD` after the gate and
  asserts the staged SHA is accepted and the built `PKGBUILD` lacks the new
  commit's marker.
