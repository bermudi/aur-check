# gh#21 — SHA-1 trust anchors will not support SHA-256 git repos (Cohort 2 L4)

**Source:** GitHub issue [#21](https://github.com/bermudi/aur-gate/issues/21)
(Cohort 2, low L4)
**Status:** fixed
**Severity:** low
**Lines:** `accepted_ref()` at `aur-gate:1341`; `write_ref()` at `aur-gate:1351`;
`find_baseline_commit()` awk parser at `aur-gate:1512,1517`; `_clone_aur()` at
`aur-gate:1576`; `_stage_scan_if_gating()` at `aur-gate:1667`; `_cmd_accept_locked()`
at `aur-gate:2566`; `cmd_makepkg()` at `aur-gate:2786`.

## Summary

`aur-gate` validates git object IDs by matching `^[0-9a-f]{40}$` wherever a
commit SHA enters the trust path:

- `accepted_ref()` reads `~/.cache/aur-gate/accepted/<pkgbase>`.
- `write_ref()` records the `origin/master` tip as a staged or accepted ref.
- `_clone_aur()` and `_stage_scan_if_gating()` capture and record the missing-cache
  gate-time tip.
- `_cmd_accept_locked()` and `cmd_makepkg()` re-validate the staged ref before
  promotion or build.
- `find_baseline_commit()` parses `git cat-file --batch` headers and missing-object
  markers for baseline recovery.

SHA-256 git repositories use 64-hex object IDs. A future AUR repo (or any
helper-local clone) using the SHA-256 object format would therefore fail every
gate path: accepted refs rejected, staging rejected, baseline recovery desynced,
and the makepkg exact-SHA guard unable to match HEAD against the staged ref.
AUR is currently SHA-1, so this is defense-in-depth future-proofing, not an
active bypass.

## Fix

Changed every SHA-length regex from the SHA-1-only pattern
`^[0-9a-f]{40}$` to `^[0-9a-f]{40}([0-9a-f]{24})?$`, which accepts exactly 40
or 64 hex characters and nothing in between.

This single pattern was applied to all six Bash `[[ ... =~ ... ]]` validation
sites and to the two `awk` regular expressions in `find_baseline_commit()` that
parse `git cat-file --batch` headers (`<sha> <type> <size>`) and missing-object
markers (`<sha>:.SRCINFO missing`). The 64-hex form is the optional tail of 24
additional hex digits, keeping the regex anchored and deterministic.

The object-existence checks that follow (`git cat-file -e`,
`git rev-parse --verify`, `git diff`, HEAD comparison) already accept any valid
git object name, so only the input-shape validation needed widening.

## Verification

- `bash -n aur-gate` — clean.
- `shellcheck -s bash aur-gate` — clean (SC2016/SC2001 excluded via
  `.shellcheckrc`).
- `./aur-gate selftest </dev/null` — 312 passed, 0 failed. Existing SHA-1-only
  fixtures still resolve and promote correctly, and the baseline-recovery
  `cat-file --batch` parser stays in sync. A positive SHA-256 block
  (`-- gh21 SHA-256 trust anchors --`) builds a real `git init
  --object-format=sha256` repo and asserts `accepted_ref` resolves a 64-hex
  anchor, `write_ref` records a 64-hex tip, and `find_baseline_commit` parses
  64-hex `cat-file --batch` headers — pinning the capability the fix adds. The
  block SKIPs cleanly on git builds without sha256 object-format support.

## Lesson

Git object IDs are not always 40 hex characters. Any code that hardcodes SHA-1
lengths will silently break when a repository uses SHA-256. The right shape
validation is a precise alternation (40 or 64 hex), not a range, with git itself
acting as the source of truth for object existence. The trust-anchor path is the
most important place to get this right: if the accepted ref format rejects a
valid future commit, the gate cannot advance the anchor even for a fully audited
build.
