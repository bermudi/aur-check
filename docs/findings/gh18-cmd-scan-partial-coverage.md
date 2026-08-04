# gh#18 — `cmd_scan` coverage is partial (Cohort 2 L1)

**Source:** GitHub issue [#18](https://github.com/bermudi/aur-gate/issues/18)
(Cohort 2, low L1)
**Status:** fixed
**Severity:** low
**Lines:** `cmd_scan()` at `aur-gate:2706`

## Summary

`cmd_scan` performs a retroactive, advisory scan of already-installed pacman
scriptlets and alpm hooks:

```bash
files=(/var/lib/pacman/local/*/install /etc/pacman.d/hooks/* /usr/share/libalpm/hooks/*)
```

It does **not** cover every libalpm script or helper-installed script location.
Examples outside the current scan set include helper-specific build/install
artifacts, custom hook directories, or scripts installed outside the fixed
pacman/libalpm paths. Because `cmd_scan` is explicitly advisory and not part of
the trust path, this is an acceptable limitation, but it must be documented so
callers do not mistake the retroactive scan for comprehensive coverage.

## Fix

- Added this finding doc (`docs/findings/gh18-cmd-scan-partial-coverage.md`) as
the canonical record of the accepted limitation.
- Updated `docs/findings/README.md` to cross-reference the closed issue.
- No functional change to `cmd_scan`; the scan set stays intentionally narrow
and advisory.

## Verification

- `bash -n aur-gate` — clean.
- `shellcheck -s bash aur-gate` — clean (SC2016/SC2001 excluded via
  `.shellcheckrc`).
- `./aur-gate selftest` — unchanged (no code changes).

## Lesson

Advisory, retroactive scans cannot silently overstate their coverage. Gaps in
coverage that are accepted for scope reasons should be documented explicitly
rather than left implicit, so users do not extend a partial scan result into a
false guarantee.
