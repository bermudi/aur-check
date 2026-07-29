# gh#11 — Force C locale for deterministic regex and byte processing (Cohort 2 M2)

**Source:** GitHub issue [#11](https://github.com/bermudi/aur-check/issues/11)
(Cohort 2, medium M2)
**Status:** fixed
**Severity:** medium
**Lines:** locale hardening at `aur-safe:38-45`; existing local `LC_ALL=C` usage at `aur-safe:361`, `aur-safe:367`, `aur-safe:658`

## Summary

`aur-safe` parses PKGBUILDs, `.SRCINFO`, diff output, and source URLs with
ASCII-oriented regexes, bracket character classes (`[[:alnum:]]`, `[[:space:]]`,
`[[:print:]]`), and byte-oriented text tools (`tr`, `grep`, `awk`, `sort`).

Before this fix the script inherited the caller's locale. In a UTF-8 locale:

- `[[:alnum:]]` / `[[:alpha:]]` can match non-ASCII characters.
- Collation and character-class ranges become locale-dependent, potentially
  letting multibyte or invalid-byte input evade deterministic checks.
- `_source_line_nonascii()` already forced `LC_ALL=C` locally, but the rest of
  the pipeline (diff parsing, source-domain extraction, checksum reflow
  detection, PKGBUILD rule matching) did not.

Only `_source_line_nonascii()` and two `tr`/`grep` calls had local `LC_ALL=C`
overrides.

## Fix

Added a global locale lock at the top of the script, before any text
processing:

```bash
export LC_ALL=C
export LANG=C
```

The `LC_ALL=C` export forces the C locale for all child processes and regex
operations. `LANG=C` is set as a fallback so the default stays deterministic even
if some later environment unsets `LC_ALL`.

The pre-existing local `LC_ALL=C` calls (`_source_line_nonascii()`,`tr
'[:upper:]' '[:lower:']`, `grep` in `_git_local_config_is_safe()`) are now
redundant but are retained as defense-in-depth documentation.

## Verification

- `bash -n aur-safe` — clean.
- `shellcheck -s bash aur-safe` — clean (SC2016/SC2001 excluded via
  `.shellcheckrc`).
- `./aur-safe selftest </dev/null` — 309 passed, 0 failed. The C-locale setting
  did not regress diff parsing, source-domain extraction, checksum reflow
  classification, or the `[[...]]` regex checks used by the hard rules.

## Lesson

Security tools that rely on ASCII character classes and exact byte matching must
not inherit the caller's locale. Locale is an input channel: `LC_ALL` and
`LC_CTYPE` can silently change what `[[:alnum:]]`, ranges, and case-folding
match. The fix is cheap and belongs near the top, next to the other environment
sanitization already in place for git.
