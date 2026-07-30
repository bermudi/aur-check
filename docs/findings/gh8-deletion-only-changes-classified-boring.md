# gh#8 — Deletion-only PKGBUILD changes classified boring (Cohort 2 H4)

**Source:** GitHub issue [#8](https://github.com/bermudi/aur-check/issues/8)
(Cohort 2, high H4)
**Related:** [W — Maintainer-drift blind to orphan adoption](W-maintainer-drift-blind-to-orphan-adoption.md)
**Status:** fixed
**Severity:** high
**Lines:** `_diff_removed_lines` / `_diff_removed_metadata_file` at
`aur-safe:522-538`; removed-field check in `classify_diff_rules()` at
`aur-safe:1895-1935`; selftest fixtures and `tc_class` cases at
`aur-safe:4477-4509` and `aur-safe:4628-4645`.

## Summary

`classify_diff_rules()` builds `scan_added` from the added lines of the diff
and runs hard rules, review rules, and the fail-closed PKGBUILD structural
classifier against those added lines. Removed lines are never inspected.

This means a diff that only deletes security-relevant fields has **no added
lines** for the classifier to examine, so it can fall through to `boring`:

```diff
-validpgpkeys=('0123456789ABCDEF...')
```

or:

```diff
-sha256sums=('111111...')
```

or:

```diff
-source=("https://example.com/pkg-1.tar")
```

A mixed diff can also exploit the gap: the attacker removes `validpgpkeys=` and
adds an otherwise-innocuous `pkgver` bump, and the added side alone clears.
Either way, an integrity control disappears from the PKGBUILD without the gate
noticing.

## Fix

The gate now extracts the removed side of the PKGBUILD diff with
`_diff_removed_metadata_file()` / `_diff_removed_lines()` and, before the
boring classification, checks whether any removed non-whitespace, non-comment
line is the opener/assignment of a security-relevant field that no longer
exists in the candidate:

- `source` and `source_<arch>` arrays
- `md5sums`, `sha<nn>sums`, `b2sums` and their arch-qualified forms
- `validpgpkeys`
- `install`, `noextract`, `options`, `backup`
- dependency arrays: `depends`, `makedepends`, `checkdepends`, `optdepends`,
  `conflicts`, `provides`, `replaces`
- `# Maintainer:` / `# Contributor:` comments (matched case-insensitively)

For each removed assignment line the field name is extracted from the start of
the line. If the candidate `origin/master:PKGBUILD` no longer contains that
exact field, the diff is routed to `review` with `[pkgbuild-<field>-removed]`
(or `[maintainer-line-removed]`). If the same field is still present, the
deletion is treated as a value change or reflow and is left to the existing
added-line classifier, which already handles checksum/source replacement and
version bumps.

Array member lines (e.g. a removed middle checksum string) do not carry the
field name and are not individually checked; the opener/closer line is removed
only when the whole array is gone, which is the full-field deletion the finding
is about.

## Verification

- `bash -n aur-safe` — clean.
- `shellcheck -s bash aur-safe` — clean (SC2016/SC2001 excluded via
  `.shellcheckrc`).
- `./aur-safe selftest </dev/null` — 318 passed, 0 failed, including the new
  fixtures:
  - `classifier-delete-validpgpkeys-field` (review)
  - `classifier-delete-sha256sums-field` (review)
  - `classifier-delete-source-field` (review)
  - `classifier-same-host-source-replacement-boring` (boring — value change,
    not deletion)

## Lesson

A deterministic diff gate cannot look only at additions. Security-relevant
PKGBUILD fields carry integrity and authority; when one disappears from the
candidate, the gate must require review even if the diff also contains inert
added metadata. The check is field-presence based, not a name blacklist, so
version bumps and reflows that keep the same field clear normally while full
field removal fails closed.
