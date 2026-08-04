# gh#22 — `_valid_pkg_name` rejects uppercase package names (Cohort 2 L5)

**Source:** GitHub issue [#22](https://github.com/bermudi/aur-gate/issues/22)
(Cohort 2, low L5)
**Status:** fixed
**Severity:** low
**Lines:** `_valid_pkg_name()` at `aur-gate:373`; `_installed_matches()` at
`aur-gate:1449`; `_aur_gate_classify()` at `aur-gate:2900`.

## Summary

`_valid_pkg_name()` enforced a lowercase-only package-name grammar:

```bash
[[ "$1" =~ ^[a-z0-9@._+-]+$ && "$1" != .* ]]
```

AUR package names are *usually* lowercase, but uppercase letters are valid
pkgname characters. A package like `UpperCase-Pkg` therefore passed no input
validation layer but was rejected by `aur-gate check`/`audit`/`explain`/gate,
producing a false "invalid package name" block.

The same lowercase-only regex had also been copied into `_installed_matches()`
(`.SRCINFO` → installed-name matching for `cmd_accept`). An installed
uppercase pkgname would be silently skipped during install confirmation, so
`accept` could fail to promote the anchor for a valid build.

A third copy existed in the generated wrapper's `_aur_gate_classify()` (the
`case` pattern used to decide whether a `yay -S <arg>` target is an AUR package
or a helper option). With that pattern still lowercase-only, `yay -S UpperCase-Pkg`
would be classified as `INVALID_TARGET` and the wrapper would abort before the
gate could ever run — a false-deny that pushes users to bypass the wrapper.

## Fix

- Central `_valid_pkg_name()` now allows uppercase:

  ```bash
  _valid_pkg_name() {
    [[ "$1" =~ ^[A-Za-z0-9@._+-]+$ && "$1" != .* ]]
  }
  ```

  The dot-prefix traversal guard (`"$1" != .*`) is unchanged; uppercase adds no
  path-traversal or URL-injection risk because the allowed character set is
  still limited to AUR-safe path/url characters.

- `_installed_matches()` no longer duplicates the regex. It now delegates to
  `_valid_pkg_name "$pkgname" || continue`, so install-confirmation benefits
  from the same canonical grammar and cannot drift again.

- `_aur_gate_classify()` (the emitted wrapper) now uses the same character set
  in its POSIX `case` pattern: `*[!a-zA-Z0-9@._+-]*` plus the `.*` dot-prefix
  guard. Uppercase package names are now accepted as AUR install targets.

- New selftests assert uppercase acceptance at both layers:
  - `uppercase-package-name-accepted` for `_valid_pkg_name`
  - `-S UpperCase-Pkg` for the wrapper `_aur_gate_classify`

## Verification

- `bash -n aur-gate` clean.
- `./aur-gate selftest </dev/null` → 304 passed, 0 failed, including the new
  `uppercase-package-name-accepted` test.
- Dot-prefixed/traversal names (`..`, `.git`) still fail validation at every
  boundary that calls `_valid_pkg_name`.

## Lesson

Don't make the validator stricter than the underlying format unless the
restriction carries a security benefit. Lowercase-only package names are a
*convention*, not a safety rule; uppercase letters do not introduce path
injection, URL manipulation, or traversal. Centralizing validation in a single
`_valid_pkg_name()` and calling it from install-confirmation avoids duplicate
regexes that silently diverge.
