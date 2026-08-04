# gh#19 — `_collect_review_details()` uses tab-separated records (Cohort 2 L2)

**Source:** GitHub issue [#19](https://github.com/bermudi/aur-gate/issues/19)
(Cohort 2, low L2)
**Status:** fixed
**Severity:** low
**Lines:** `_collect_review_details()` at `aur-gate:1131`; caller at `aur-gate:1959-1963`

## Summary

`_collect_review_details()` walks a `git diff` and emits one record per
non-boring `+` line for the review-detail summary:

```
<raw added-line text> \t <formatted detail ("file:line: text")>
```

The record was split with `IFS=$'\t' read -r d_text d_fmt` in the caller.
Because the raw added-line text can legitimately contain tab characters
(e.g. indentation in `PKGBUILD` or literal string content), a tab inside the
text was misread as the field boundary: `d_text` was truncated, `d_fmt` got the
remainder, and the detail shown to the user was mangled.

The gate's diff classification happens before this helper is invoked, so the
security decision was unaffected; this was a review-detail presentation bug.

## Fix

- `_collect_review_details()` now emits records with a NUL (0x00) delimiter
  between the raw added-line text and the formatted detail:

  ```awk
  printf "%s\0%s:%d: %s\n", text, file, newln, text
  ```

  The detail intentionally omits Git's heuristic hunk heading; it is not parsed
  PKGBUILD shell scope.

- The caller now reads the two fields in two `read` steps:

  ```bash
  while IFS= read -r -d '' d_text && IFS= read -r d_fmt; do
    cand_text+=("$d_text"); cand_fmt+=("$d_fmt")
  done < <(_collect_review_details "$dir" "$base_ref" "$want_file")
  ```

  `read -d ''` consumes up to the NUL byte, preserving any tabs or other
  whitespace in `d_text`. The second `read` consumes the formatted detail up to
  the newline. Setting `IFS=` prevents trimming of leading or trailing
  whitespace in either field.

- Comments describing the record layout were updated from "tab-separated" to
  "NUL-separated".

NUL is a safe delimiter because `PKGBUILD`/diff text cannot contain embedded
NUL bytes, so it is unambiguous while still preserving the exact added-line
bytes needed by `_detail_is_build_logic()`.

## Verification

- `bash -n aur-gate` — clean.
- `shellcheck -s bash aur-gate` — clean.
- `./aur-gate selftest </dev/null` — 319 passed, 0 failed.
- `classifier-detail-tab-in-text` sends an added build-command line containing
  a literal interior tab through `_collect_review_details()` and its caller,
  then asserts that the complete rendered `PKGBUILD:<line>: <text>` detail
  retains the tab. Reverting the caller to `IFS=$'\t' read` makes this test
  fail.

## Lesson

When carrying an unescaped payload alongside metadata in a single record, the
field separator must be a byte the payload cannot contain. Tabs are a
legitimate character in PKGBUILD source, so they cannot serve as the boundary
between the raw line and its formatted detail. NUL keeps the record format
simple and preserves every byte of the original diff line.
