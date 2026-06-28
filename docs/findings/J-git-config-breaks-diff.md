# Finding J — User git config breaks diff parsing

**Source:** kimi-k2.6 red-team review, session `019f0517-d73a-78d5-929f-c514eed1880d`  
**Status:** fixed (2026-06-28) — `export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null` at script load; pinned by `git-config-isolation-hard-rules-fire` selftest  
**Severity:** high  
**Lines:** `diff_added()` at aur-safe:208-211, `_pkgbuild_optdepends_added_line()` at aur-safe:291-319, `_describe_added_line()` at aur-safe:320-351, `files_with_status()` at aur-safe:238-246, `name_status` loop at aur-safe:714-736

## What happens

User git config options that alter diff output break the entire classification
pipeline. The script does not set `GIT_CONFIG_GLOBAL=/dev/null` or pass
`--no-color --no-ext-diff --src-prefix=a/ --dst-prefix=b/` to git diff commands.

**Specific breakages:**

- `diff.colorWords=true` / `diff.wordDiff=true` — diff output is word-oriented,
  no `+` line prefixes. `diff_added`'s `sed -n '/^+++/!s/^+//p'` returns empty.
  All hard/review content rules find nothing. A modified `.install` hook with
  `npm install` produces no hits.
- `diff.noprefix=true` — `+++` headers become `+++ PKGBUILD` instead of
  `+++ b/PKGBUILD`. The file-tracking regexes in `_pkgbuild_optdepends_added_line`
  and `_describe_added_line` (anchored on `^\+\+\+ b\/`) never match → always
  return "not found".
- `diff.mnemonicPrefix=true` — prefixes change from `a/`/`b/` to `i/`/`w/` etc.
- `textconv` filters on PKGBUILD — `git show` could execute arbitrary code
  (user-compromise scenario, not AUR attacker).

**Impact:** A malicious diff with `npm install` or `curl | sh` produces an
empty `added` string → hard rules don't fire. Structural checks might still
catch file-level changes, but modified `.install` hooks with only content
changes would slip through.

## Fix

Export `GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null` at the top of
the script, or pass `-c diff.colorMoved=no --no-color --no-ext-diff
--src-prefix=a/ --dst-prefix=b/` to all git diff/show commands in the trust
path. This single change closes the `diff.colorWords`, `diff.noprefix`, and
`textconv` attack surface.

## Test gap

No test with `GIT_CONFIG_GLOBAL` set to a malicious config. Add a selftest
fixture with `diff.colorWords=true` and verify hard rules still fire.
