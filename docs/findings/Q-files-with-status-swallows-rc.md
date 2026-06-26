# Finding Q — `files_with_status` silently ignores git diff failures

**Source:** kimi-k2.6 red-team review, session `019f0517-d73a-78d5-929f-c514eed1880d`  
**Status:** open  
**Severity:** medium  
**Lines:** `files_with_status()` at aur-safe:238-246

## What happens

`files_with_status` pipes `git diff ... 2>/dev/null` into `awk` without checking
the pipeline exit code. If `git diff` fails (corrupted object, race with `git gc`,
disk error), stdout is empty, `awk` prints nothing, and the caller
(`classify_diff_rules`) sees an empty result → "no new `.install` files".

This is called *after* `diff_added` has already succeeded, so the diff itself is
readable, but the file-status enumeration fails silently. `new_installs` and
`mod_installs` are hard/review triggers. If `git diff --name-only` fails, a new
`.install` file could be missed.

## Fix

Follow the `diff_added` pattern: capture output, assert exit code, then process:
```bash
diff_out=$(git -C "$dir" diff ... 2>&1) || return 1
```

## Test gap

No test for `git diff --name-only` failure while `diff_added` succeeds.
