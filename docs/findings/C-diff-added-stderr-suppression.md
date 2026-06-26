# Finding C — `diff_added` suppresses stderr — corrupted diff silently returns clean

**Source:** glm-5.1 delegate review, session `019f0184-3dba-7727-bac9-7f203e6516af`  
**Status:** open (deferred, low exploitability but trust-path failure)  
**Lines:** `diff_added()` at `aur-safe:160-163`, pre-diff short-circuit at `aur-safe:645-648`

## What happens

`diff_added` pipes `git diff` through `sed` with stderr silenced:

```bash
# aur-safe:160-163
diff_added() {
  git --no-pager diff "$@" -- "${EXCLUDE_PATHS[@]}" 2>/dev/null \
    | sed -n '/^+++/!s/^+//p'
}
```

If `git diff` fails (corrupted object, GC'd baseline SHA, disk error), stderr is
silenced, stdout is empty → `added` is empty → every rule loop finds nothing →
`scan_diff_rules` returns 0 (clean). The pre-diff short-circuit has the same hole:

```bash
# aur-safe:645-648 (approx, cached path)
if ! git -C "$dir" diff --name-only "${base}..origin/${AUR_REMOTE_BRANCH}" \
  -- "${EXCLUDE_PATHS[@]}" 2>/dev/null | grep -q .; then
  # "ok — no source changes" path
```

## Why this matters

The gate's "ok — no source changes" output is reachable from both:
- "properly audited and found nothing" (correct)
- "couldn't run the audit at all" (silent failure)

The fetch-failure rationale from REVIEWER-NOTES ("failing closed would train
users to ignore warnings") doesn't apply here — a corrupted baseline has no
cached fallback like a stale `origin/master` does. If the diff command itself
can't run, the data we need is absent, not stale.

## Exploitability

**Low** — requires corrupted repo state (disk error, GC'd referenced object).
But it's a silent trust-path failure: the gate says "clean" when it did zero
work.

## Fix

Assert `git diff` exit code. `set -o pipefail` is already active, so using
`$?` after the pipeline doesn't work (pipefail makes the pipeline return the
last failing component, which is `sed` when `git diff` fails). Fix:

```bash
diff_added() {
  local diff_out rc
  diff_out=$(git --no-pager diff "$@" -- "${EXCLUDE_PATHS[@]}" 2>/dev/null) || return 2
  sed -n '/^+++/!s/^+//p' <<<"$diff_out"
}
```

Or capture into a variable + check `PIPESTATUS[0]` before `pipefail` masks it.
Surface as review (exit 2) on failure, never silently clean.

## Test gap

No selftest for corrupted-baseline → empty-diff → fails-clean. Would need a
fixture with a corrupted git object (e.g. `git gc` then delete a pack file).
