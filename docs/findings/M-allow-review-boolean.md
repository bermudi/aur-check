# Finding M — `AUR_SAFE_ALLOW_REVIEW=0` enables auto-proceed

**Source:** kimi-k2.6 red-team review, session `019f0517-d73a-78d5-929f-c514eed1880d`  
**Status:** open  
**Severity:** medium  
**Lines:** `review_prompt()` at aur-safe:1156, `_aur_safe_gate()` at aur-safe:1529

## What happens

Both locations test `[[ -n "${AUR_SAFE_ALLOW_REVIEW:-}" ]]`. Any non-empty string
is truthy in bash, including `0`, `no`, `false`. A user setting
`AUR_SAFE_ALLOW_REVIEW=0` intending to disable auto-proceed actually **enables**
it. The gate auto-proceeds on all review hits, including clone failures and
`audit_unavailable`.

## Fix

Change to `[[ "${AUR_SAFE_ALLOW_REVIEW:-}" == "1" ]]` in both locations.

## Test gap

No test for `AUR_SAFE_ALLOW_REVIEW=0` behavior. Verify it blocks, not proceeds.
