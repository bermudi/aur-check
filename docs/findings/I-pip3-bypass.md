# Finding I — `pip3 install` bypasses `pip` review rule

**Source:** glm-5.1 red-team review, session `019f0517-d737-732f-b8d6-6ae4c3208309`  
**Status:** open  
**Severity:** high  
**Lines:** `add_review pip` at aur-safe:151

## What happens

The pip review rule at line 151 uses the pattern `pip[[:space:]]+(install|download)`.
This requires literal `pip` immediately followed by whitespace. `pip3 install
evil-pypkg` (the default `pip` on modern Arch systems) does NOT match. Same for
`pip-3 install` and `python -m pip install`.

On the cached/tier-1 diff paths, the diff classifier still catches "non-boring
line → review exit 2", so this is not silent — but it loses the explicit `[pip]`
review tag, degrading user comprehension. Combined with Finding G (tier-2
skipping review rules), `pip3 install malicious-pypkg` on a missing-cache tier-2
path is **silent**.

## Fix

Broaden to `pip3?[[:space:]]+(install|download|wheel|build)` or
`(pip|pip3|pip-3|python -m pip)[[:space:]]+(install|download)`.

## Test gap

Add selftest for `pip3 install foo` matching the review rule.
