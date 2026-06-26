# Finding N — Split-package missing-cache degrades to tier-2 whole-file fallback

**Source:** kimi-k2.6 red-team review, session `019f0517-d73a-78d5-929f-c514eed1880d`  
**Status:** open  
**Severity:** medium  
**Lines:** `check_pkg()` at aur-safe:994, `_clone_aur()` at aur-safe:617

## What happens

A split package (pkgname ≠ pkgbase, e.g. `windsurf`) whose helper cache clone
has been deleted: `yay -Qua` reports the pkgname. `check_pkg` receives `$pkg` =
pkgname. `find_pkg_dir` fails (no cache). Falls through to `missing_cache_gate
"$pkg"`, which calls `_clone_aur dir "$pkg"`. `_clone_aur` constructs the URL as
`${AUR_URL}/${pkg}.git` — but AUR git repos are keyed by **pkgbase**, not
pkgname. Clone of `pkgname.git` fails → `missing_cache_gate` returns 2 after
tier-2 whole-file scan.

**Impact:** The missing-cache path loses baseline recovery (tier 1) for split
packages, degrading to the coarse whole-file fallback. This is exactly the
"ventoy-bin" blindspot that baseline recovery was designed to fix. For a split
package with a pre-existing `.install` hook, the user gets a review/consent
prompt on every update instead of a clean diff. Worsened by Finding G
(tier-2 skips review rules).

## Fix

Resolve pkgbase before calling `_clone_aur`. Options: query the AUR RPC, seed
from a known mapping, or parse `yay -Qua` output more carefully (some helpers
emit pkgbase). At minimum, document the limitation clearly.

## Test gap

No selftest covers a split package routed through `missing_cache_gate`.
