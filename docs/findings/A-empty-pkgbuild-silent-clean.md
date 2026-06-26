# Finding A — Empty PKGBUILD in tier 2 treated as clean

**Source:** kimi-k2.6 delegate review, session `019f0184-3dbd-7d44-b9b3-8ef793ee553b`  
**Status:** closed (fixed — `_scan_whole_pkg` failure surfaces as review exit 2)  
**Lines:** `_scan_whole_pkg()` at `aur-safe:382`, caller at `aur-safe:595`

## What happens

`missing_cache_gate` tier 2 (whole-file fallback) calls `_scan_whole_pkg` but
drops the return code:

```bash
# aur-safe:595
_scan_whole_pkg "$dir"; rm -rf "${dir%/*}"
if (( SCAN_HITS )); then
  # ... review hit path ...
fi
```

`_scan_whole_pkg` returns 1 when content is empty (line 389):

```bash
content=$(cat "$dir"/PKGBUILD "$dir"/*.install "$dir"/*.sh 2>/dev/null || true)
[[ -z "$content" ]] && return 1
```

`_clone_aur` at line 370 checks PKGBUILD *exists* (`[[ -f ]]`) but not non-empty.
So a 0-byte PKGBUILD + no `.install`/`.sh` files → `SCAN_HITS` stays 0 → `return 0`
(clean). The gate prints "clean" having scanned nothing.

## Exploitability

**Low.** An attacker can't inject a payload through an empty file — no rules fire
on empty content, no code executes. But the gate's "clean" output is misleading.
Same structural class as the original missing-cache blindspot: error-state →
empty → clean.

## Fix

One line at `aur-safe:595` — check `$?` from `_scan_whole_pkg` and surface as
review (exit 2) on failure:

```bash
if ! _scan_whole_pkg "$dir"; then
  log "  $(c_yellow "review") $pkg — empty PKGBUILD (no content to scan)"
  return 2
fi
```

## Test gap

No selftest for empty-PKGBUILD-in-clone path. A test fixture with a 0-byte
PKGBUILD + no other sourceable files should verify exit code 2.
