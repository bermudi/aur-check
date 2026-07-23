# Finding O — `find_pkg_dir` slow path doesn't verify `.git` exists

**Source:** qwen3.7-max red-team review, session `019f0517-d73a-78d5-929f-caae55c267e2`; also flagged by glm-5.1  
**Status:** fixed (2026-07-23)
**Severity:** medium  
**Lines:** `find_pkg_dir()` slow path at aur-safe:192

## What happens

The slow path (when `$pkg` doesn't contain `-`) checks `[[ -f "${d}.SRCINFO" ]]`
but not `.git`. Fast path (line 189) correctly checks `.git`. If the slow path
returns a directory with `.SRCINFO` but no `.git` (corrupted cache, manual
deletion), all subsequent git operations fail:

- `git -C "$dir" fetch` fails silently
- `git rev-parse --verify "origin/master"` fails → `return 0` (skip)

The package is silently skipped from audit, printing "skip" — an ungated
passthrough.

## Exploitability

**Low** — requires local cache corruption, not attacker-controlled. But it's a
silent audit skip, same structural class as the original missing-cache blindspot.

## Fix

Add `.git` check to slow path: `[[ -d "${d}/.git" && -f "${d}/.SRCINFO" ]]`.

## Implementation

The old directory scan is gone. Split pkgname→pkgbase is resolved through AUR
RPC and only that exact cache directory is considered, with both `.git` and
`.SRCINFO` required. This also prevents an unrelated attacker-authored cached
`.SRCINFO` from claiming the split pkgname and redirecting the gate.
