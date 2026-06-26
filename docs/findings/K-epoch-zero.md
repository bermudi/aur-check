# Finding K — `epoch=0` breaks install confirmation and baseline recovery

**Source:** kimi-k2.6 red-team review, session `019f0517-d73a-78d5-929f-c514eed1880d`  
**Status:** open  
**Severity:** high  
**Lines:** `_installed_matches()` at aur-safe:515-518, `find_baseline_commit()` at aur-safe:567

## What happens

A PKGBUILD that explicitly sets `epoch=0` (legal in makepkg; emitted to
`.SRCINFO` as `epoch = 0`) breaks both install confirmation and baseline
recovery. Pacman only displays the epoch prefix when it is non-zero, so
`pacman -Q` reports `pkgname 1.0-1`, not `pkgname 0:1.0-1`.

- **`_installed_matches`:** `epoch=$(awk ... '/^[[:space:]]*epoch =/ {print $2}')`
  captures `0`. `[[ -n "$epoch" ]]` is true, so `want` becomes `0:1.0-1`.
  `pacman -Q` returns `1.0-1`. Strings don't match → returns 1 → `accept` never
  promotes the staged ref.
- **`find_baseline_commit`:** The awk script produces `0:1.0-1`. But
  `_pacman_query` returns `1.0-1` (no `0:`). The baseline commit is never found
  → missing-cache path falls back to tier-2 whole-file scan.

**Impact:** The trust anchor never advances for packages with `epoch=0`. Every
subsequent gate re-audits the full diff from the stale anchor, training users
that the gate "always flags this package." In automation with
`AUR_SAFE_ALLOW_REVIEW=1`, it causes repeated consent prompts or log noise. It
also degrades missing-cache baseline recovery to the weaker whole-file fallback.

## Fix

Treat `epoch=0` the same as empty epoch when constructing the version string for
comparison with `pacman -Q`, since pacman normalizes it away:
```bash
[[ -n "$epoch" && "$epoch" != "0" ]] && want="${epoch}:" ; want+="${ver}-${rel}"
```

## Test gap

No selftest fixture uses `epoch=0`. Add fixtures for both `_installed_matches`
and `find_baseline_commit` with `epoch = 0` in `.SRCINFO`.
