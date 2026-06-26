# Finding B — `cmd_scan` is an ad-hoc third rule pipeline

**Source:** kimi-k2.6 delegate review, session `019f0184-3dbd-7d44-b9b3-8ef793ee553b`  
**Updated:** 2026-06-26 — fixed by converging `cmd_scan` on the shared rule arrays  
**Status:** closed (fixed in code; retroactive scanner is report-only and advisory)
**Lines:** `_scan_report_file()` / `cmd_scan()` at `aur-safe:842-887`

## What happens

`cmd_scan` used to hardcode its own `grep -rE` patterns for retroactive scanning
of already-installed packages. Those patterns lagged the `RULE_PATTERNS` arrays
the live gate uses.

### Rule divergence table

| Package manager | Gate (`RULE_PATTERNS`) | `cmd_scan` | Missing |
|---|---|---|---|
| npm | `install\|i\|ci\|add\|run\|exec` | `install\|i\|add` | `ci`, `run`, `exec` |
| pnpm | `install\|i\|add\|ci\|run` | `install\|add` | `i`, `ci`, `run` |
| bun | `add\|x\|install` | `add\|x` | `install` |
| yarn | `add\|install` | `add` | `install` |

Additionally, `cmd_scan` hardcodes the exact blacklist names
(`atomic-lockfile|crypto-javascript|lockfile-js|nextfile-js|js-digest`) that the
main gate deliberately avoids — the gate uses structural pattern detection
because "the attacker rotates names faster than blacklists track"
(design-ledger.md).

### Evidence from the June 2026 campaign (aur-general list)

The `aur-general` mailing list (301 messages, 2026-06-01 through 2026-06-24)
documents the actual campaign. The attacker *did* rotate names and installers
exactly as the gate's structural approach predicted:

- **Payload names beyond the blacklist:** `yargs`, `chalk`, `minimist`,
  `ansicolor`, `nextfile-js`. `cmd_scan`'s hardcoded list misses all of them.
- **Wave 2 switched installers:** `bun add` (not `npm install`). `cmd_scan`
  covers `bun add\|x` but misses `bun install` — the gate's `RULE_PATTERNS` has
  `add\|x\|install`, `cmd_scan` has `add\|x`.
- **Wave 3 used escape obfuscation:** `$'\x63'"d"` / `$'\141\x6e'` etc. —
  `cmd_scan`'s grep would miss this entirely because it pattern-matches
  strings, not structural features. The main gate's hex/octal escape-run
  detector (a structural rule) catches it.

The divergence is not theoretical — it's a documented gap against a real
campaign that evolved across three waves in four days.

### Why this exists

`cmd_scan` is a *retroactive* scan of already-installed packages (different
purpose from the live gate). The divergence may have been accidental or an
unwritten attempt to reduce noise on installed things, but it was a maintenance
hazard: updating the main `RULE_PATTERNS` arrays did not update `cmd_scan`;
adding a new hard-fail rule to the gate did not make `cmd_scan` retroactively
catch already-installed instances.

## Fix

`cmd_scan` now uses `_scan_report_file()`, a report-only scanner over the live
gate's `RULE_NAMES` / `RULE_PATTERNS` and `REVIEW_NAMES` / `REVIEW_PATTERNS`.
There is no longer a blacklist of payload package names and no separate
package-manager regex list.

Two details keep the retroactive scanner useful without weakening the gate:

- `cmd_scan` feeds only installed execution surfaces:
  `/var/lib/pacman/local/*/install`, `/etc/pacman.d/hooks/*`, and
  `/usr/share/libalpm/hooks/*`.
- `_scan_report_file()` skips the two hook-surface marker rules
  (`install-hook-ref`, `install-hook-func`) because the selected inputs are
  already installed hook/scriptlet surfaces. A clean `post_install()` scriptlet
  is not itself a payload signal; npm/bun/yarn, pipe-to-interpreter,
  decode/obfuscation, and review rules still come from the shared arrays.

The command remains advisory retroactive triage: it exits non-zero when it finds
anything, but it is not part of the update trust path.

## Verification

Selftests now cover the shared-rule scanner with `npm ci`, `bun install`,
`yarn install`, hex escape runs, pipe-to-interpreter, and a clean hook. Updating
`RULE_PATTERNS` now automatically changes retroactive scan coverage.
