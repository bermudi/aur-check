# Finding B — `cmd_scan` is an ad-hoc third rule pipeline

**Source:** kimi-k2.6 delegate review, session `019f0184-3dbd-7d44-b9b3-8ef793ee553b`  
**Updated:** 2026-06-26 — added campaign evidence from `aur-general` mailing list  
**Status:** open (deferred, needs design decision)  
**Lines:** `cmd_scan()` at `aur-safe:815-835`

## What happens

`cmd_scan` hardcodes its own `grep -rE` patterns for retroactive scanning of
already-installed packages. These patterns lag the `RULE_PATTERNS` arrays the
live gate uses.

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
purpose from the live gate). The divergence may be intentional — less aggressive
to avoid noise on installed things. But it's undocumented and a maintenance
hazard: updating the main `RULE_PATTERNS` arrays won't update `cmd_scan`; adding
a new hard-fail rule to the gate won't make `cmd_scan` retroactively catch
already-installed instances.

## Fix options

1. **Reuse `RULE_PATTERNS`** — make `cmd_scan` loop over the same arrays as the
   gate (one source of truth). Risk: may be too aggressive for retroactive
   scanning (every installed package with `npm install` in its build function
   will fire).
2. **Document the divergence with rationale** — keep the separate patterns but
   add a comment in `cmd_scan` explaining why and linking to this finding.
3. **Deprecate `cmd_scan`** — if the retroactive-triage use case is weak now that
   the live gate is hardened, remove it.

## Test gap

No selftest for `cmd_scan` at all — it exits via `exit $found`, not part of the
selftest framework.
