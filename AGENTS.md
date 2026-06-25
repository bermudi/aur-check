# AGENTS.md

## Project
`aur-safe` — a deterministic gate for Arch Linux AUR package updates, run as a
shell wrapper around `yay`/`paru`. Single-user, single-machine, not distributed.
Born during the May–June 2026 AUR supply-chain attack; its entire reason for
existing is to stop malicious AUR updates from reaching pacman. **Read
`REVIEWER-NOTES.md` before touching the trust path** — it's the design ledger
(threat model, settled decisions, rejected approaches, verification status).

## Stack
Bash 5.3, git, an AUR helper (`yay` or `paru`). `pi` only for the advisory
`explain` subcommand. No build system, no other dependencies. Single-file script
(`aur-safe`); runtime state under `~/.cache/aur-safe/`.

## Architecture
The gate runs **before** the helper on `yay/paru -Syu`. **Deterministic regex
rules are the gate; the LLM is never on the trust path** — it's an on-demand
second opinion via `explain` only. This is settled; do not propose
LLM-in-the-loop gating.

**Trust model (the central invariant):** `~/.cache/aur-safe/accepted/<pkgbase>`
is the trust anchor — the SHA of the last commit that was *audited AND confirmed
installed*. Seeded from the helper-cache HEAD on first contact, then advanced
only by `accept` after a build pacman confirms. The accepted ref must mean *the
commit we audited, not what got installed*: there's a TOCTOU window between the
gate's fetch and the helper's, resolved by capturing the gate-time tip into
`staged/` and promoting only confirmed installs. Any change that lets the anchor
advance to an unaudited commit reopens the original bug this project was built
to fix — re-check staging discipline on every gate-path change.

Two gate paths, both diff-based:
- **Cached:** helper has a git clone → `git diff accepted..origin/master` → rules.
- **Missing-cache (clone gone):** baseline recovery — clone fresh, find the
  installed version's commit in AUR history, diff that..origin/master. Falls
  back to a whole-file hard-rule scan only if the installed version isn't found.

Both paths share one rule pipeline (`scan_diff_rules`) so they can't drift. See
`REVIEWER-NOTES.md` for the full two-tier model and rule-classification rationale.

## Threat model (why the rules look the way they do)
The 2026 attacker adopts an **orphaned** package via a burner account, pushes an
`.install` hook running `npm install <payload>` (e.g. `atomic-lockfile`,
`crypto-javascript` — they exfiltrate Telegram/browser/SSH data), impersonates
the prior maintainer (same name, swapped email domain), and shifts obfuscation
(hex/octal escapes, `bun`/`pnpm`/`pip`, alternate interpreters). This is why:
- JS package managers (npm/pnpm/bun/yarn) are **hard-fail**; pip/gem/cargo/go
  are **review-only** (legit AUR use is common).
- `.install` hooks + new/modified `.install` files are the primary vector.
- Maintainer + `source=()` domain drift is flagged (the impersonation signal).

The attacker rotates names faster than blacklists track, so the design is
**structural pattern detection, not a payload-name list.** Do not propose adding
names to a blacklist — that loses the race.

## Conventions
- **Comments point to REVIEWER-NOTES** for rationale; code comments are dense
  and reference the doc by section. Keep this coupling.
- **Deliberately-kept shellcheck warnings** — do NOT "fix" these (documented in
  REVIEWER-NOTES): SC2016 (backticks in single-quoted regex are *chars to match*,
  not command-subst — double-quoting executes the string) and SC2001 (`sed`
  indent is clearer than `${var//$'\n'/...}`).
- **`set -uo pipefail` without `set -e`** — the script relies on explicit
  `case $rc` propagation; `-e` fights that pattern.
- **Bash, not Go/Rust/Python.** Security tool — every line must be eyeballable.
  Port only if complexity outgrows readable bash.
- Color funcs (`c_red` etc.) strip escapes on non-TTY; match this in new output.

## Workflow
```sh
bash -n aur-safe          # syntax check
./aur-safe selftest       # the gate — must stay green
shellcheck -s bash aur-safe
```
Live path to exercise: `./aur-safe check <pkg>` (e.g. `ventoy-bin`, a known
missing-cache baseline-recovery case). The wrapper (`aur-safe wrapper`) is not
installed by default.

## Constraints & Red Lines
- **Never put the LLM on the trust path.** `explain` is advisory; deterministic
  rules decide block/warn/allow.
- **Never let the trust anchor advance to an unaudited commit.** Staging/`accept`
  discipline is the TOCTOU fix — see Architecture.
- **Validate external input at boundaries.** Package names go into git URLs and
  flag-file paths; they're regex-validated at entry points. Don't open a new
  entry point without the guard.
- **Don't swallow exceptions.** `grep … || true` is deliberate where grep's exit
  is a signal, not a failure — never blanket-swallow in new code.

## Quality Bar
- **Security tool: code is not done until verified.** `selftest` green + `bash -n`
  clean after every meaningful change. If a change can't be verified, redesign
  until it can.
- **On any change to the gate path** (the cached diff, missing-cache gate, shared
  rule pipeline, staging/accept): re-check the TOCTOU invariant and whether a
  blocked update can still poison the anchor.
- **Search before creating.** Reuse existing functions rather than re-deriving;
  the cached and missing-cache paths share `scan_diff_rules` deliberately.
- **A delegate review pass** (e.g. `glm-5.1`/`kimi-k2.6`/`qwen3.7-max`) on
  trust-path changes has caught two real bugs across two iterations — worth it.
