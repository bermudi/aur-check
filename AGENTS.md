# AGENTS.md

## Project
`aur-safe` — a deterministic gate for Arch Linux AUR package updates, run as a
shell wrapper around `yay`/`paru`. Single-user, single-machine, not distributed.
Born during the May–June 2026 AUR supply-chain attack; its entire reason for
existing is to stop malicious AUR updates from reaching pacman.

**Read these before touching the trust path:**
- [docs/design-ledger.md](./docs/design-ledger.md) — canonical design ledger (threat
  model, settled decisions, rejected approaches, verification status)
- [docs/threat-model.md](./docs/threat-model.md) — attacker profile, defensive
  design principles, rule classification
- [docs/findings/](./docs/findings/) — documented findings and implementation
  assessments from reviews A–S; consult each status rather than stale line numbers
- [BACKLOG.md](./BACKLOG.md) — prioritized task list with fix order, effort,
  and status tracking (all 23 findings from the 2026-06-26 review)

## Stack
Bash 5.3, git, `flock` (util-linux), an AUR helper (`yay` or `paru`). `pi` only
for the advisory `explain` subcommand and the optional boring-edge verifier. No
build system. Single-file script (`aur-safe`); runtime state under
`~/.cache/aur-safe/`.

## Architecture

### Trust model (the central invariant)
`~/.cache/aur-safe/accepted/<pkgbase>` is the trust anchor — the SHA of the last
commit that was *audited AND confirmed installed*. First contact requires
whole-candidate review; the anchor is created/advanced only by `accept` after a
fresh guarded build pacman confirms. The accepted ref must mean *the commit we
audited, not what got installed*: staging resolves **anchor advancement** across the gate/helper
fetch window. The generated wrapper also injects the Finding-S makepkg guard,
which requires helper checkout HEAD to equal the staged SHA and a fresh build
immediately before PKGBUILD execution. **Any change that lets the anchor advance to an
unaudited commit reopens the original bug** — re-check staging discipline on
every gate-path change.

### Two gate paths (both diff-based)
- **Cached:** helper has a git clone → `git diff accepted..origin/master` → rules.
- **Missing-cache (clone gone):** baseline recovery — clone fresh, find the
  installed version's commit in retained AUR history, diff that..origin/master,
  then require review with whole-candidate context even if the reconstructed
  diff is clean. Falls back to the same mandatory whole-file review if absent.

### Two rule pipelines (not one)
- **Diff pipeline** (`scan_diff_rules`): hard + deterministic boring metadata
  allowlist + boring-edge review/optional verifier + structural rules. Shared by
  the cached path and the baseline-recovery tier, so they can't drift.
- **Whole-file pipeline** (`_scan_whole_pkg`): hard + review rules. `audit` is
  advisory; the baseline-less missing-cache tier always requires review even
  with no regex hit. Shared implementation, caller-specific policy.

There is also a **third ad-hoc pipeline** in `cmd_scan` (retroactive scan of
installed packages) — documented as [Finding B](./docs/findings/B-cmd-scan-adhoc-pipeline.md).

## Conventions
- **Comments point to design-ledger** for rationale; code comments are dense
  and reference the doc by section. Keep this coupling.
- **Deliberately-kept shellcheck warnings** — do NOT "fix" these (documented in
 design-ledger): SC2016 (backticks in single-quoted regex are *chars to match*,
 not command-subst — double-quoting executes the string) and SC2001 (`sed`
 indent is clearer than `${var//$'\n'/...}`). Excluded via `.shellcheckrc` so
 `shellcheck -s bash aur-safe` exits clean in CI.
- **`set -uo pipefail` without `set -e`** — the script relies on explicit
  `case $rc` propagation; `-e` fights that pattern.
- **Bash, not Go/Rust/Python.** Security tool — every line must be eyeballable.
  Port only if complexity outgrows readable bash.
- Color funcs (`c_red` etc.) strip escapes on non-TTY; match this in new output.
- **Security tool** No if or buts, anything that smells like an issue needs to
  be fixed right away.

## Workflow
```sh
bash -n aur-safe          # syntax check
./aur-safe selftest       # the gate — every reported case must stay green
shellcheck -s bash aur-safe  # SC2016/SC2001 excluded via .shellcheckrc
```
Live path to exercise: `./aur-safe check <pkg>` (e.g. `ventoy-bin`, a known
missing-cache baseline-recovery case). The wrapper (`aur-safe wrapper`) is not
installed by default.

## Constraints & Red Lines
- **Never let the LLM override deterministic risk.** `explain` is advisory; the
  optional verifier can only auto-clear deterministic `boring_edge` diffs, never
  hard/review/audit-unavailable results.
- **Never let the trust anchor advance to an unaudited commit.** Staging/`accept`
  discipline is the TOCTOU fix — see Architecture.
- **Validate external input at boundaries.** Package names go into git URLs and
  flag-file paths; they're regex-validated at entry points. Don't open a new
  entry point without the guard.
- **Don't swallow exceptions.** `grep … || true` is deliberate where grep's exit
  is a signal, not a failure — never blanket-swallow in new code.
- **Don't add names to blacklists.** The design is structural pattern detection;
  the attacker rotates names faster than lists track. See
  [threat model](./docs/threat-model.md).
- **`git init` defaults to `main`, not `master`.** Any new fixture or clone
  logic assuming `master` will silently fail (empty `origin/master`). Always
  force `-c init.defaultBranch=master`.

## Known vulnerability classes (2026-06-26 red-team review)

Findings E–R have implemented fixes/mitigations as recorded in
[BACKLOG.md](./BACKLOG.md) and [docs/findings/](./docs/findings/). Load-bearing
regressions to keep pinned: non-ASCII source URLs never become boring; tier-2
never exits clean; installed confirmation binds to root-owned pacman pkgbase +
freshness records; git output is config-isolated and failure-checked; and the
generated wrapper locks the full gate → helper → accept transaction and
injects exact staged-SHA plus fresh-artifact enforcement at the makepkg seam.

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
