# aur-safe

Deterministic gate for [Arch Linux AUR](https://aur.archlinux.org/) package
updates. Born during the May–June 2026 AUR supply-chain attack — catches
malicious updates **before** they reach pacman. Deterministic rules are the gate;
an opt-in LLM verifier can only auto-clear narrowly classified boring-edge
diffs. See
[docs/design-ledger.md](./docs/design-ledger.md) for the full design ledger (threat
model, settled decisions, rejected approaches, verification status).

## How it works

yay/paru keep a per-package git clone of the AUR repo (`~/.cache/yay/<pkg>` or
`~/.cache/paru/clone/<pkg>`). `origin/master` is the candidate update.
aur-safe keeps its **own** trust anchor, decoupled from the helper:

```
~/.cache/aur-safe/
  accepted/<pkgbase>   ← last audited+installed commit (trust anchor)
  staged/<pkgbase>     ← gate-time tip, pending build confirmation
  last-gate            ← per-run manifest for accept
```

On update, aur-safe runs **before** yay/paru — it's a shell wrapper, not a
pacman hook (hooks run *after* install — too late).

### Two gate paths

| Path | Condition | Mechanism |
|---|---|---|
| **Cached** | Helper has a git clone | `git diff accepted..origin/master` → rules |
| **Missing-cache** | Clone deleted/absent | Clone fresh, find installed version's commit in AUR history (baseline recovery), diff *that*..origin/master → rules. Falls back to whole-file hard-rule scan if the version isn't found. |

Both paths share the same diff-based rule pipeline (`scan_diff_rules`), so they
can't drift.

### Two rule pipelines

| Pipeline | When used | Rules applied |
|---|---|---|
| **Diff** (`scan_diff_rules`) | Cached path, baseline recovery (tier 1) | Hard-fail + deterministic boring metadata allowlist + boring-edge review/optional verifier + structural review |
| **Whole-file** (`_scan_whole_pkg`) | `audit`, missing-cache fallback (tier 2) | Hard-fail only |

Review rules (pip/gem/cargo/go) can't run on a whole-file scan — they'd fire on
every legit package that uses those tools. Whole-file scans are always review-level
(exit 2, warn), never hard-fail.

### Exit codes

| Code | Meaning | Wrapper action |
|---|---|---|
| 0 | Clean — no rule hits | Proceed |
| 1 | Hard-fail — block | Abort |
| 2 | Review — flagged, consent required | `aur-safe gate` / wrapper prompt: `[l]ist`, `[v]iew` diff, `[e]xplain`, `[y]es`, or `[N]o` (or auto-proceed if `AUR_SAFE_ALLOW_REVIEW=1`); `check` exits 2 for caller handling |
| 3 | Usage/env error | Surface |

## Install

```sh
git clone https://github.com/bermudi/aur-safe ~/build/aur-check
ln -s ~/build/aur-check/aur-safe ~/.local/bin/aur-safe
```

Dependencies: `bash` ≥ 4.3, `git`, an AUR helper (`yay` or `paru`). `pi` is
required only for `explain` and the optional boring-edge verifier.

## Enable

Run `aur-safe wrapper`, paste the `yay()` / `paru()` function into your shell rc
(`~/.bashrc` or `~/.zshrc`), `exec $SHELL`. From then on:

- `yay -Syu` / `paru -Syu` — gated before pacman
- `yay -S <pkg>` / `paru -S <pkg>` — advisory audit for new installs
- Everything else (`-Q`, `-R`, repo `-S`) passes through

```
$ yay -Syu
aur-safe: gating 4 AUR update(s)
▶ cursor-bin  ok
▶ ventoy-bin  ok (baseline recovery)
▶ discord-ptb review — .install hook modified (consent required)
▶ some-pkg    BLOCKED — npm install in .install
```

## Usage

```
aur-safe gate              gate every pending AUR update
aur-safe check <pkg> ...   gate specific cached package(s); exits 2 on review
aur-safe audit <pkg>       advisory scan of an uncached/new package
aur-safe scan              retroactive scan of installed packages
aur-safe explain [pkg]     LLM second-opinion on last flagged diff
aur-safe accept            promote staged refs (called by the wrapper)
aur-safe rules             list active rules
aur-safe wrapper           print the suggested shell wrapper
aur-safe selftest          run built-in rule tests (162/162)
```

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `AUR_SAFE_YAY_CACHE` | `~/.cache/yay` | yay cache directory |
| `AUR_SAFE_PARU_CACHE` | `~/.cache/paru/clone` | paru cache directory |
| `AUR_SAFE_STATE_DIR` | `~/.cache/aur-safe` | State directory (accepted/staged/manifest) |
| `AUR_SAFE_MODEL` | `zai/glm-5.2` | LLM model for `explain` |
| `AUR_SAFE_BRANCH` | `master` | AUR remote branch |
| `AUR_SAFE_AUR_URL` | `https://aur.archlinux.org` | AUR base URL (mirrors, testing) |
| `AUR_SAFE_EXPLAIN_MAXLINES` | `1000` | Diff truncation for `explain` |
| `AUR_SAFE_CONFIG` | `~/.config/aur-safe/config` | Optional config file path |
| `AUR_SAFE_LLM_AUTO_BORING` | `0` | Set `1` to let the strict LLM verifier auto-clear boring-edge diffs |

Optional config file:

```sh
mkdir -p ~/.config/aur-safe
printf 'AUR_SAFE_LLM_AUTO_BORING=1\n' > ~/.config/aur-safe/config
```

Environment variables override the config file. Enabling
`AUR_SAFE_LLM_AUTO_BORING=1` trades deterministic-only gating for convenience on
diffs that deterministic checks already confined to parser-ambiguous metadata,
optional dependency, checksum, or same-host `source=()` changes. It cannot
override hard blocks, review hits, audit-unavailable results, or staging/accept
checks.

Wrapper-level (set in your shell rc):

| Variable | Purpose |
|---|---|
| `AUR_SAFE_ALLOW_REVIEW=1` | Auto-proceed on review flags (non-interactive) |

**Warning:** `AUR_SAFE_ALLOW_REVIEW=1` also auto-proceeds when the gate cannot
audit at all — e.g. AUR clone failure on the missing-cache path (zero signal).
In automation that cannot tolerate a blocked update, this recreates a silent
passthrough hole. Do not set it in unattended scripts unless you accept that
tradeoff.

## Status

Single-user, single-machine. Hardened through multiple independent reviews (see
commit history and `docs/findings/`). A 2026-06-26 red-team review by three
delegate models found 23 findings — see [BACKLOG.md](./BACKLOG.md) for the
prioritized task list. The trust anchor is aur-safe's own
accepted-ref state, seeded from the helper HEAD on first contact and advanced
only after a gate-audited build that pacman confirms installed. Selftest: 162/162.

Licensed under the [MIT License](./LICENSE).

## Docs

- [docs/design-ledger.md](./docs/design-ledger.md) — canonical design ledger (threat model,
  architecture, settled decisions, rejected approaches, verification)
- [docs/threat-model.md](./docs/threat-model.md) — attacker profile, defensive
  principles, rule classification
- [docs/findings/](./docs/findings/) — 18 documented security findings (A–R:
  A/B/C closed, D deferred, E–R open from 2026-06-26 red-team review)
- [BACKLOG.md](./BACKLOG.md) — prioritized task list from 2026-06-26 review
