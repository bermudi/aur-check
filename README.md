# aur-safe

Deterministic gate for [Arch Linux AUR](https://aur.archlinux.org/) package
updates. Born during the May–June 2026 AUR supply-chain attack — catches
malicious updates **before** they reach pacman. The LLM is advisory only;
deterministic regex rules are the gate. See
[REVIEWER-NOTES.md](./REVIEWER-NOTES.md) for the full design ledger (threat
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
| **Diff** (`scan_diff_rules`) | Cached path, baseline recovery (tier 1) | Hard-fail + review + structural |
| **Whole-file** (`_scan_whole_pkg`) | `audit`, missing-cache fallback (tier 2) | Hard-fail only |

Review rules (pip/gem/cargo/go) can't run on a whole-file scan — they'd fire on
every legit package that uses those tools. Whole-file scans are always review-level
(exit 2, warn), never hard-fail.

### Exit codes

| Code | Meaning | Wrapper action |
|---|---|---|
| 0 | Clean — no rule hits | Proceed |
| 1 | Hard-fail — block | Abort |
| 2 | Review — flagged, consent required | Prompt (or auto-proceed if `AUR_SAFE_ALLOW_REVIEW=1`) |
| 3 | Usage/env error | Surface |

## Install

```sh
git clone https://github.com/bermudi/aur-safe ~/build/aur-check
ln -s ~/build/aur-check/aur-safe ~/.local/bin/aur-safe
```

Dependencies: `bash` ≥ 5.0, `git`, an AUR helper (`yay` or `paru`). `pi` is
required only for the `explain` subcommand.

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
aur-safe check <pkg> ...   gate specific cached package(s)
aur-safe audit <pkg>       advisory scan of an uncached/new package
aur-safe scan              retroactive scan of installed packages
aur-safe explain [pkg]     LLM second-opinion on last flagged diff
aur-safe accept            promote staged refs (called by the wrapper)
aur-safe rules             list active rules
aur-safe wrapper           print the suggested shell wrapper
aur-safe selftest          run built-in rule tests (87/87)
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

Wrapper-level (set in your shell rc):

| Variable | Purpose |
|---|---|
| `AUR_SAFE_ALLOW_REVIEW=1` | Auto-proceed on review flags (non-interactive) |

## Status

Single-user, single-machine. Hardened through multiple independent reviews (see
commit history and `docs/findings/`). The trust anchor is aur-safe's own
accepted-ref state, seeded from the helper HEAD on first contact and advanced
only after a gate-audited build that pacman confirms installed. Selftest: 87/87.

## Docs

- [REVIEWER-NOTES.md](./REVIEWER-NOTES.md) — canonical design ledger (threat model,
  architecture, settled decisions, rejected approaches, verification)
- [docs/threat-model.md](./docs/threat-model.md) — attacker profile, defensive
  principles, rule classification
- [docs/findings/](./docs/findings/) — deferred security findings (pending
  fixes, documented for visibility)
