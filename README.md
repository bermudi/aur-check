# aur-safe

Deterministic gate for [Arch Linux AUR](https://aur.archlinux.org/) package
updates. Born during the May–June 2026 AUR supply-chain attack — see
[REVIEWER-NOTES.md](./REVIEWER-NOTES.md) for the threat model and design
rationale.

## What it does

Catches malicious AUR updates **before** they reach pacman, using deterministic
regex rules — no LLM on the trust path. The LLM (`zai/glm-5.2` via `pi`) is only
invoked on-demand via `explain` for a second opinion on already-flagged diffs.

```
yay/paru cache (~/.cache/yay/<pkg>) is a git clone
  └─ origin/master = candidate update

aur-safe keeps its OWN trust anchor, decoupled from the helper's HEAD:
  ~/.cache/aur-safe/accepted/<pkgbase> = last audited+installed commit
       │
       ▼
  git diff accepted..origin/master  ──►  deterministic rules (15 hard, 7 review)
       │                                   │
       │                            hard-fail ──► exit 1, block
       │                            review    ──► exit 2, warn
       │                            clean     ──► stage the audited tip
       └─ after a successful build, `aur-safe accept` advances the anchor
            (only if pacman confirms the package installed at that version)
```

## Install

```sh
git clone <repo> ~/build/aur-check
ln -s ~/build/aur-check/aur-safe ~/.local/bin/aur-safe
```

Dependencies: `bash`, `git`, and an AUR helper (`yay` or `paru`). `pi` is
required only for the `explain` subcommand.

## Usage

```
aur-safe gate              gate every pending AUR update
aur-safe check <pkg> ...   gate specific cached package(s)
aur-safe audit <pkg>       advisory scan of an uncached/new package
aur-safe scan              retroactive scan of installed packages
aur-safe explain [pkg]     LLM second-opinion on last flagged diff
aur-safe accept            promote staged refs (called by the wrapper)
aur-safe rules             list active rules
aur-safe wrapper           print the suggested shell wrapper (not installed)
aur-safe selftest          run built-in rule tests
```

## Enable

Run `aur-safe wrapper`, paste the `yay()` function into your shell rc,
`exec $SHELL`. From then on `yay -Syu` gates every AUR update; new installs get
an advisory audit first.

## Status

Single-user, single-machine. Hardened through multiple independent reviews.
The trust anchor is aur-safe's own accepted-ref state
(`~/.cache/aur-safe/accepted/<pkgbase>`), seeded from the helper HEAD on first
contact and advanced only after a gate-audited build that pacman confirms
installed — so a manipulated or stale helper-cache HEAD can no longer produce
an empty diff that prints clean. See `REVIEWER-NOTES.md`.
