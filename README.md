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
  ├─ HEAD          = last version you built (known-good baseline)
  └─ origin/master = candidate update
       │
       ▼
  git diff HEAD..origin/master  ──►  deterministic rules (15 hard, 7 review)
       │                                   │
       │                            hard-fail ──► exit 1, block
       │                            review    ──► exit 2, warn
       └─ on-demand: aur-safe explain ──► LLM second opinion
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
aur-safe rules             list active rules
aur-safe wrapper           print the suggested shell wrapper (not installed)
aur-safe selftest          run built-in rule tests
```

## Enable

Run `aur-safe wrapper`, paste the `yay()` function into your shell rc,
`exec $SHELL`. From then on `yay -Syu` gates every AUR update; new installs get
an advisory audit first.

## Status

Single-user, single-machine. Hardened through multiple independent reviews; the
known gap is the trust-anchor assumption (HEAD = known-good), tracked for a
future accepted-ref state redesign. See `REVIEWER-NOTES.md` → "Genuinely
contested" and "Deferred."
