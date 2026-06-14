# aur-safe — morning notes

Built last night, hardened this morning per the consolidated expert review.
**Not wired up** — ready for you to enable when you're happy.

## What it is
Deterministic gate for AUR updates. yay/paru keep a per-package git clone; HEAD
= last build (known-good), origin/master = candidate. We diff the two and run
rules against ADDED lines. No LLM on the trust path; the model only runs
on-demand via `explain`.

## Where it lives
- Script: `~/.local/bin/aur-safe` (executable, on PATH, 607 lines)
- State:  `~/.cache/aur-safe/` (flagged diffs; auto-GC'd after 30 days)
- Model:  `zai/glm-5.2` via `pi` (reuses existing auth)

## Verified
- `selftest`: 26/26 (incl. all new evasion vectors + FP mitigations)
- `gate` on your 3 real updates: all clean, exit 0
- Synthetic attack with full evasion toolkit (function-syntax hook, python/perl
  pipes, process substitution, backtick eval, hex-obfuscation run, impersonation,
  committed payload archive): **7 hard rules fired, exit 1**
- Stealth scenario (modified existing hook + impersonation + committed binary,
  no hard payloads): **3 review rules fired, exit 2** (non-blocking)
- paru cache resolution confirmed (found pkg in `~/.cache/paru/clone/`)
- `explain` truncation guard works (5000-line diff → 50 lines to LLM)
- `scan` of installed packages: clean

## Commands
```
aur-safe gate              gate every pending AUR update (precedes yay/paru -Syu)
aur-safe check <pkg> ...   gate specific cached package(s)
aur-safe audit <pkg>       advisory scan of a new/uncached package (PKGBUILD+.install+.sh)
aur-safe scan              retroactive scan of installed packages
aur-safe explain [pkg]     LLM second-opinion on the last flagged diff
aur-safe rules             list active rules
aur-safe wrapper           print the shell wrapper (NOT installed)
aur-safe selftest          run the rule tests
```

## To enable (when ready)
Run `aur-safe wrapper`, paste the `yay()` function into your shell rc,
`exec $SHELL`. Gates `-Syu`/`-Sy`/`-Su`; advisory-audits new `-S <pkg>` (parses
flags correctly now — `yay -S pkg --noconfirm` audits `pkg`, not `--noconfirm`).

## Rules (12 hard-fail, 7 review, + 3 structural)
Hard (block): install-hook-ref, install-hook-func (incl. `function` kwd +
no-parens syntax), npm, npx, pnpm, bun, yarn, pipe-to-interpreter (→
sh/python/node/ruby/perl…), proc-subst-net, eval-subst, backtick-net,
base64-decode, hex-escape-run (2+ adjacent), octal-escape-run, new-install-file.

Review (warn): hex/octal single escape (ANSI-safe), pip, gem, cargo/go-install,
python/perl inline-net, modified-install-file, new-binary-file,
maintainer-domain-new, source-domain-new.

## What the review got right / what I changed / what I rejected
Applied as-is: wrapper arg-parse bug, awk --name-only fix, `function`/no-parens
hook syntax, alternate-interpreter pipes, backtick eval, email-regex rigidity,
.patch/.diff exclusion, paru support, LLM truncation, state GC, pi doc.

Modified: hex/octal — single→review, run-of-2+→hard (their ANSI-whitelist idea
is itself an evasion vector); audit scope — PKGBUILD+.install+.sh not "all text
files" (that causes the alert fatigue §4 warns about).

Rejected: `${arr[@]+"${arr[@]}"}` cargo-cult on statically-populated rule arrays
(guarded the wrapper's `_pkgs` array where emptiness is real).

Added beyond the review: process-substitution evasion (`sh <(curl…)`), standalone
backtick-network (`\`curl…\``), committed-binary-file review, modified-.install
structural review.

## Known limitations
- New installs (`-S foo`) are advisory-audited, not gated (scope was "every AUR
  *update*" = cached packages, which ARE gated).
- Domain-drift checks need a prior commit in cache.
- Wiping `~/.cache/yay` + `~/.cache/paru/clone` loses the baseline until next build.
