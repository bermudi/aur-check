# Threat Model

The canonical design ledger is [REVIEWER-NOTES.md](../REVIEWER-NOTES.md). This
document is a focused extraction of the threat model — what we're defending
against and why the rules look the way they do.

## Attacker profile

The May–June 2026 AUR supply-chain attacker:

1. **Creates a burner account** (single-package, throwaway email) on the AUR.
2. **Adopts an orphaned package** (automatic adoption, no review required).
3. **Pushes a commit adding/modifying an `.install` hook** that runs
   `npm install <payload-package>` — payloads observed: `atomic-lockfile`,
   `crypto-javascript`, `lockfile-js`, `nextfile-js`, `js-digest`. The npm
   package ships a binary blob that exfiltrates data (Telegram `tdata`,
   browser directories, SSH keys).
4. **Impersonates the prior maintainer** — keeps the name, swaps the email
   domain — so the diff looks benign at a glance.
5. **Shifts obfuscation** across iterations: hex/octal shell escapes, `bun add`
   / `pip install` instead of `npm`, alternate interpreters for `| sh`.

The attacker rotates package names and installers faster than blacklists can
track. Static name lists are a losing race.

## Defensive design principles

### Structural pattern detection, not blacklists

The attacker rotates names faster than blacklists can track, so aur-safe
detects *structural patterns* rather than payload names:

- **JS package managers** (npm/pnpm/bun/yarn) are **hard-fail** — they are the
  primary campaign vector and have no legitimate use in an `.install` hook.
- **Other package managers** (pip/gem/cargo/go) are **review-only** — they have
  legitimate use in real AUR packages (Python/Ruby/Rust tooling).
- **Hex/octal escape runs** (2+ adjacent) are hard-fail — they spell out hidden
  strings. Single escapes are review-only (could be ANSI color codes).
- **Pipe-to-interpreter** (`curl … | sh`) and **eval-of-substitution**
  (`eval $(...)`) are hard-fail — they execute arbitrary fetched content.
- **Maintainer and `source=()` domain drift** is flagged (review) — this catches
  the impersonation signal without blocking legitimate version bumps.

### The LLM is never on the trust path

The gate is deterministic regex rules. The LLM (`explain` subcommand) is an
on-demand second opinion on *already-flagged* diffs — advisory only. This is
settled; do not propose LLM-in-the-loop gating.

### The trust anchor is decoupled from the helper

`~/.cache/aur-safe/accepted/<pkgbase>` is aur-safe's own trust anchor, not the
helper's HEAD. It means *the commit we audited, not what got installed* — a
TOCTOU window between the gate's fetch and the helper's is resolved by staging
(`staged/`) and promoting only on version-confirmed install (`accept`). Any
change that lets the anchor advance to an unaudited commit reopens the original
bug this project was built to fix.

## Why not a pacman hook

Pacman hooks run *after* install — by then the malicious `.install` has already
executed. Interception must happen before makepkg/pacman, hence the shell
wrapper around yay/paru.

## Rule classification rationale

| Class | Examples | Gate behavior |
|---|---|---|
| **Hard-fail** | npm/pnpm/bun/yarn, pipe-to-interpreter, eval-subst, base64-decode, escape runs (2+) | Block (exit 1) |
| **Review** | pip/gem/cargo/go, single hex/octal escape, maintainer/source drift, python-inline-net | Warn (exit 2) |

The asymmetry (JS package managers → hard-fail, others → review) is intentional:
the observed campaign uses JS package managers; Python/Ruby/Rust/Go legitimate
use is more common in real AUR packages. This is a judgment call documented as a
genuinely contestable decision in REVIEWER-NOTES.md.

## Primary vector: `.install` hooks

The campaign's payload rides in `.install` hooks running `npm install <bad>`.
aur-safe hard-fails on:

- **New or modified `.install` files** (`install-hook-ref`, `install-hook-func`)
  — any reference to a `.install` file, or any `post_install`/`pre_install`/
  `post_upgrade`/`pre_remove`/`post_remove` shell function definition.

These rules are the primary defense. Everything else (package managers, escapes,
network) defends against payloads that avoid the `.install` mechanism.

## Obfuscation arms race

The attacker iterates on evasion. aur-safe counters with structural patterns
that don't depend on specific obfuscation tricks:

- **Hex/octal escape runs** — two adjacent `\xNN` or `\NNN` sequences spell
  hidden strings. Single escapes are review-only (ANSI color codes are `\x1b`,
  `\033`). No whitelist of "safe" escape codes — a name-list whitelist is
  itself an evasion surface (attacker sprinkles `\x1b` decoys, hides real
  payload in the middle).
- **Alternate interpreters** — `| python`, `| node`, `| ruby`, `| perl` in
  addition to `| sh`/`| bash`.
- **Alternate package managers** — `bun add`, `pnpm install`, `yarn add` in
  addition to `npm install`.
