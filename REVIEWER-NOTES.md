# aur-safe — reviewer context

`aur-safe` is a deterministic gate for Arch Linux AUR package updates. This file
exists so reviewers give useful feedback instead of re-litigating decisions
that were deliberate. **Read this before reviewing the script.**

## What problem it solves (threat model)

An active, evolving supply-chain attack on the AUR (May–June 2026, still
ongoing). The attacker's MO:

1. Creates a burner account (single-package, throwaway email).
2. Adopts an **orphaned** AUR package (automatic adoption, no review).
3. Pushes a commit that adds/edits an `.install` hook running
   `npm install <payload-package>` — currently `atomic-lockfile`,
   `crypto-javascript`, `lockfile-js`, `nextfile-js`, `js-digest`. The npm
   package ships a binary blob that exfiltrates data (Telegram `tdata`,
   browser dirs, SSH keys).
4. **Impersonates the prior maintainer** — keeps the name, swaps the email
   domain — so the diff looks benign at a glance.
5. Obfuscation is shifting: hex/octal shell escapes, `bun add`/`pip install`
   instead of `npm`, alternate interpreters for `| sh`.

The attacker rotates package names and installers faster than blacklists can
track. Static name lists are already a losing race.

## Architecture (settled — don't propose alternatives unless you see a real flaw)

**Deterministic rules are the gate. The LLM is never on the trust path.**

- yay/paru keep a per-package git clone (`~/.cache/yay/<pkg>` or
  `~/.cache/paru/clone/<pkg>`). Checked-out `HEAD` = last version you built
  (treated as known-good). `origin/master` = candidate.
- On update: `git fetch`, diff `HEAD..origin/master`, run regex rules against
  ADDED lines only.
- Hard-fail rules → exit 1, block the update.
- Review-only rules → exit 2, warn but don't block.
- `explain` subcommand pipes a *flagged* diff to an LLM (`zai/glm-5.2` via
  `pi`, reusing existing auth) for a second opinion. Advisory only.

**Why not LLM-in-the-loop as the gate:** the attacker is using obfuscated bash
(hex/octal escapes). LLMs handle obfuscated bash inconsistently — false
negatives on the real attack, false positives on legit updates. The
deterministic gate catches the observed vectors reliably; the LLM is better as
an on-demand explainer of *flagged* diffs than as a trust boundary. This was
debated extensively and settled.

**Why not a pacman hook:** pacman hooks run *after* install — by then the
malicious `.install` has already executed. Interception must happen before
makepkg/pacman, hence the shell wrapper around yay/paru.

## Decisions that look arbitrary but aren't

### `set -uo pipefail` without `set -e`
The script does many `grep ... || true` and explicit exit-code propagation
(`case $rc in 1) ...`). `set -e` would fight that pattern. Pipefail catches
the real dangers (silent grep failures in pipelines); `-e` would add noise.

### Single hex/octal escape → review; run of 2+ → hard-fail
The obvious "fix" is an ANSI-color-code whitelist (`\x1b`, `\033`). **Don't
propose this** — a name-list whitelist is itself an evasion surface. An
attacker sprinkles `\x1b` decoys to look legit, then hides the real payload
in the middle. The run-based heuristic is structural: obfuscation spells out
strings as *runs* of escapes; color codes are isolated. Cleaner distinction,
no maintainable list to poison.

### `audit` scans `PKGBUILD` + `*.install` + `*.sh`, not "all text files"
Scanning READMEs and LICENSEs would trip every rule (they legitimately
contain example shell snippets, escape sequences in docs). That's the alert
fatigue that defeats the whole tool. The sourced-script surface is the actual
attack surface.

### `${arr[@]+"${arr[@]}"}` is NOT used on the rule arrays
The `RULE_NAMES`/`RULE_PATTERNS` arrays are statically populated at the top of
the script — never empty, never unset. The `set -u` guard is cargo cult on
bash 5 for arrays that provably cannot be empty. **It IS used in the wrapper's
`_pkgs` array**, where emptiness is a real runtime possibility. Don't suggest
applying it uniformly.

### `git fetch` failure → warn and continue, not fail-closed
If fetch fails (offline, AUR down), we diff against whatever `origin/master`
is locally cached — which is the last successful fetch, still a valid
known-good baseline. Failing closed would block all updates during routine
network blips, training users to ignore warnings.

### `comm -13` set-diff for domain drift, not regex
A version bump on the *same* domain (kernel.org → kernel.org) must NOT fire.
Only NEW domains should. A regex can't express "set membership" cleanly;
`comm -13` does. Same logic for `source=()` host drift.

### `.patch` / `.diff` excluded from diff scanning
Legitimate C/C++ patches contain hex/octal escapes and `eval`-like patterns.
Including them would false-positive on most C/C++ AUR packages.

### Exit codes: 0 clean | 1 hard-fail | 2 review | 3 usage/env
Maps cleanly to wrapper semantics: 0 → proceed, 1 → abort, 2 → proceed with
consent, 3 → surface error. More granular codes would just need re-mapping
at the wrapper layer.

### Written in bash, not Go
It's a security tool; every line should be eyeballable by the user. The logic
is git + grep + exec, all safe and idiomatic in bash. Port to Go if it grows
complexity beyond what bash reads cleanly.

### Backticks in single-quoted regex/test strings (shellcheck SC2016)
The backticks are *characters to match*, not command substitution. Switching
to double quotes (as shellcheck suggests) would make bash execute
`` `curl -s http://x` `` during the self-test. Single quotes are mandatory
here. SC2016 is correct about the mechanics, wrong about the implication.

### `sed 's/^/  /'` for indenting output (shellcheck SC2001)
For prefixing every line of a multi-line string, `sed` is more readable than
the `${var//$'\n'/...}` equivalent. The subprocess-perf argument is irrelevant
outside a hot loop, and this isn't one.

## Genuinely contestable — feedback wanted here

These are real open questions where I'd value pushback:

1. **Hard-fail vs review classification.** Currently `npm`/`pnpm`/`bun`/`yarn`
   in a PKGBUILD diff are hard-fails; `pip`/`gem`/`cargo`/`go install` are
   review-only. The asymmetry is intentional (the observed campaign uses JS
   package managers; Python/Ruby/etc. legit use is more common in AUR), but
   the line is a judgment call. Is it drawn in the right place?

2. **Hex/octal run threshold = 2+.** Somewhat arbitrary. 2 catches
   `\x6e\x70` (two chars) but also `\x1b\x5d` (legit OSC sequences in some
   terminal scripts). 3+ would reduce FPs but miss short obfuscated strings.
   Is 2 right?

3. **New installs (`yay -S foo`) are advisory, not gating.** No baseline to
   diff against, so only absolute rules apply — and blocking on "any npm call
   in a PKGBUILD" would block legit node-related AUR packages. Currently
   prints findings and proceeds. Should it gate instead?

4. **Wrapper doesn't define a `paru` function.** It only shadows `yay`.
   `paru` users would need to copy-paste and rename. Worth auto-detecting
   which helper is in use and defining the right function?

5. **The `scan` subcommand's pattern list is hardcoded.** It checks installed
   packages for a fixed set of payload names (`atomic-lockfile`,
   `crypto-javascript`, etc.). This is the blacklist approach the main gate
   deliberately avoids. Justified for retroactive triage (you want to catch
   known-bad names that already landed), or should it reuse the main rule
   engine?

## What I don't need feedback on

- "Why not just use an LLM?" — see Architecture. Settled.
- "Why bash not Go/Rust/Python?" — see Decisions. Settled for v1.
- Style nits that shellcheck already flagged and I deliberately kept
  (SC2016, SC2001). See Decisions.
- Suggestions to add more package names to a blacklist. The whole point is
  that blacklists lose.

## Verification status (so you don't re-verify what's already proven)

- `selftest`: 26/26 rules pass, incl. all evasion vectors and FP mitigations
- Real AUR updates (3 pending): clean, exit 0, no regression
- Synthetic full-evasion attack: 7 hard rules fire, exit 1
- Stealth scenario (impersonation + modified hook + committed binary, no
  payloads): 3 review rules fire, exit 2
- `explain` → LLM path confirmed working with glm-5.2
- paru cache resolution confirmed
- Not wired up — lives at `~/.local/bin/aur-safe`, enabled via shell wrapper
