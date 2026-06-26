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

### Accepted-ref state (finding 1.2) — the trust-anchor fix

**Problem:** `check_pkg` used to diff `HEAD..origin/master`, trusting the
helper-cache HEAD as known-good. But HEAD can advance past the known-good state
(aborted build, manual `git pull` in the cache, helper restart) → an empty diff
prints clean while a malicious update lands.

**Design (staging + post-build accept):**
- `accepted/<pkgbase>` = `<sha>\t<iso-utc>\t<origin-url>`. Seeded from cache HEAD
  on first contact, then frozen.
- On a clean or review-only audit, `check_pkg` writes the **gate-time**
  `origin/master` tip to `staged/<pkgbase>` (NOT on empty-diff / hard-fail /
  skip paths) and appends `pkgbase` to a per-run manifest (`last-gate`).
- The wrapper captures the helper's exit code, runs the build, then calls
  `aur-safe accept`. `accept` promotes `staged → accepted` **only for manifest
  entries pacman confirms installed at the staged version**.

**Why staging (not deferred acceptance or post-build bump):** the accepted ref
must mean *the commit we audited*, not *what got installed*. There's a TOCTOU
window between `check_pkg`'s fetch and the helper's own fetch. Capturing the
gate-time tip (X) means a window-commit X′ lands installed-but-not-accepted;
the next gate diffs X..origin/master, surfaces X′ as fresh delta, audits it.
Deferred acceptance (match installed pkgver vs `.SRCINFO`) was rejected: needs a
new parser and pkgver can stay identical across a malicious push.

**Install-confirmation assertion (closes the untested `-Syu` partial-failure
case):** `accept` compares the installed version (`pacman -Q`) against the
staged commit's `.SRCINFO` pkgver/pkgrel/epoch — ANY matching pkgname counts
(for split packages). The `.SRCINFO` format (verified against makepkg source +
real cached files): `pkgbase=` and `pkgname=` are section headers at column 0
(no leading tab); attributes are tab-indented; a blank line separates sections.
makepkg always emits `pkgname=` (one per sub-package, even for non-split where
it equals pkgbase). A defensive `pkgbase=` fallback covers malformed files
missing `pkgname=`:

```
names=$(awk -F' = ' '/^[[:space:]]*pkgname =/ {print $2}' <<<"$srcinfo")
  [[ -n "$names" ]] || names=$(awk -F' = ' '/^[[:space:]]*pkgbase =/ {print $2; exit}' <<<"$srcinfo")
```
Note the `^[[:space:]]*` (not `^\t`): well-formed files indent attributes with
a single tab, but some real AUR packages ship **space-indented** `.SRCINFO`
(e.g. `opera-developer` uses 8 spaces). A tab-anchored regex silently extracts
nothing on those files, so the install check never matches and the anchor never
advances. The column-0 section headers (`pkgbase=`/`pkgname=`) stay anchored —
they are never indented in practice. A package that didn't build/install won't
match → its anchor is left unchanged → next gate re-audits. This means `accept`
is safe to run on **any** helper exit code.

**Verified (sandboxed, isolated root/dbpath/cachedir):** both `yay` v12.6.0 and
`paru` v2.1.0 exit non-zero on ANY build failure (`exit status 4` from makepkg
propagates), `--noconfirm` included, ordering-independent — the good packages
install, the failing one is blocked. **Source-confirmed via deepwiki:** yay
(`Jguer/yay`, `main.go`) mirrors makepkg's `exec.ExitError` or defaults to 1,
`--noconfirm` is orthogonal, no swallow path; paru (`Morganamilo/paru`,
`--failfast` v1.11.0+) returns non-zero if any package fails to build (continues
others, but non-zero), no swallow path. So `rc==0 → accept` alone is safe;
install-confirmation is kept as defense-in-depth against untested code paths or
future helper changes. A sandboxed `-Syu` was not run (only `-Bi`), but the
exit-code semantics are now source-grounded rather than inferred for both
gated helpers.

**Review debate (deepseek-v4-pro/xhigh):** 6 findings raised. Conceded: (2)
review-consent must also stage [fixed — stage before `return 2`]; (3) no staged
GC [fixed — `gc_state` sweeps `staged/` at +7d, `accepted/` never swept]; (5)
empty-diff staging is a no-op [fixed — stage only on non-empty clean/review];
(6) bare SHA lacks provenance [fixed — `sha\tts\turl`]. Disputed finding (1)
"`--all-staged` promotes unbuilt commits" was rated CRITICAL but its premise
("yay can exit 0 on partial") is disproven by the test above; demoted to
non-issue. `--all-staged` was dropped entirely in favor of a per-run manifest
(cross-run isolation) + install-confirmation (intra-run). Finding (4) agreed
the TOCTOU argument validates staging over deferred.

### `comm -13` set-diff for domain drift, not regex
A version bump on the *same* domain (kernel.org → kernel.org) must NOT fire.
Only NEW domains should. A regex can't express "set membership" cleanly;
`comm -13` does. Same logic for `source=()` host drift.

### `.patch` / `.diff` excluded from diff scanning
Legitimate C/C++ patches contain hex/octal escapes and `eval`-like patterns.
Including them would false-positive on most C/C++ AUR packages.

### Missing-cache path: baseline recovery + whole-file fallback
A package in `yay -Qua` whose cache clone is gone (manual `rm`, `yay -Sc`,
corruption, new machine) has no `origin/master` to diff and no accepted ref to
diff against. The entire gate is a `git diff accepted..origin/master`, so v1
`return 0`'d with a dim "skip" — a malicious update sailed through **ungated**
while the gate still printed `✓ all clear`. This is strictly weaker than the
new-install path (`audit`), which at least runs the absolute rules. `check_pkg`
now routes this case to `missing_cache_gate`, a **two-tier** gate:

**Tier 1 — baseline recovery (preferred).** Fresh-clone the AUR repo, then walk
`origin/<branch>` history to find the commit whose `.SRCINFO` matches the
**installed** version (`find_baseline_commit`), and diff
`installed-commit..origin/master` through the SAME `scan_diff_rules` pipeline the
cached path uses (hard + review + structural checks). Exit codes mirror the
cached path: hard hit → 1 (block), review hit → 2, clean → 0. This eliminates
the whole-file false positives that motivated review-only-on-missing-cache: a
pre-existing legit `.install` hook (ventoy-bin's `post_install`) is NOT in the
delta, so only a newly-added hook (the campaign vector) is flagged.

**Tier 2 — whole-file fallback.** If the installed version isn't found in AUR
history (or can't be queried), clone + hard-rules-only absolute scan of
PKGBUILD/`.install`/`.sh` at **review level**: hard hit → 2 (consent), clean →
0. This is the old `scan_clone` behavior, preserved for the no-match case. Clone
failure → 2 (zero signal — surface for consent, never silently pass). The clone
URL is overridable via `AUR_SAFE_AUR_URL` (mirrors + selftest without network).

**`find_baseline_commit` mechanism & policy.** It reads every commit's `.SRCINFO`
in one `git cat-file --batch` pass (~80 ms for an 858-commit repo; per-commit
`git show` is ~25× slower). The batch stream echoes the *blob's* sha in its
header, not the commit's, so the commit↔`.SRCINFO` association is restored by
passing the oldest-first commit list into awk and mapping by block index. It
returns the **OLDEST** matching commit: if several commits share the installed
pkgver (e.g. a malicious push keeping pkgver identical), the oldest match
maximizes diff coverage and surfaces any intervening commit. Conservative by
design — it may over-report on a benign re-commit at the same version, never
under-report. Whitespace-tolerant version extraction mirrors `_installed_matches`
(some packages ship space-indented `.SRCINFO`, e.g. opera-developer).

**Why tier-2 is review (2), not hard-fail (1):** a whole-file scan has no
baseline, so the `install-hook-*` rules fire on any pre-existing legit `.install`
(ventoy-bin, vscode-bin, …). Hard-failing would block routine updates of common
packages. (Tier 1's diff has none of these FPs, so it CAN hard-fail — and does.)
Why not advisory (0) like `audit`: `audit` gates a deliberate *new* install the
user just typed; an uncached *update* is an unsolicited delta the user expected
the gate to have already vouched for. Silent auto-proceed on that path is the
bug we're fixing.

**Staging preserves the finding-1.2 TOCTOU guarantee on both tiers.** `_clone_aur`
captures the gate-time tip (`origin/<branch>` SHA + origin URL) into `SCAN_SHA`
before any cleanup. On a clean or review-hit scan (NOT hard-fail, NOT
clone-failure), `_stage_scan_if_gating` writes `staged/<pkgbase>` + manifest
entry, exactly as the cached path's `_stage_if_gating` does. So `accept` promotes
the **audited** commit X (the origin tip at clone time), not whatever the helper
later fetches+installs (X′) — and NOT the baseline commit (which is only the diff
base, never a trust anchor). Without staging, a window-commit X′ pushed between
the clone and yay's own fetch would install, then be auto-seeded as the trusted
baseline on the next gate (`accepted_ref` falls back to helper-cache HEAD when no
accepted file exists) — reopening the exact bug finding 1.2 closed. Hard-fail
exits do NOT stage: a blocked update never reaches the helper, so there's nothing
to accept. `$pkg` is used as pkgbase (correct for non-split; split packages fail
the clone URL anyway since AUR repos are keyed by pkgbase).

**`scan_diff_rules` is shared by both diff paths** (cached + baseline recovery)
so they can never drift: `diff_added` → hard rules + new-`.install` (→ 1 + stash)
→ review rules + modified-`.install` + new binaries + maintainer/source drift
(→ 2 + stash) → 0. Staging stays in the callers (cached uses `_stage_if_gating`
with a cache dir; missing-cache uses `_stage_scan_if_gating` with `SCAN_SHA`).

**Known limitation — `AUR_SAFE_ALLOW_REVIEW=1` auto-proceeds clone failures.**
The wrapper honors this env var for all exit-2 results, including a clone
failure (zero signal). In non-interactive/automation contexts this recreates a
silent-passthrough hole for the missing-cache path specifically. A separate
exit code for "audit unavailable" (not consented review) was considered and
deferred — it requires a wrapper-contract change. For now, do not set
`AUR_SAFE_ALLOW_REVIEW=1` in automation that can't tolerate a blocked update.

**Review debate (glm-5.1 / kimi-k2.6 / qwen3.7-max):** 6 findings raised.
Conceded & fixed: (1) HIGH — TOCTOU/anchor-poisoning via unstaged scan-time tip
[fixed — `_stage_scan_if_gating` + `SCAN_SHA`/`SCAN_URL` capture]; (4) unvalidated
`$pkg` in `check_pkg` (only `cmd_audit` validated) + missing `--` in `git clone`
[fixed — regex guard at `check_pkg` entry, `--` separator]; missing-PKGBUILD
silently accepted if `.install` exists [fixed — explicit PKGBUILD-existence
check]. Noted, deferred: clone-fail under `AUR_SAFE_ALLOW_REVIEW=1` [see limit
above]; restricting the scan to `.install`+`.sh` (not PKGBUILD) to shrink
false-positive blast radius on legit `build()` npm calls [moot for tier 1 —
baseline recovery made the whole-file FP problem largely disappear; tier 2 still
hard-scans PKGBUILD]; a *separate* pre-existing blindspot where `find_pkg_dir`'s
slow path can return a `.SRCINFO`-only dir (no `.git`) → `git rev-parse` fails →
`return 0` [same category, natural follow-up]. Held: `explain` prompt labels
whole-file content as "FLAGGED DIFF" — cosmetic, the LLM analysis is
format-agnostic.

### Cache re-seeding — rejected (baseline recovery superseded it)
A `reseed`/`yay -G` wrapper to restore a missing cache clone was once the
planned "fix" for the missing-cache path. **Rejected after baseline recovery
landed**, on three grounds:
1. **The motivation is gone.** Re-seeding was conceived when missing-cache was a
de graded path (coarse whole-file scan, `.install` FPs). Baseline recovery made
the missing-cache path a real diff through the same `scan_diff_rules` pipeline —
functionally equivalent to the cached path for the common case. Re-seeding no
longer upgrades a bad path to a good one.
2. **It would make the next gate *less* scrutinized, not more.** Cached
first-contact seeds the anchor from clone HEAD and audits *nothing* about the
tip (trusted wholesale). Missing-cache baseline recovery diffs the installed
version to the tip and scans the delta. So restoring the cached path to "fix" a
missing-cache package would reduce scrutiny on its next gate.
3. **Naive re-seed re-creates the blindspot** for the *currently-pending* update:
clone → `accepted_ref` auto-seeds from clone HEAD (= origin/master tip) → if
that update is malicious, the next gate shows an empty diff and prints clean.
This is identical to fresh-install first-contact semantics (an accepted
assumption), so it's not a new hole — but it inverts the value proposition.

The escape hatch for the rare convenience case already exists and is free:
`yay -G <pkg>` clones correctly (incl. split packages, which the missing-cache
clone URL gets wrong) and behaves as a known first-contact seed. Document, don't
build. Revisit only if repeated fresh-clone cost on missing-cache packages
becomes measurable (unlikely — missing-cache is rare and one clone per gate is
~80ms).

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

4. **Wrapper defines both `yay()` and `paru()`.** (Resolved — both are gated
   cross-shell, bash+zsh.) Residual: `_aur_safe_dispatch` itself is only tested
   via the classify function, not end-to-end. The 3 historical dispatch bugs
   were each found manually, not by selftest. Trust the classify tests; verify
   the full pipeline manually on any wrapper change.

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

- `selftest`: 87/87 (31 rule-engine + 16 wrapper-dispatch + 20 accepted-ref /
  staging / accept / install-confirmation, incl. faithful split + non-split +
  space-indented + pkgbase-fallback `.SRCINFO` scenarios verified against
  makepkg output + real cached files; +10 missing-cache fallback cases: routing
  / exit-code / clone-fail / review-rules-skipped / .install-hit / staging-tip
  / manifest / stash, via local `file://` fixture repos, no network; +10
  baseline-recovery cases: FP-elimination / hard-hit-blocks / review-hit /
  review-hit-stashes-diff / not-found-falls-back / clean-stages-tip /
  hard-hit-no-stage / skips-missing-srcinfo / comment-missing-no-desync /
  tree-type-no-desync, via local fixtures with real git history + committed
  `.SRCINFO`).
  Run with `aur-safe selftest`.
- Accepted-ref lifecycle verified end-to-end on a real cached package
  (cursor-bin): seed from HEAD, stage on non-empty clean diff, manifest write,
  install-confirmation (incl. non-split `pkgbase=` fallback), `accept` promotion.
- Wrapper dispatch (gate → build → `accept`) verified with a stub helper in
  both bash and zsh: clean build → accept → rc 0; failed build → rc 1
  propagated; review-consent → proceeds → rc 0.
- `yay`/`paru` exit non-zero on ANY build failure — sandboxed test
  (isolated root/dbpath/cachedir, good+broken PKGBUILDs), both helpers,
  ordering-independent. **Source-confirmed via deepwiki** for both `Jguer/yay`
  (`main.go`, mirrors `exec.ExitError`) and `Morganamilo/paru` (`--failfast`,
  non-zero if any build fails). See *Accepted-ref state* above.
- Full cached-package sweep (18 packages, all installed AUR pkgs on this
  system): install-confirmation parser verdict matches the ground-truth oracle
  (MATCH iff installed version == parsed `.SRCINFO` version) on every row —
  tab-format, space-format (opera-developer), split (windsurf), and stale-cache
  cases alike. No false positives or negatives.
- Real AUR updates: clean, exit 0, no regression.
- Missing-cache path verified live on ventoy-bin (cache clone deleted,
  pending update): v1 silently `return 0`'d; now clones and baseline-recovers
  (installed version matched in AUR history → real diff), so the pre-existing
  legit `.install` hook no longer false-positives — exits 0 when the delta is
  clean, 1 if a hook is newly added. Falls back to whole-file review (2) only
  if the installed version isn't in history. Scan stashed for `explain`.
- `find_baseline_commit` validated against real caches (opencode-bin 858
  commits, opera-developer 421 incl. space-indented `.SRCINFO`, cursor-bin,
  vscode-bin): correct commit, correct ancestor-of-origin/master, correct
  version match, ~80 ms history walk for the largest repo. The missing-.SRCINFO
  block-index path is covered by `baseline-skips-missing-srcinfo` (a mid-history
  commit without `.SRCINFO` no longer desyncs the cat-file batch walk).
- Synthetic full-evasion attack: hard rules fire, exit 1.
- Stealth scenario (impersonation + modified hook + committed binary, no
  payloads): review rules fire, exit 2.
- `explain` → LLM path confirmed working with glm-5.2.
- Wired cross-shell (`~/.shrc`), both `yay` and `paru` gated.
