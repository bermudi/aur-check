# aur-safe — reviewer context

`aur-safe` is a deterministic gate for Arch Linux AUR package updates. This file
exists so reviewers give useful feedback instead of re-litigating decisions
that were deliberate. **Read this before reviewing the script.**

## What problem it solves (threat model)

aur-safe is a deterministic gate for Arch Linux AUR package updates — it
catches malicious updates **before** they reach pacman. See
**[threat-model.md](threat-model.md)** for the full, sourced account —
attacker profile, three-wave obfuscation timeline, homograph vector, and
related community tools. This document focuses on *design decisions*, not
threat narrative.

## Architecture (settled — don't propose alternatives unless you see a real flaw)

**Deterministic classification is the gate. The LLM cannot override risk.**

- yay/paru keep a per-package git clone (`~/.cache/yay/<pkg>` or
  `~/.cache/paru/clone/<pkg>`). Checked-out `HEAD` = last version you built
  (treated as known-good). `origin/master` = candidate.
- On update: `git fetch`, diff `HEAD..origin/master`, classify the ADDED lines
  plus changed-file structure.
- Hard-fail rules → exit 1, block the update.
- Deterministic boring metadata allowlist (version/pkgrel/pkgver, checksum-only,
  literal optional dependency metadata, same-host `source=()` changes, no
  structural signals) → exit 0.
- Boring-edge (same narrow fields, but parser-ambiguous formatting/array shape)
  → exit 2 unless `AUR_SAFE_LLM_AUTO_BORING=1` and the strict verifier returns
  exactly `VERDICT: BORING_EDGE_OK`.
- Review-only rules or structural signals → exit 2 with consent.
- Audit-unavailable (fetch/clone/diff/read/state failure) → exit 1 and block;
  zero signal cannot be safely consented past.
- `explain` subcommand pipes a *flagged* diff to an LLM (`zai/glm-5.2` via
  `pi`, reusing existing auth) for a second opinion. Advisory only.

**LLM boundary:** the attacker is using obfuscated bash (hex/octal escapes).
LLMs handle obfuscated bash inconsistently — false negatives on the real attack,
false positives on legit updates. The LLM therefore cannot override hard,
review, audit-unavailable, clone/diff, staging, or accept decisions. The only
opt-in gate use is a narrow convenience verifier for deterministic
`boring_edge`: the diff already has no dangerous patterns, no review patterns,
no changed files outside `PKGBUILD`/`.SRCINFO`, no added/removed files, and no
new maintainer/source host domains. Anything except an exact first-line
`VERDICT: BORING_EDGE_OK` stays review.

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

### `git fetch` failure → audit unavailable
The helper fetches again before building. If the gate scans stale
`origin/master` after its fetch fails, it can report clean and then let the
helper install a newer unseen commit seconds later. `check_pkg` therefore
returns blocking audit-unavailable (1), does not stage, and never labels stale
state all-clear. This trades offline convenience for a real mechanism; the old
warn-and-continue behavior was an unsafe availability optimization.

### Accepted-ref state (finding 1.2) — the trust-anchor fix

**Problem:** `check_pkg` used to diff `HEAD..origin/master`, trusting the
helper-cache HEAD as known-good. But HEAD can advance past the known-good state
(aborted build, manual `git pull` in the cache, helper restart) → an empty diff
prints clean while a malicious update lands.

**Design (staging + post-build accept):**
- `accepted/<pkgbase>` = `<sha>\t<iso-utc>\t<origin-url>`. Never seeded from
  helper HEAD. Missing anchors use the baseline-recovery/whole-candidate path,
  always require review, and are created only after confirmed installation.
- On a clean or review-only audit, `check_pkg` writes the **gate-time**
  `origin/master` tip to `staged/<pkgbase>` (NOT on empty-diff / hard-fail /
  skip paths) and appends `pkgbase` to a per-run manifest (`last-gate`).
- The wrapper captures the helper's exit code, runs the build, then calls
  `aur-safe accept`. `accept` promotes `staged → accepted` **only for manifest
  entries pacman confirms installed at the staged version**.
- Deliberate new AUR installs use the same lifecycle: under the transaction
  lock, `audit` stages its fresh-clone SHA/pkgbase, the helper installs, and
  `accept` creates the first confirmed anchor. Repository packages are skipped.

**Why staging (not deferred acceptance or post-build bump):** the accepted ref
must mean *the commit we audited*, not *what got installed*. There's a TOCTOU
window between `check_pkg`'s fetch and the helper's own fetch. Capturing the
gate-time tip (X) preserves anchor identity. The generated wrapper also passes
a [Finding-S](findings/S-helper-build-toctou.md) guard through yay/paru's
`--makepkg` seam: immediately before PKGBUILD execution it requires manifest
membership, clean worktree/index, and `HEAD == staged SHA`. It injects helper
yay `--rebuildall --nomakepkgconf` / paru
`--rebuild=all --nochroot --nolocalrepo`, overrides persisted helper mflags with
a fixed safe set, rejects caller-supplied rebuild/custom makepkg flags and makepkg
artifact/integrity/context-switch modes, then adds `--cleanbuild --force` so
stale source/build/package state cannot bypass the guarded build. A window commit X′ therefore blocks
and must be audited on a rerun rather than executing first.
Deferred acceptance (match installed pkgver vs `.SRCINFO`) was rejected: needs a
new parser and pkgver can stay identical across a malicious push.

**Install-confirmation assertion (Finding F fix):** `.SRCINFO` is attacker-
authored and independent of what pacman actually installed, so its names and
version are now only a *candidate claim*, never sufficient proof. `accept`
passes the staged trust-anchor key as the expected pkgbase and requires all of:

1. staged `.SRCINFO` declares that exact column-0 `pkgbase` and at least one
   column-0 `pkgname` (malformed metadata has no fallback);
2. the claimed version matches an installed package record;
3. that root-owned pacman local-DB record binds the pkgname back to the expected
   pkgbase (`%BASE%`, with `%NAME%` fallback for old non-split records); and
4. both `%BUILDDATE%` and `%INSTALLDATE%` are at or after the staged ref's file
   timestamp, proving a stale same-version install cannot confirm a failed build.

Any matching split member counts, preserving split-package behavior without
letting `.SRCINFO` claim an unrelated installed package such as `glibc`.
`epoch=0` is normalized to no prefix, matching pacman's version rendering.
Missing/malformed local DB fields fail closed: the staged ref remains and the
old anchor is re-audited next time. This keeps `accept` safe on **any** helper
exit code without executing or statically approximating attacker-controlled
PKGBUILD shell.

**State durability and concurrency:** accepted/staged/flag records are written
to a same-directory temporary and atomically renamed; a failed trust-state or
manifest write blocks the helper rather than pretending the audit was durable.
The generated wrapper holds `run.lock` (`flock`) across the complete
**gate → helper build/install → accept** transaction. Locking gate and accept
separately is insufficient because another gate could truncate the manifest
while the helper builds. Direct `gate`/`accept` calls acquire the same lock for
their own mutations. Existing sourced wrappers must be regenerated to gain the
cross-process lock span.

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
cached path's rules: hard hit → 1 (block), review hit → 2. A deterministically
clean recovered diff still becomes review (2) with the whole candidate stashed,
because retained AUR history is attacker-controlled and cannot earn silent
trust. Baseline recovery still preserves precise delta severity: a pre-existing
legit `.install` hook is absent from the diff, while a newly-added hook can
hard-block. The whole candidate is additional human context, not a source of
hard-fail decisions.

**Tier 2 — whole-file fallback.** If the installed version isn't found in AUR
history (or can't be queried), clone and scan PKGBUILD/`.install`/`.sh` against
both hard and review rules, then **always return review (2)**. A baseline-less
absence of known regex hits is not evidence that arbitrary PKGBUILD shell is
safe; attacker-rewritten history must never become a silent clean. The whole
content is stashed for review. Clone/read failure blocks with exit 1 (zero
signal cannot be consented). The clone URL is overridable via
`AUR_SAFE_AUR_URL` (mirrors + selftest without network).

**`find_baseline_commit` mechanism & policy.** It reads every commit's `.SRCINFO`
in one `git cat-file --batch` pass (~80 ms for an 858-commit repo; per-commit
`git show` is ~25× slower). The batch stream echoes the *blob's* sha in its
header, not the commit's, so the commit↔`.SRCINFO` association is restored by
passing the oldest-first commit list into awk and mapping by block index. It
returns the **OLDEST** matching commit: if several commits share the installed
pkgver (e.g. a malicious push keeping pkgver identical), the oldest match
maximizes diff coverage and surfaces any intervening commit **within retained
AUR history**. Conservative within that history — it may over-report on a benign
re-commit at the same version. Whitespace-tolerant version extraction mirrors
`_installed_matches` (some packages ship space-indented `.SRCINFO`, e.g.
opera-developer).

**Why every missing-cache success is review (2), not hard-fail (1):** a whole-file scan has no
baseline, so the `install-hook-*` rules fire on any pre-existing legit `.install`
(ventoy-bin, vscode-bin, …). Hard-failing would block routine updates of common
packages. Tier 1's recovered diff can still hard-fail newly added payloads, but
its clean result cannot auto-pass: an attacker can rewrite retained history and
place a payload inside the reconstructed baseline. Why not advisory (0) like
`audit`: `audit` gates a deliberate *new* install the
user just typed; an uncached *update* is an unsolicited delta the user expected
the gate to have already vouched for. Silent auto-proceed on that path is the
bug we're fixing.

**Staging preserves the finding-1.2 TOCTOU guarantee on both tiers.** `_clone_aur`
captures the gate-time tip (`origin/<branch>` SHA + origin URL) into `SCAN_SHA`
before any cleanup. On a clean or review-hit scan (NOT hard-fail, NOT
clone-failure), `_stage_scan_if_gating` writes `staged/<pkgbase>` + manifest
entry, exactly as the cached path's `_stage_if_gating` does. So `accept` promotes
the **audited** commit X (the origin tip at clone time), not whatever the helper
later builds — and NOT the baseline commit (which is only the diff base, never a
trust anchor). The makepkg guard additionally rejects a helper checkout X′ that
does not equal staged X. Without staging, no reviewed commit identity could be
bound to the installed package or used to create the first anchor. Hard-fail
exits do NOT stage: a blocked update never reaches the helper, so there's nothing
to accept. Staging keys by **pkgbase**, derived from the clone dir name
(`${dir##*/}`, mirroring the cached path). `_clone_aur` resolves pkgname→pkgbase
via AUR RPC before cloning (Finding N fix), so split packages stage and anchor
correctly. Flag files stay keyed by pkgname for display (`explain <pkgname>`).

**`scan_diff_rules` is shared by both diff paths** (cached + baseline recovery)
so they can never drift: `diff_added` → hard rules + new-`.install` (→ `hard`,
exit 1 + stash) → review rules + modified-`.install` + added/removed files + new
binaries + maintainer/source drift (→ `review`, exit 2 + stash) → deterministic
boring metadata allowlist (→ `boring`, exit 0) → parser-ambiguous known boring
fields (→ `boring_edge`, exit 2 unless the opt-in strict verifier returns
exactly `VERDICT: BORING_EDGE_OK`). `.SRCINFO` lines that changed only leading
whitespace are ignored before metadata classification (makepkg regeneration can
flip spaces↔tabs without semantic change). Literal `.SRCINFO` advisory/package
metadata entries (`pkgdesc`, `url`, `arch`, `license`, `groups`, `optdepends`,
`noextract` — `noextract=` is a versioned *filename* pointing at a `source=()`
entry, never executed) and `.SRCINFO` dependency entries either already
satisfied by the installed package set, proven by pacman sync DB to be
repository packages, OR **intra-pkgbase** (the dep's name matches this
pkgbase's `pkgbase=` or a declared `pkgname=` member at the new tip — a
self-reference that cannot pull in unaudited code from outside the package
under review) are boring metadata; all other unknown/AUR-looking dependencies
stay review so a package update cannot silently pull an unaudited AUR
dependency. Literal single-quoted members of PKGBUILD `depends=()` /
`makedepends=()` / `checkdepends=()` arrays inherit that same trust decision
only when the candidate `.SRCINFO` contains the dependency too. The shared
full-candidate tracker proves multiline-array context and disables auto-clear
on parser-ambiguous lexical shapes; bare/double-quoted values, shell expansion,
stray quoted tokens, and
unknown AUR dependencies stay review. This keeps PKGBUILD and `.SRCINFO`
classification symmetric without treating executable shell syntax as generic
metadata. The **PKGBUILD array-literal forms** of `license`/`arch`/`groups`/
`noextract` (`license=('MIT' 'LGPL-2.0-or-later')`, `arch=('x86_64' 'aarch64')`)
are classified symmetrically with their `.SRCINFO` space-delimited forms —
makepkg writes them into `.PKGINFO` without executing them; they touch no
checksum, source host, or trust anchor. (`pkgdesc`/`url` are scalars, never
array literals; `optdepends` keeps its own stricter handler that rejects shell
expansion.) `PKGBUILD` build variables assigned a bare **lowercase** git SHA
(`_commit=<hex>`, `_gittag=<short-sha>`, `_gitrev`/`_tag`/`_rev`, optionally
quoted, 7..40 hex chars) are boring — the RHS of a string assignment is never
executed and the fetched artifact is verified by the `*sums=()` array. The
var-name is RESTRICTED to conventional SHA holders (not any `_`-prefixed var):
this closes the validpgpkeys-indirection gap a delegate review flagged
(delegate-review Finding 1), where a `_evil=<lowercase-40hex>` feeding an
already-present `validpgpkeys=($_evil)` would otherwise auto-clear on a
trust-anchor surface (lowercase is NOT a defense — `validpgpkeys=` accepts any
case; the var-name allowlist is). Add a name to the allowlist only when a real
AUR package needs it — every added name re-opens the surface. **Dotted-decimal
version build-vars** (`_nwjs_ffmpeg_version=0.113.0`, `_electron_version=v25.3.0`
— optional `v` prefix + quotes, any `_-prefixed var name`) are the same
inert-metadata class and are boring: the RHS never executes, and the version only
selects a path in `source=()` whose artifact is verified by `*sums=()` (host drift
/ IDN homograph are caught by `source_domains()` + the Finding E guard, run before
the per-line loop). Unlike `_commit`, the var-name is NOT restricted here — a
dotted decimal cannot be a PGP fingerprint (hex) or a checksum (hex/`SKIP`), so
the RHS **format** is the security boundary, not the name; the validpgpkeys-
indirection that forced the `_commit` allowlist has no analogue. This matters
because real package var names don't follow a convention (`_nwjs_ffmpeg_version`,
not `_version`), so a name allowlist would silently miss the motivating
`opera-developer` case. Command substitution is rejected (`$`/backtick break the
`[0-9.]` match). Inline
fingerprints in `validpgpkeys=(...)` remain caught by
`_pkgbuild_checksum_array_line` (requires a `*sums=(` array). Indexed
checksum-array element assignments (`sha512sums[0]=<hex>` / `'SKIP'` — distinct
syntax from the `sums=(...)` literal and `sums_<arch>=` var forms; the `[N]`
index between name and `=` breaks both of those regexes) are boring: the RHS is
inert data makepkg enforces against the downloaded artifact, and a wrong value
fails the build before install; the motivating `cursor-bin` shape declares the
array with a `'SKIP'` placeholder at `[0]`, then overwrites `[0]` in a separate
statement with the real hash. **Arch-qualified** `source`/`*sums` lines are
classified symmetrically with their bare forms in every syntax:
`.SRCINFO` space-delimited (`source_x86_64 =` / `sha256sums_aarch64 =`),
PKGBUILD single-line arrays (`source_x86_64=(...)`), and bare assignments —
the `opencode-bin` / `visual-studio-code-bin` per-arch-tarball shape (a
version bump renaming each `source_<arch>` URL on the same host is boring).
This is safe only because the **Finding E homograph guard**
(`_source_line_nonascii`, run in `classify_diff_rules` before the per-line
boring loop) forces review on any added line carrying `://` (or a `source`/
`source_*=` token) with a byte ≥ 0x80: `source_domains()`'s hostname extractor
is ASCII-only and blind to IDN homograph hosts, so without the guard a
Cyrillic-prefixed URL would auto-clear as inert metadata (the threat model's
own example). The `://`-anywhere match catches the multi-line array
continuation line shape, not just the `source=` token-start line — added
2026-07-05 after a delegate review flagged that the continuation line
otherwise falls to the standalone-URL `boring_edge` path, reachable by the LLM
auto-green verifier (the LLM is no better at spotting an invisible Cyrillic
byte than the deterministic classifier). Literal
single-quoted `PKGBUILD optdepends=(...)` entries and standalone quoted/bare
`SKIP`/hex tokens — the per-line shape inside a PKGBUILD multiline
`sha256sums=(...)` array, distinct from the `.SRCINFO` `sha256sums = <hex>`
form already handled above — are boring metadata; non-literal PKGBUILD shell
expansion inside optdepends stays review. Literal quoted local filenames inside
a proven multiline `source=()` array are `boring_edge`; a global filename regex
would be unsafe because a quoted top-level token is executable shell. The
optdepends/checksum/dependency/source trackers share one
`_pkgbuild_array_member_added_line` state machine over the complete candidate
PKGBUILD. Parsing the candidate avoids old/new hunk ambiguity: a `@@` label can
name a removed multiline opener after the new file changed to `depends=()`.
Openers require `(` at end-of-line; closers cover bare, comment-suffixed, and
inline-final `)` forms so checksum state cannot leak into `validpgpkeys`. Because
candidates are keyed by raw text, every candidate-file occurrence must be inside
the target array; a safe duplicate cannot mask an executable twin. This is not
a full Bash parser, so any multiline quote/backtick, heredoc, or backslash-line
continuation disables contextual auto-clear—preventing fake openers hidden in
inert/joined text.
This shared seam keeps those parser invariants from drifting. All git
invocations are isolated from user/system config via
`export GIT_CONFIG_GLOBAL=/dev/null
GIT_CONFIG_SYSTEM=/dev/null` at script load (Finding J): user options like
`diff.noprefix` (strips the `b/` prefix → file trackers never match),
`diff.colorWords`/`diff.wordDiff` (word-oriented output, no `+` prefixes →
empty `added`), and `textconv` (arbitrary code on `git show`) would otherwise
break the pipeline or execute attacker code; the export overrides any hostile
caller env (last export wins) and makes diff output deterministic.
**Review-detail selection** (`_detail_is_build_logic` / `_review_added_line_summary`):
when a diff has more than one non-boring added line, the reported detail prefers
a build-logic line (a `prepare`/`build`/`check`/`package`/`install` function
header, or a build/install statement like `install`/`cp`/`cmake`/`make`/`npm`/
`cargo`) over an earlier metadata-ish non-boring line (e.g. `backup=`, a new
PKGBUILD var assignment), so the reviewer's eye lands on the security-relevant
change. This is editorial only — the gate's classification is unaffected; a
missed keyword falls through to the generic summary (fail-safe). The
build-logic check is **content-based**, not git-hunk-annotation-based: PKGBUILD
has no built-in diff driver, so git never annotates hunks with `package()`/
`build()` context, making a prior `^PKGBUILD:N in (...)` summary regex
effectively dead. The keyword list is not a security blacklist (the threat
model's red line is against attacker-rotated package/installer names, not shell
keywords).
Diff/read failures are `audit_unavailable` (exit 1), never consented or LLM
auto-green, and never stage. Staging stays in the callers (cached uses `_stage_if_gating` with a
cache dir; missing-cache uses `_stage_scan_if_gating` with `SCAN_SHA`).

**Optional LLM boring-edge verifier.** Config is loaded from
`~/.config/aur-safe/config` (`KEY=value`, currently only
`AUR_SAFE_LLM_AUTO_BORING=0|1`), with environment variables taking precedence.
When disabled, `boring_edge` is ordinary review. When enabled, `llm_check_boring_edge`
uses `pi` with no tools/session and accepts only an exact first-line
`VERDICT: BORING_EDGE_OK`; command failure, missing `pi`, malformed output,
`NEEDS_HUMAN`, truncation, or anything else returns review. This can stage only
through the normal clean rc-0 caller path, so the staged SHA remains the
gate-time tip and `accept` still requires installed-version confirmation.

**Missing-cache retained-history limit (mitigated by mandatory review).** The
cached path anchors on aur-safe's frozen SHA, but a missing-cache package has no
local accepted/cache ref. Baseline recovery reconstructs a useful diff base from
retained AUR history, which an attacker can rewrite. Therefore even a clean
recovered diff stashes the whole candidate and returns review (2); history is
used for precision and hard-rule detection, never to earn silent trust.

**Audit-unavailable is not consentable.** `AUR_SAFE_ALLOW_REVIEW=1` applies
only to exit-2 results after a real candidate was audited. Fetch/clone/diff/read
or state failures map to exit 1, block the helper, and never stage. This closes
the old zero-signal auto-proceed/first-contact re-seeding hole.

**Review debate (glm-5.1 / kimi-k2.6 / qwen3.7-max):** 6 findings raised.
Conceded & fixed: (1) HIGH — TOCTOU/anchor-poisoning via unstaged scan-time tip
[fixed — `_stage_scan_if_gating` + `SCAN_SHA`/`SCAN_URL` capture]; (4) unvalidated
`$pkg` in `check_pkg` (only `cmd_audit` validated) + missing `--` in `git clone`
[fixed — regex guard at `check_pkg` entry, `--` separator]; missing-PKGBUILD
silently accepted if `.install` exists [fixed — explicit PKGBUILD-existence
check]. Clone-fail auto-consent is now closed by blocking audit-unavailable.
Restricting the scan to `.install`+`.sh` (not PKGBUILD) to shrink
false-positive blast radius on legit `build()` npm calls [moot for tier 1 —
baseline recovery supplies precise delta severity; tier 2 still scans PKGBUILD
but always requests review]. The old `find_pkg_dir` slow-path blindspot is now
closed more strongly than a `.git` check: split pkgname→pkgbase is resolved by
AUR RPC and only that exact cache directory is inspected, so an unrelated
attacker-authored cached `.SRCINFO` cannot redirect the gate. Held: `explain` prompt labels
whole-file content as "FLAGGED DIFF" — cosmetic, the LLM analysis is
format-agnostic.

### Cache re-seeding — rejected
A helper clone is cache, not evidence of what pacman installed. `accepted_ref`
therefore never seeds from helper HEAD—even when a clone already exists. A
missing anchor is routed through baseline recovery plus mandatory whole-candidate
review, then `accept` creates the anchor only after the guarded build is
confirmed installed. `yay -G` may restore cache convenience but cannot create
trust state. This costs one fresh clone/review on migration and closes the
aborted-build/manual-pull first-contact bypass.

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

## Open pressure points — useful feedback belongs here

These are the real pressure points where future work should stay focused:

1. **Hard-fail vs review classification.** Currently `npm`/`pnpm`/`bun`/`yarn`
   in a PKGBUILD diff are hard-fails; `pip`/`gem`/`cargo`/`go install` are
   review-only. The asymmetry is intentional (the observed campaign uses JS
   package managers; Python/Ruby/etc. legit use is more common in AUR), but
   the line is a judgment call. Is it drawn in the right place?

2. **Hex/octal run threshold = 2+.** Somewhat arbitrary. 2 catches
   `\x6e\x70` (two chars) but also `\x1b\x5d` (legit OSC sequences in some
   terminal scripts). 3+ would reduce FPs but miss short obfuscated strings.
   Is 2 right?

3. **New-install findings remain advisory.** No baseline exists, so blocking on
   every absolute npm/build-tool match would reject legitimate packages. The
   wrapper now stages the audited SHA and confirms the first anchor after
   install, but findings still print and proceed. Should policy become blocking?

4. **Wrapper defines both `yay()` and `paru()`.** Resolved cross-shell. Dispatch
   classification is in selftest; the full lock/audit-or-gate/helper/accept
   order was also verified with stub executables in bash and syntax-checked in
   bash+zsh. Repeat the behavioral stub on wrapper changes.

5. ~~**Missing-cache baseline recovery is weaker than a frozen accepted SHA.**~~
   Resolved operationally: retained history is used for delta precision, but
   every missing-cache result requires whole-candidate review and cannot exit 0.

## Path forward (current priorities)

The core update gate is the protected asset: cached updates, missing-cache
baseline recovery, staging/accept, and diff-failure handling now share the same
diff-based trust discipline. Future work should improve that discipline or
remove drift; it should not broaden the trust path casually.

1. ~~**Enforce the staged SHA immediately before makepkg (Finding S).**~~ ✅
   done 2026-07-23 via both helpers' `--makepkg` seam; missing, mismatched,
   dirty, or transitively-unaudited checkouts block before PKGBUILD sourcing.
2. ~~**Split "audit unavailable" from "review hit".**~~ ✅ done 2026-07-23.
   Zero-signal failures now block with exit 1; only audited candidates can
   produce consentable exit 2.
3. ~~**Add a review-level homograph check for `source=()` URLs.**~~ ✅ done
   2026-07-01 (`_source_line_nonascii`). Flag newly-added or changed source
   hostnames containing non-ASCII characters (bytes ≥ 0x80) → review, before
   the per-line boring loop. Covers `.SRCINFO` space-delimited + PKGBUILD array
   + bare assignment syntaxes. Hard-fail upgrade still open pending real
   campaign evidence.
4. ~~**Decide the missing-cache history-rewrite policy.**~~ ✅ mandatory review
   implemented 2026-07-23. Retained history improves delta precision but never
   earns exit 0; the whole candidate is stashed for consent.
5. **Measure before changing new-install gating or thresholds.** Keep `audit`
   advisory until real AUR samples quantify false positives. Any move toward
   blocking new installs, changing the hex/octal threshold, or reclassifying
   package managers needs fixtures that prove the false-positive cost is worth
   the added protection.

Definition of done for trust-path changes: update this ledger, link code
comments to the relevant section/finding, run `bash -n aur-safe`,
`./aur-safe selftest`, and `shellcheck -s bash aur-safe`, and re-check the
TOCTOU invariant: blocked/unknown audits never stage; consentable/clean audits
stage only the gate-time tip; `accept` promotes only installed-version-confirmed
staged commits.

## What I don't need feedback on

- "Why not just use an LLM?" — see Architecture. Settled.
- "Why bash not Go/Rust/Python?" — see Decisions. Settled for v1.
- Style nits that shellcheck already flagged and I deliberately kept
  (SC2016, SC2001). See Decisions.
- Suggestions to add more package names to a blacklist. The whole point is
  that blacklists lose.

## Verification status (so you don't re-verify what's already proven)

- `selftest`: **241/241**. Coverage includes hard/review rule variants; wrapper
  dispatch, update-query failure, and gate-through-accept locking; atomic
  accepted/staged state; pacman local-DB pkgbase/build/install binding (foreign
  `.SRCINFO` rejection, stale-build rejection, split packages, epoch zero);
  missing-cache baseline recovery and always-review tier 2; git/diff failure
  propagation; package-name/RPC path validation; shared multiline-array context
  (including the `depends=()` latch regression); quoted source filenames;
  homographs; classifier/LLM boundaries; and gate-time SHA staging. Fixtures use
  local `file://` repos and isolated state. Run with `aur-safe selftest`.
- Accepted-ref lifecycle is covered end-to-end: no implicit HEAD seed, atomic
  stage/accept, manifest,
  expected-pkgbase/version/build/install confirmation, and promotion. Malformed
  `.SRCINFO` has no pkgbase fallback and cannot advance the anchor.
- Wrapper dispatch verified with stub executables: gate/audit → helper → accept
  ordering, transaction lock inherited by aur-safe children, lock fd/env removed
  from the untrusted helper, helper rc propagation, new-install staging, exact
  pre-makepkg SHA, forced fresh artifact build, cache-reuse/context-switch
  rejection, combined `-Syu <new-target>` auditing, and option-operand parsing.
  Generated wrapper syntax passes both bash and zsh.
- `yay`/`paru` exit non-zero on ANY build failure — sandboxed test
  (isolated root/dbpath/cachedir, good+broken PKGBUILDs), both helpers,
  ordering-independent. **Source-confirmed via deepwiki** for both `Jguer/yay`
  (`main.go`, mirrors `exec.ExitError`) and `Morganamilo/paru` (`--failfast`,
  non-zero if any build fails). See *Accepted-ref state* above.
- The pacman local-record adapter is live-checked against installed AUR package
  metadata (`%NAME%`, `%VERSION%`, `%BASE%`, `%BUILDDATE%`, `%INSTALLDATE%`);
  malformed/missing fields fail closed.
- Real AUR updates: clean, exit 0, no regression.
- Missing-cache path verified live on ventoy-bin (cache clone deleted,
  pending update): v1 silently `return 0`'d; now clones and baseline-recovers
  (installed version matched in AUR history → real diff), so the pre-existing
  legit `.install` hook no longer hard-fails — retained history gives precise
  delta severity, while the path still requires whole-candidate review (2).
  Falls back to whole-file review if the installed version isn't in history.
  Scan stashed for `explain`.
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
- **Red-team review (2026-06-26):** three delegate reviewers (glm-5.1 adversarial
  auditor, kimi-k2.6 edge-case hunter, qwen3.7-max bug spotter) against the full
  codebase + docs — 23 findings across 14 new finding files (E–R) + 9 low-severity
  items. The two critical and six high findings now have implemented mitigations
  or fixes; remaining low-priority work is tracked separately. See
  [BACKLOG.md](../BACKLOG.md) for current status
  and [findings/](findings/) for individual write-ups.
