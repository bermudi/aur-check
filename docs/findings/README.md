# Findings

Durable record of aur-gate's security findings — the mechanisms, fixes, and
lessons learned. This directory is the canonical long-form reference, cited by
code comments and `AGENTS.md`.

**Implementation lineage:** findings created before 2026-08-04 often cite the
retired Bash script and its historical line numbers. The supported Rust
implementation at the repository root is now the policy oracle. The Bash source
and its full ledger are frozen under `archive/bash/`; open issues must be
assessed and fixed against Rust rather than backported to the archive. The
migration disposition for still-open Bash-era issues is recorded in
[`ZZ-cohort2-reconciliation.md`](ZZ-cohort2-reconciliation.md); tracker state
may lag code until closure review and durable `ghNN` documentation are complete.

## How findings are tracked

Two artefacts, two roles:

- **GitHub issues** — the *live tracker*. Open work, workflow state, who/when.
  Open findings carry their issue number in the catalog below.
- **`docs/findings/`** (this directory) — the *durable record*. One markdown file
  per substantive finding: mechanism, threat-model relevance, fix, verification,
  lesson. Each file's `Status` field records open/fixed.

GitHub issues are poor long-term reference (closed issues recede from view);
this directory is what you read to understand what the tool defends against and
why. When a finding is resolved, update the doc's `Status` **and** close its issue.

## Provenance

Findings arrived in waves; each doc's `Source` field has the precise attribution.

### Founding pass (A–D)
Earliest findings from initial hardening. All closed. No severity classification
(predates the scheme).

### 2026-06-26 red-team review (E–R)
Three delegate reviewers against the full codebase + docs — 14 finding files.
Session transcripts under `~/.pi/agent/sessions/--home-daniel-build-aur-gate--/`:

| Reviewer | Role | Session |
|---|---|---|
| glm-5.1 | adversarial auditor | `019f0517-d737-732f-b8d6-6ae4c3208309` |
| kimi-k2.6 | edge-case hunter | `019f0517-d73a-78d5-929f-c514eed1880d` |
| qwen3.7-max | bug spotter | `019f0517-d73a-785f-929f-caae55c267e2` |

### Follow-up findings (S–Y)
Gaps surfaced in later implementation reviews (S–V) and the 2026-07-27 follow-up
of the impersonation / source-drift signals and the advisory `accept` path
(W–Y; all fixed).

### GitHub Cohort 2 — 2026-07-27 (#2–#22)
A second review filed directly as GitHub issues under a C/H/M/L scheme
(C1–C3 critical, H1–H5 high, M1–M8 medium, L1–L5 low). Under the findings/-
canonical model each gets a `ghNN` doc when its issue closes (legacy A–Y predate
the tracker). They partially overlap Cohort 1 (e.g. GH H1 ≈ local J/L7 git-config
isolation, fixed) and add new gaps (C2 fail-open URI, …). **gh2–gh5 (critical
C1–C3 + H1, #2–#5), gh18 (L1, #18), gh19 (L2, #19), and gh21–gh22 (L4–L5, #21–#22)
are resolved** — the `++` added-line-drop, fail-open source URI validation,
advisory-only `cmd_audit`, repo-local git-config / git-invocation hardening,
`cmd_scan` partial-coverage documentation, review-detail record separation,
SHA-256 trust anchors, and uppercase package-name validation; **gh8 (H4, #8)
is resolved** (deletion-only/removed PKGBUILD security fields no longer auto-
clear as boring); **gh11 (M2, #11) is resolved** (C-locale determinism);
**gh10 (M1, #10) is resolved** (duplicate of gh3 — source authority anomalies
deterministically routed to review before the LLM boundary); **#24–#26 are fixed**
(W/Y/X — maintainer-drift orphan adoption, advisory-accept commit binding,
`source+=()` drift); **#7, #9, #13, #14, #20 were closed on 2026-08-04** after
Rust-code re-evaluation (forced `--text`/NUL-safe evidence, all-untracked +
regular-blob makepkg guard, size-framed `cat-file` parsing, escaped terminal/
pager output, head-and-tail advisory context). **#12, #15, #16 remain partially
open** (HTTPS-only `AUR_URL` not enforced; trust files lack `O_NOFOLLOW`;
`--opt=value` wrapper forms unhandled) and **#17 remains open** (DoS
availability hardening). See
<https://github.com/bermudi/aur-gate/issues>.

### GitHub Cohort 3 — 2026-08-04 (#27–#35)
A third review (two adversarial passes: qwen3.8-max-preview on workflow/policy
and qwen3.8-max on Git internals/shell runtime) was filed after verifying each
finding against the Rust code. 9 genuinely new issues were filed; findings
already resolved by the Rust migration or by existing fixes were not filed
(binary-update DoS, build-time anchor poisoning, cmd_audit lockless, accept
TOCTOU, helper config precedence, config/env mismatch, rule severity asymmetry,
pacman -U boundary, line-continuation evasion). The new issues extend closed
#5 (git config: `http.*` and `includeIf.*` gaps) and closed #4 (cmd_audit
zero-hit first-contact). **#31 (H10) is resolved** — `cmd_audit` now requires
whole-candidate review for first-contact packages even when the deterministic
scan produces zero rule hits, matching `check_pkg`'s missing-cache gate. See
<https://github.com/bermudi/aur-gate/issues>.

## Catalog

Status: ✓ fixed/closed · △ mitigated · ◷ open. Open findings link to their issue.

### Critical
- ✓ **gh2** — Added-line extractor drops lines beginning with `++` (C1, #2) → [doc](gh2-added-line-extractor-drops-plusplus-lines.md) · [#2](https://github.com/bermudi/aur-gate/issues/2)
- ✓ **gh3** — Source URI validation fail-open (userinfo, scheme downgrade, local paths, VCS/IPv6/port) → [doc](gh3-source-uri-fail-open.md) · [#3](https://github.com/bermudi/aur-gate/issues/3)
- ✓ **gh4** — Explicit new installs through `cmd_audit` were advisory-only (C3, #4) → [doc](gh4-cmd-audit-advisory-only.md) · [#4](https://github.com/bermudi/aur-gate/issues/4)
- ✓ **gh5** — Repo-local git config trusted; git invocation hardening incomplete (H1, #5) → [doc](gh5-git-invocation-hardening.md) · [#5](https://github.com/bermudi/aur-gate/issues/5)
- ✓ **F** — Trust-anchor poisoning via attacker-crafted `.SRCINFO` → [doc](F-srcinfo-trust-anchor-poisoning.md)
- △ **E** — IDN homograph `source=()` URL bypass → silent exit 0 (mitigated, review-level) → [doc](E-homograph-source-bypass.md)
- ✓ **S** — Helper can build a commit newer than the audited gate-time tip (TOCTOU) → [doc](S-helper-build-toctou.md)
- ✓ **U** — PKGBUILD source-time execution auto-cleared as metadata → [doc](U-pkgbuild-source-time-execution-autoclear.md)

### High
- ✓ **G** — Missing-cache tier-2 silently passes review-only payloads → [doc](G-tier2-review-rules-skipped.md)
- ✓ **H** — `bunx`, `pnpm exec`, `yarn dlx` escape JS package-manager hard rules → [doc](H-bunx-pnpm-exec-yarn-dlx-missing.md)
- ✓ **I** — `pip3 install` bypasses `pip` review rule → [doc](I-pip3-bypass.md)
- ✓ **J** — User git config breaks diff parsing → [doc](J-git-config-breaks-diff.md)
- ✓ **K** — `epoch=0` breaks install confirmation and baseline recovery → [doc](K-epoch-zero.md)
- ✓ **L** — Concurrent gate runs corrupt the per-run manifest → [doc](L-manifest-race.md)
- ✓ **T** — Changed patch content omitted from review evidence → [doc](T-patch-review-evidence-omitted.md)
- ✓ **W** — Maintainer-drift blind to orphan adoption (empty baseline) → [doc](W-maintainer-drift-blind-to-orphan-adoption.md) · [#24](https://github.com/bermudi/aur-gate/issues/24)
- ✓ **gh6** — Hard rules are brittle and can be evaded into review (Cohort 2 H2, #6) → [doc](gh6-hard-rules-brittle.md) · [#6](https://github.com/bermudi/aur-gate/issues/6)
- ✓ **gh8** — Deletion-only PKGBUILD changes classified boring (Cohort 2 H4, #8) → [doc](gh8-deletion-only-changes-classified-boring.md) · [#8](https://github.com/bermudi/aur-gate/issues/8)
- ◷ **#27** — Git replace refs & grafts enable auditor/builder view split (Cohort 3 H7) · [#27](https://github.com/bermudi/aur-gate/issues/27)
- ◷ **#28** — Git `http.*` local config keys escape safety check — proxy/CA MITM (Cohort 3 H8, extends #5) · [#28](https://github.com/bermudi/aur-gate/issues/28)
- ◷ **#30** — Wrapper dispatch does not reject `--hookdir`/`--cachedir`/`--gpgdir`/`--logfile` (Cohort 3 H9) · [#30](https://github.com/bermudi/aur-gate/issues/30)
- ✓ **#31** — `cmd_audit` auto-proceeds on first-time install with zero rule hits (Cohort 3 H10, extends #4) → [doc](gh31-cmd-audit-first-contact-zero-hit.md) · [#31](https://github.com/bermudi/aur-gate/issues/31)

### Medium
- ✓ **M** — `AUR_GATE_ALLOW_REVIEW=0` enables auto-proceed → [doc](M-allow-review-boolean.md)
- ✓ **N** — Split-package missing-cache clone failure (no scan, wrong staging key) → [doc](N-split-pkg-missing-cache.md)
- ✓ **O** — `find_pkg_dir` slow path doesn't verify `.git` exists → [doc](O-find-pkg-dir-no-git.md)
- △ **P** — Quoted PKGBUILD `source=()` entries reclassified as true-positive under gh3 → [doc](P-quoted-source-filenames-fp.md)
- ✓ **Q** — `files_with_status` silently ignores git diff failures → [doc](Q-files-with-status-swallows-rc.md)
- ✓ **R** — Package name regex allows `.`, `..`, `.git` → [doc](R-pkg-name-path-traversal.md)
- ✓ **V** — Inline checksum-array reflow false-positive (availability/FP) → [doc](V-inline-checksum-reflow-fp.md)
- ✓ **Y** — Advisory (non-wrapper) `accept` has no commit-identity binding → [doc](Y-advisory-accept-no-commit-binding.md) · [#25](https://github.com/bermudi/aur-gate/issues/25)
- ✓ **gh11** — Force C locale for deterministic regex and byte processing (Cohort 2 M2, #11) → [doc](gh11-force-c-locale.md) · [#11](https://github.com/bermudi/aur-gate/issues/11)
- ✓ **gh10** — LLM boring-edge auto-green should never see source authority anomalies (Cohort 2 M1, #10; duplicate of gh3) → [doc](gh10-llm-boring-edge-source-authority.md) · [#10](https://github.com/bermudi/aur-gate/issues/10)
- ◷ **#12** — AUR RPC parsing brittle, HTTPS not enforced (Cohort 2 M3, partial) · [#12](https://github.com/bermudi/aur-gate/issues/12)
- ◷ **#15** — State-dir permissions / symlink hygiene — trust files lack `O_NOFOLLOW` (Cohort 2 M6, partial) · [#15](https://github.com/bermudi/aur-gate/issues/15)
- ◷ **#16** — Wrapper portability — `--opt=value` unhandled (Cohort 2 M7, partial) · [#16](https://github.com/bermudi/aur-gate/issues/16)
- ◷ **#17** — DoS via large repos/diffs (Cohort 2 M8, open) · [#17](https://github.com/bermudi/aur-gate/issues/17)
- ◷ **#29** — Git `includeIf.*` bypasses `include.` prefix check (Cohort 3 M10, extends #5) · [#29](https://github.com/bermudi/aur-gate/issues/29)
- ◷ **#32** — Wrapper resolves aur-gate/pacman/flock via PATH at runtime (Cohort 3 M11) · [#32](https://github.com/bermudi/aur-gate/issues/32)
- ◷ **#33** — Zero-diff cached update exits clean without staging (Cohort 3 M12) · [#33](https://github.com/bermudi/aur-gate/issues/33)
- ◷ **#34** — Predictable PID-based temp filename in `stash_flag` (Cohort 3 M13) · [#34](https://github.com/bermudi/aur-gate/issues/34)

### Low
- ✓ **X** — `source+=()` append invisible to source-domain drift → [doc](X-source-append-invisible-to-domain-drift.md) · [#26](https://github.com/bermudi/aur-gate/issues/26)
- ✓ **gh18** — `cmd_scan` coverage is partial (Cohort 2 L1, #18) → [doc](gh18-cmd-scan-partial-coverage.md) · [#18](https://github.com/bermudi/aur-gate/issues/18)
- ✓ **gh21** — SHA-1 trust anchors will not support SHA-256 git repos (Cohort 2 L4, #21) → [doc](gh21-sha256-trust-anchors.md) · [#21](https://github.com/bermudi/aur-gate/issues/21)
- ✓ **gh22** — `_valid_pkg_name` rejects uppercase package names (Cohort 2 L5, #22) → [doc](gh22-uppercase-pkg-name-rejected.md) · [#22](https://github.com/bermudi/aur-gate/issues/22)
- ✓ **gh19** — `_collect_review_details()` uses tab-separated records (Cohort 2 L2, #19) → [doc](gh19-collect-review-details-tab-separated.md) · [#19](https://github.com/bermudi/aur-gate/issues/19)
- ◷ **#35** — Force-pushed history causes permanent lockout without auto-recovery (Cohort 3 L7) · [#35](https://github.com/bermudi/aur-gate/issues/35)
- L1–L9 (Cohort 1 lows) — see §Low-severity findings below; all fixed except L2.

### Founding pass (A–D, closed)
- **A** — Empty PKGBUILD in tier 2 treated as clean → [doc](A-empty-pkgbuild-silent-clean.md)
- **B** — `cmd_scan` is an ad-hoc third rule pipeline → [doc](B-cmd-scan-adhoc-pipeline.md)
- **C** — `diff_added` suppresses stderr — corrupted diff silently returns clean → [doc](C-diff-added-stderr-suppression.md)
- **D** — Version-vs-SHA mismatch in `accept` (working as designed) → [doc](D-accept-version-vs-sha.md)

## Low-severity findings (Cohort 1, L1–L9)

Too minor for individual files; recorded here for completeness. Detail lives in
the delegate transcripts (sessions above). All **fixed** except **L2** (rejected
as a non-finding — see below).

- **L1** (fixed) — `audit` path trust anchor autoseeds without install-confirmation.
  New installs now run under the transaction lock: `audit` stages the scanned
  SHA/pkgbase, the helper installs, and `accept` confirms via pacman before the
  first anchor is created.
- **L2** (rejected) — LLM boring-edge verifier "prompt injection." The verifier
  runs with `pi --no-tools --no-session` (no tool access, single-shot text mode)
  and only sees diffs that have already passed all hard and review rules
  deterministically — it can exclusively auto-clear `boring_edge` (ambiguous
  metadata), never hard/review/audit-unavailable. Worst case is a boring-edge
  metadata diff gets auto-cleared instead of going to human review; the LLM
  cannot execute, write, or call anything. Opt-in, off by default. Not a real
  finding — the "prompt injection" framing imagined an agent with tools, not a
  constrained oracle that emits one verdict string.
- **L3** (fixed) — `classify_diff_rules` printed entire `$name_status` instead of
  `$path`. Cosmetic.
- **L4** (fixed) — `write_ref` didn't validate `git rev-parse` success.
- **L5** (fixed) — `source_domains` awk overmatched `source_dir=` variables
  (tightened to `source(_[[:alnum:]_]+)?=\(`). The inverse gap — `source+=()` —
  is the open finding **X**.
- **L6** (fixed) — `python-inline-net` missed aliased imports and raw sockets.
- **L7** (fixed, with J) — No `GIT_CONFIG_GLOBAL` isolation.
- **L8** (fixed) — Temp directories leaked on SIGINT (trap handler added).
- **L9** (fixed) — `git diff --name-status` without `-z` broke on tab-in-filename.

## Pending reconciliation

- **Cohort 2 (C/H/M/L, GitHub #2–#22) + #24–#26:** durable `docs/findings/`
  writeups are filed per-finding as each issue closes (see AGENTS.md "Findings &
  issue tracking"). **All closed issues have docs:** #2 (gh2), #3 (gh3), #4 (gh4),
  #5 (gh5), #6 (gh6), #8 (gh8), #10 (gh10, duplicate of gh3), #11 (gh11), #18 (gh18),
  #19 (gh19), #21 (gh21), #22 (gh22), #24 (W), #25 (Y), #26 (X). Where they overlap
  Cohort 1 (already fixed), the existing doc is cross-linked rather than
  duplicated.
- **Open issues without docs (by design — doc is written on close):** #12,
  #15, #16, #17 (Cohort 2 partial/open); #27–#35 (Cohort 3, all new).
  (Closed 2026-08-04 pending their `ghNN` docs: #7, #9, #13, #14, #20.)
- **L2 (Cohort 1):** rejected as a non-finding (see §Low-severity findings). No
  tracker home needed.
