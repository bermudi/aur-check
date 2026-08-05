# Cohort 2 reconciliation — GitHub #2–#22 → local findings

The repo accumulated findings in two largely independent cuts:

- **Cohort 1 (local A–Y)** — the founding pass + 2026-06-26 red-team review +
  follow-ups. Durable writeups live in `docs/findings/`.
- **Cohort 2 (GitHub #2–#22) + #24–#26** — a later review filed directly as
  GitHub issues under a C/H/M/L scheme. Each gets a `ghNN` doc when its issue
  closes (see AGENTS.md "Findings & issue tracking"); **all closed issues now
  have docs** (gh2, gh3, gh4, gh5, gh6, gh8, gh11, gh18, gh19, gh21, gh22;
  #24→W, #25→Y, #26→X cross-linked to existing Cohort 1 docs).

This map reconciles them: each Cohort 2 item either (a) duplicates a Cohort 1
finding → cross-link, no new doc; (b) extends one → note the extension on the
existing doc; or (c) is genuinely new → a `ghNN` doc when closed.

Status codes in the original table were checked against the now-retired Bash
source on 2026-07-27. They are historical, not the current Rust release status.

## Rust migration disposition (2026-08-04, revised 2026-08-04 on issue re-evaluation)

The Rust-primary migration resolves the mechanisms in #7 (forced text/NUL-safe
evidence), #9 (all untracked files + regular-blob-only trees, submodules
rejected structurally, tracked `.gitattributes` neutralized by #7's `--text` +
`core.attributesFile=`), #13 (size-framed batch parsing), #14 (escaped
terminal/pager/provider output), and #20 (head-and-tail advisory context with
an explicit omission marker). These five issues were **closed on 2026-08-04**
after code verification; durable `ghNN` docs are filed as each closes per
AGENTS.md.

**Partially resolved (still open):**
- **#12 (M3)** — typed JSON RPC, malformed-output fail-closed, and split-package
  resolution are fixed (`src/rpc.rs`), but `validate_aur_url`
  (`src/config.rs:146-156`) accepts `http://` as well as `https://`; the issue's
  explicit "enforce HTTPS" ask is not met. Open for a maintainer call (reject
  `http://` except under a test override, or document HTTP-mirror intent).
- **#15 (M6)** — state directories are `0700`, non-symlink, current-user-owned
  (`src/state.rs:161-184`), but **trust files (`accepted/`, `staged/`) are read
  via `fs::read_to_string` without `O_NOFOLLOW`** (`state.rs:320-323`;
  `commands.rs:340-348,728-730`; `engine.rs:304-308`), and the manifest append
  path (`state.rs:386-390`) also lacks it. The earlier claim of "no-follow trust
  files" in this doc was an overclaim and is corrected here.
- **#16 (M7)** — zsh `read -n` portability is fixed (Rust owns interaction;
  wrapper uses only POSIX `read -r`) and Bash/Zsh transaction tests exist, but
  the wrapper classifier does not handle `--opt=value` forms
  (`assets/wrapper.sh:66-72`), and helper `-Qua` parsing still assumes the first
  whitespace field is the package name without `valid_pkg_name()` validation
  (`src/commands.rs:87-125`).

**Still applicable:** #17 (M8) — no git-operation timeouts, no diff/file-count
limits on the main gate pipeline, full-history clones, and unbounded
`rev-list`/`cat-file` walks. Remains a fail-closed availability-hardening item.

## Summary table

| GH # | ID | Title (short)                               | Status in code        | Disposition |
|------|----|---------------------------------------------|-----------------------|-------------|
| #2   | C1 | `+++`-prefix added lines dropped by sed     | **FIXED** → gh2        | done — [gh2](gh2-added-line-extractor-drops-plusplus-lines.md) |
| #3   | C2 | `source_domains` fail-open (userinfo/scheme/IPv6/…) | **FIXED** → [gh3](gh3-source-uri-fail-open.md) | done — cross-links E |
| #4   | C3 | `audit` (explicit installs) not blocking    | **FIXED** → [gh4](gh4-cmd-audit-advisory-only.md) | done |
| #5   | H1 | Repo-local git config + ext-diff not isolated | **FIXED** → [gh5](gh5-git-invocation-hardening.md) | done — extension of J/L7 |
| #6   | H2 | Hard rules evadable via quoting/paths       | **FIXED** → [gh6](gh6-hard-rules-brittle.md) | done — architectural (structural classifier is the backstop) |
| #7   | H3 | `.gitattributes` binary marking blunts scan | **FIXED** → closed 2026-08-04 | **new** — needs doc |
| #8   | H4 | Deletion-only changes classified boring     | **FIXED** → [gh8](gh8-deletion-only-changes-classified-boring.md) | done — related to W |
| #9   | H5 | makepkg guard untracked-file check too narrow | **FIXED** → closed 2026-08-04 | **new** — needs doc; extends S |
| #10  | M1 | LLM verifier shouldn't see source-authority anomalies | **FIXED** → [gh10](gh10-llm-boring-edge-source-authority.md) (duplicate of gh3) | done |
| #11  | M2 | No global `LC_ALL=C`                        | **FIXED** → [gh11](gh11-force-c-locale.md) | done |
| #12  | M3 | AUR RPC parsing brittle (awk JSON)          | PARTIAL (HTTPS not enforced) | **new** — needs doc |
| #13  | M4 | `find_baseline_commit` cat-file desync      | **FIXED** → closed 2026-08-04 | **new** — needs doc |
| #14  | M5 | Terminal escape injection in logs/pager      | **FIXED** → closed 2026-08-04 | **new** — needs doc |
| #15  | M6 | State-dir permissions / symlink hygiene      | PARTIAL (trust files lack `O_NOFOLLOW`) | **new** — needs doc |
| #16  | M7 | Wrapper portability (zsh `read -k`, `--opt=val`) | PARTIAL (`--opt=val` unhandled) | **new** — needs doc |
| #17  | M8 | DoS via large repos/diffs                    | OPEN (availability hardening) | **new** — needs doc |
| #18  | L1 | `cmd_scan` coverage partial                  | **FIXED** → [gh18](gh18-cmd-scan-partial-coverage.md) | done — duplicate of B |
| #19  | L2 | `_collect_review_details` tab-separated records | **FIXED** → gh19    | done — [gh19](gh19-collect-review-details-tab-separated.md) |
| #20  | L3 | `EXPLAIN_MAXLINES` truncation hides payload  | **FIXED** → closed 2026-08-04 | **new (minor)** — needs doc |
| #21  | L4 | SHA-1-only trust anchors (no SHA-256 git)    | **FIXED** → [gh21](gh21-sha256-trust-anchors.md) | done |
| #22  | L5 | `_valid_pkg_name` rejects uppercase          | **FIXED** → gh22     | done — [gh22](gh22-uppercase-pkg-name-rejected.md) |

**Tally:** 20 closed issues (#2–#7, #9, #10–#11, #13–#14, #18–#19, #20–#22,
#24–#26). 15 of those have durable docs (gh2, gh3, gh4, gh5, gh6, gh8, gh10,
gh11, gh18, gh19, gh21, gh22; #24→W, #25→Y, #26→X); the 5 closed on 2026-08-04
(#7, #9, #13, #14, #20) still need their `ghNN` docs filed. 4 open issues
remain: #12 (partial — HTTPS not enforced), #15 (partial — trust files lack
`O_NOFOLLOW`), #16 (partial — `--opt=value` unhandled), #17 (open — DoS
availability hardening). 2 duplicates (#10↔gh3, #18↔B), 1 extension
(#5↔J/L7), 1 partial-overlap (#3↔E). Cohort 1 L2 is rejected (non-finding).

## Verified-against-code notes (the ones worth checking, not just trusting the issue text)

- **#2 (C1) is FIXED.** Was `sed -n '/^+++/!s/^+//p'` in `diff_added` /
  `_diff_added_metadata_file`; an added PKGBUILD line beginning with `++` was
  dropped. Replaced by the hunk-aware `_diff_added_lines()` (aur-gate:313);
  see [gh2](gh2-added-line-extractor-drops-plusplus-lines.md).
- **#5 (H1) is FIXED (closed).** The `git()` wrapper (`aur-gate:~226-365`)
  forces `--no-ext-diff`, `--no-textconv`, `--word-diff=none`, and a short
  list of `-c` overrides on every call; the environment is sanitized at load;
  and `_git_local_config_is_safe()` fail-closes on repo-local `.git/config`
  keys that can alter output, redirect fetches, or execute code. Details and
  verification are in [gh5](gh5-git-invocation-hardening.md).
- **#3 (C2) is FIXED.** All nine source-URI axes (userinfo `@`, scheme
  downgrade, local paths, scp-like, IPv6 literals, VCS-type change, `SKIP`
  checksum introduction, fragment/query, plus the homograph axis from Finding E)
  are now handled. Details and verification are in
  [gh3](gh3-source-uri-fail-open.md); E is cross-linked as a partial mitigation
  folded into the full fix.
- **#18 (L1) is FIXED.** Duplicates B — both flag `cmd_scan` as an ad-hoc third
  pipeline with incomplete coverage. B is the canonical writeup; #18 closed as a
  duplicate pointing at `docs/findings/B-cmd-scan-adhoc-pipeline.md`. See
  [gh18](gh18-cmd-scan-partial-coverage.md).
- **#19 (L2) is FIXED.** `_collect_review_details()` now emits NUL-separated
  records (`raw text\0formatted detail`) instead of tab-separated; the caller
  reads `d_text` with `read -d ''` and `d_fmt` with a normal `read`. This
  preserves literal tabs in added PKGBUILD lines. Details are in
  [gh19](gh19-collect-review-details-tab-separated.md).
- **#8 (H4) is FIXED.** Removed PKGBUILD security-relevant fields are now
  tracked. `classify_diff_rules()` extracts removed metadata lines with
  `_diff_removed_metadata_file()`, then for each removed assignment line checks
  whether the candidate still contains the same field. Deletion of
  `validpgpkeys`, `*sums`, `source`, dependency arrays, `install`/`noextract`/
  `options`/`backup`, or the last maintainer/contributor comment routes to
  `review`; value changes and reflows that keep the field clear normally.
  See [gh8](gh8-deletion-only-changes-classified-boring.md).

## Notable relationships

- **#8 (H4) ↔ W:** H4 is the deletion half (removing maintainer/integrity
  lines), W is the add-to-empty-baseline half. The two-commit launder in W's
  doc uses H4's mechanism for step A. Both W (#24) and H4 (#8) are now fixed.
- **#9 (H5) ↔ S:** H5 extends S's makepkg guard. The Bash guard checked a
  narrow allowlist of untracked filenames (`PKGBUILD .SRCINFO *.install *.sh`)
  and missed `.gitattributes`, `.gitmodules`, submodules, uppercase extensions.
  The Rust guard rejects **all** untracked files and requires every tree leaf
  to be a regular blob (submodules/gitlinks and symlinks rejected
  structurally); tracked `.gitattributes` is neutralized by #7's `--text` +
  `core.attributesFile=`. Closed 2026-08-04.
- **#10 (M1) ↔ L2 (Cohort 1):** M1 was a real concern — source-authority
  anomalies must never reach the boring_edge bucket (deterministic routing).
  It is now fixed (duplicate of gh3): `_source_line_values_are_safe()` routes
  unsafe source URIs to `review` before the LLM boundary. L2 ("prompt
  injection") was thought to overlap but is rejected as a non-finding: the
  verifier has no tools and can only clear boring_edge metadata diffs.
- **#4 (C3) ↔ Y:** adjacent advisory-mode weaknesses. C3 = audit-not-blocking
  on new installs; Y = accept's version-only binding on updates.

## Pending work

All closed issues have their durable docs filed **except** the 5 closed on
2026-08-04 (#7, #9, #13, #14, #20), which still need their `ghNN` docs written
per AGENTS.md "Findings & issue tracking." The cross-links called out above are
in place (#10→gh3 duplicate, #18→B duplicate, #5→J extension, #3→E partial).

**Open issues (4):**
- **#12 (M3)** — partial: typed JSON RPC fixed, but `AUR_URL` HTTPS-only
  enforcement is not (HTTP accepted). Awaiting a maintainer call.
- **#15 (M6)** — partial: state dirs hardened, but trust-file reads
  (`accepted/`, `staged/`) lack `O_NOFOLLOW`; the earlier "no-follow trust
  files" claim in this doc was an overclaim, corrected above.
- **#16 (M7)** — partial: zsh interaction fixed, but `--opt=value` forms are
  unhandled in the wrapper classifier and `-Qua` parsing is unvalidated.
- **#17 (M8)** — open: DoS availability hardening (git timeouts, diff/file
  limits, `--single-branch`/blob filtering, bounded `rev-list`).

Cohort 1 L2 (LLM "prompt injection") is rejected as a non-finding — the
verifier runs with `--no-tools --no-session` and can only auto-clear
`boring_edge` metadata diffs, never hard/review; no tracker home needed.

## Cohort 3 — 2026-08-04 (#27–#35)

A third review (two adversarial passes: qwen3.8-max-preview on workflow/policy
and qwen3.8-max on Git internals/shell runtime) was verified against the Rust
code before filing. 9 genuinely new issues were filed; findings already
resolved by the Rust migration or existing fixes were not filed.

| GH # | ID | Title (short) | Severity | Extends |
|------|----|---------------|----------|---------|
| #27  | H7 | Git replace refs split auditor/builder views; grafts rewrite ancestry — **fixed** ([gh27](gh27-git-replace-refs-grafts.md)) | high | — |
| #28  | H8 | Git `http.*` local config escapes safety check (proxy/CA MITM) | high | #5 |
| #29  | M10 | Git `includeIf.*` bypasses `include.` prefix check | medium | #5 |
| #30  | H9 | Wrapper dispatch misses `--hookdir`/`--cachedir`/`--gpgdir`/`--logfile` | high | — |
| #31  | H10 | `cmd_audit` auto-proceeds on first-time install with zero rule hits | high | #4 |
| #32  | M11 | Wrapper resolves aur-gate/pacman/flock via PATH at runtime | medium | — |
| #33  | M12 | Zero-diff cached update exits clean without staging | medium | — |
| #34  | M13 | Predictable PID-based temp filename in `stash_flag` | medium | — |
| #35  | L7 | Force-pushed history permanent lockout without auto-recovery | low | — |

**Findings verified as already resolved (not filed):** binary-update permanent
DoS (Rust routes non-execution-surface NUL to review); build-time anchor
poisoning (wrapper strips lock/staging capabilities before build);
cmd_audit lockless (wrapper holds transaction lock); accept read-then-rename
TOCTOU (entire accept under lock); helper config file precedence (explicit CLI
flags override config files); config/env mismatch (wrapper delegates to Rust
binary for state-dir resolution); rule severity asymmetry (intentional,
documented in threat model); pacman -U ungated (documented threat-model
boundary); line-continuation evasion (full PKGBUILD lexical analysis detects
continuations as ambiguous context).
