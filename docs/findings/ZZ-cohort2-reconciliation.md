# Cohort 2 reconciliation — GitHub #2–#22 → local findings

The repo accumulated findings in two largely independent cuts:

- **Cohort 1 (local A–Y)** — the founding pass + 2026-06-26 red-team review +
  follow-ups. Durable writeups live in `docs/findings/`.
- **Cohort 2 (GitHub #2–#22)** — a later review filed directly as GitHub issues
  under a C/H/M/L scheme. Each gets a `ghNN` doc when its issue closes (see
  AGENTS.md "Findings & issue tracking"); **gh2 (#2/C1) is done**.

This map reconciles them: each Cohort 2 item either (a) duplicates a Cohort 1
finding → cross-link, no new doc; (b) extends one → note the extension on the
existing doc; or (c) is genuinely new → a `ghNN` doc when closed.

Status codes checked against `aur-safe` source on 2026-07-27 (not just the issue
text, which predates several Cohort 1 fixes).

## Summary table

| GH # | ID | Title (short)                               | Status in code        | Disposition |
|------|----|---------------------------------------------|-----------------------|-------------|
| #2   | C1 | `+++`-prefix added lines dropped by sed     | **FIXED** → gh2        | done — [gh2](gh2-added-line-extractor-drops-plusplus-lines.md) |
| #3   | C2 | `source_domains` fail-open (userinfo/scheme/IPv6/…) | **PARTIAL** (E covers homographs only) | **new** — needs doc, cross-link E |
| #4   | C3 | `audit` (explicit installs) not blocking    | OPEN                  | **new** — needs doc |
| #5   | H1 | Repo-local git config + ext-diff not isolated | **OPEN** (verified) | **extension of J/L7** — note on J |
| #6   | H2 | Hard rules evadable via quoting/paths       | OPEN (by design)      | **new (architectural)** — needs doc |
| #7   | H3 | `.gitattributes` binary marking blunts scan | OPEN                  | **new** — needs doc |
| #8   | H4 | Deletion-only changes classified boring     | OPEN                  | **new** — needs doc; related to W |
| #9   | H5 | makepkg guard untracked-file check too narrow | OPEN                | **new** — needs doc; extends S |
| #10  | M1 | LLM verifier shouldn't see source-authority anomalies | OPEN      | **new** — needs doc; overlaps L2 |
| #11  | M2 | No global `LC_ALL=C`                        | OPEN                  | **new** — needs doc |
| #12  | M3 | AUR RPC parsing brittle (awk JSON)          | OPEN                  | **new** — needs doc |
| #13  | M4 | `find_baseline_commit` cat-file desync      | OPEN                  | **new** — needs doc |
| #14  | M5 | Terminal escape injection in logs/pager      | OPEN                  | **new** — needs doc |
| #15  | M6 | State-dir permissions / symlink hygiene      | OPEN                  | **new** — needs doc |
| #16  | M7 | Wrapper portability (zsh `read -k`, `--opt=val`) | OPEN            | **new** — needs doc |
| #17  | M8 | DoS via large repos/diffs                    | OPEN                  | **new** — needs doc |
| #18  | L1 | `cmd_scan` coverage partial                  | OPEN (advisory by design) | **duplicate of B** — cross-link |
| #19  | L2 | `_collect_review_details` tab-separated records | OPEN (cosmetic)   | **new (minor)** — needs doc |
| #20  | L3 | `EXPLAIN_MAXLINES` truncation hides payload  | OPEN (advisory)       | **new (minor)** — needs doc |
| #21  | L4 | SHA-1-only trust anchors (no SHA-256 git)    | OPEN (future-proofing) | **new (minor)** — needs doc |
| #22  | L5 | `_valid_pkg_name` rejects uppercase          | **FIXED** → gh22     | done — [gh22](gh22-uppercase-pkg-name-rejected.md) |

**Tally:** 1 duplicate (#18↔B), 1 extension (#5↔J/L7), 1 partial-overlap (#3↔E,
#10↔L2), 18 genuinely new. So ~18 new finding docs are owed under the
findings/-canonical model.

## Verified-against-code notes (the ones worth checking, not just trusting the issue text)

- **#2 (C1) is FIXED.** Was `sed -n '/^+++/!s/^+//p'` in `diff_added` /
  `_diff_added_metadata_file`; an added PKGBUILD line beginning with `++` was
  dropped. Replaced by the hunk-aware `_diff_added_lines()` (aur-safe:313);
  see [gh2](gh2-added-line-extractor-drops-plusplus-lines.md).
- **#5 (H1) is OPEN.** `grep -c 'no-ext-diff'` → 0; `grep -c 'word-diff=none'`
  → 0, across 27 git diff invocations. J/L7 only export
  `GIT_CONFIG_GLOBAL/SYSTEM=/dev/null` (script load) — they do **not** isolate
  repo-local `.git/config` (reachable by a prior malicious build) nor pass
  `--no-ext-diff` (so `diff.external` in `.git/config` can execute). So #5 is a
  true extension of J, not a duplicate.
- **#3 (C2) is PARTIALLY open.** The homograph axis is covered by Finding E
  (`_source_line_nonascii` forces review on non-ASCII bytes in source lines).
  The other eight axes (userinfo `@`, scheme downgrade, local paths, scp-like,
  IPv6 literals, VCS-type change, `SKIP` checksum introduction, fragment/query)
  are unhandled — no `@` rejection exists in source classification. So C2 is
  mostly-new, with E as a documented partial mitigation.
- **#18 (L1) duplicates B.** Both flag `cmd_scan` as an ad-hoc third pipeline
  with incomplete coverage. B is the canonical writeup; #18 should close as a
  duplicate pointing at `docs/findings/B-cmd-scan-adhoc-pipeline.md`.

## Notable relationships

- **#8 (H4) ↔ W:** H4 is the deletion half (removing maintainer/integrity
  lines), W is the add-to-empty-baseline half. The two-commit launder in W's
  doc uses H4's mechanism for step A. Both need fixing.
- **#9 (H5) ↔ S:** H5 extends S's makepkg guard — the guard checks a narrow
  allowlist of untracked filenames (`PKGBUILD .SRCINFO *.install *.sh`) and
  misses `.gitattributes`, `.gitmodules`, submodules, uppercase extensions.
- **#10 (M1) ↔ L2 (Cohort 1):** both concern the LLM boring-edge verifier
  seeing things it shouldn't. M1 is source-authority anomalies; L2 is prompt
  injection broadly. Likely the same fix surface.
- **#4 (C3) ↔ Y:** adjacent advisory-mode weaknesses. C3 = audit-not-blocking
  on new installs; Y = accept's version-only binding on updates.

## Pending work

1. **#2 (C1) is done** → [gh2](gh2-added-line-extractor-drops-plusplus-lines.md).
   Remaining ~17 new findings get a `ghNN` doc as each issue closes (naming:
   `gh<issue-number>-<slug>.md`; legacy A–Y keep their letters).
2. Cross-link the three relationships above (#18→B duplicate; #5→J extension;
   #3→E partial).
3. Each new doc cites its GitHub issue; thin the issue body to a pointer once
   its doc exists.
4. Update `docs/findings/README.md` catalog; retire the "Pending reconciliation"
   note once all of #3–#22 are filed.
