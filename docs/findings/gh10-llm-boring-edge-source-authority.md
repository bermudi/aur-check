# gh10 — LLM boring-edge auto-green should never see source authority anomalies

**Source:** GitHub issue [#10](https://github.com/bermudi/aur-check/issues/10)
(Cohort 2 M1)
**Status:** fixed (duplicate of gh3)
**Severity:** medium
**Duplicate of:** [gh3](gh3-source-uri-fail-open.md) (Cohort 2 C2, #3)

## Summary

If `AUR_SAFE_LLM_AUTO_BORING=1`, the LLM boring-edge verifier can auto-clear
`boring_edge` diffs. Parser-ambiguous source changes (userinfo `@`, scheme
downgrade, VCS type change, `SKIP` checksum, local paths, IPv6/scp-like forms)
are visually subtle and should never be LLM-verifiable — they must be
deterministic review.

## Fix

This issue was resolved by the gh3 fix (closed 2026-07-28, one day before #10
was identified as already-fixed). `_source_line_values_are_safe()` tokenizes
`source=()` and `.SRCINFO` source lines and rejects any URI that is not
`https://` with a dotted hostname and no `@`/`?`/`#`/`[`/`]`/VCS-prefix. Unsafe
source URIs route to `review` (return 2), never `boring_edge`, so the LLM
verifier never sees them. See [gh3](gh3-source-uri-fail-open.md) for the full
mechanism and fix.

## Verification

- `bash -n aur-safe` — clean.
- `shellcheck -s bash aur-safe` — clean.
- `./aur-safe selftest` — all source-URI selftests green: `source-userinfo-bypass`,
  `source-scheme-downgrade`, `source-local-file`, `source-scp-like`,
  `source-ipv6-literal`, `source-vcs-plus-skip`, `source-https-port`,
  `source-variable-in-host`.

## Lesson

When two issues describe the same fix surface from different angles (gh3 from
the fail-open source-URI perspective, #10 from the LLM-shouldn't-see-it
perspective), closing one does not auto-close the other. The staleness review
must check open issues against recently-landed fixes, not just closed issues
against their docs.
