---
Source: GitHub #4
Status: fixed
Severity: critical
---

## Summary

`cmd_audit()` cloned a new-install candidate, ran `_scan_whole_pkg()` to print
hard and review findings, and then unconditionally returned 0 as long as the
clone/read succeeded. The generated wrapper runs each explicit new install
through `aur-gate audit "$pkg" || exit $?`, so a hard-rule hit only printed a
warning and the install continued.

Example: a malicious PKGBUILD with `build() { npm install crypto-javascript; }`
would be flagged by the `npm` rule but `cmd_audit` returned 0; `yay -S` then
built and installed the package. With `AUR_GATE_STAGING=1` the audit even
staged the package after a hard hit, so a later `accept` could promote the trust
anchor for an unaudited install.

## Fix

- `cmd_audit` is now a gate with the same exit-code contract as the rest of the
trust path: 0 for clean or consented review, 1 for hard-block / clone-read
failure, 2 for review that still needs consent.
- Clone/read failures return 1 and never stage.
- Hard-rule hits stash whole-candidate evidence and return 1; they never reach
`_stage_scan_if_gating`.
- Review-rule hits stash whole-candidate evidence and call `review_prompt` for
interactive consent (or honor `AUR_GATE_ALLOW_REVIEW=1` non-interactively).
Only after consent does `cmd_audit` stage.
- Added an `audit-review` context to `cmd_explain` and updated design-ledger /
wrapper comments to remove the outdated "advisory" language.

This preserves the finding-1.2 TOCTOU invariant: the trust anchor can only
advance for a commit that was actually audited and then confirmed installed by
pacman.

## Verification

- `bash -n aur-gate` — clean.
- `shellcheck -s bash aur-gate` — clean (SC2016/SC2001 excluded in `.shellcheckrc`).
- `./aur-gate selftest` — 300 passed, 0 failed, including new regression fixtures:
  - `audit-hard-blocks` / `audit-hard-no-stage` (npm in `build()` returns 1
    without a staged ref or manifest entry)
  - `audit-hard-stashes-evidence` (the blocked whole candidate is retained with
    `audit-hard` context)
  - `audit-review-returns-2` / `audit-review-no-stage-without-consent` (pip in
    `build()` returns 2 without a staged ref or manifest entry)
  - `audit-review-stashes-evidence` (the consentable candidate is retained with
    `audit-review` context)
  - `audit-review-allow-stages` (`AUR_GATE_ALLOW_REVIEW=1` lets a review hit
    stage and return 0).

## Lesson

A subcommand consumed by the wrapper as a gate must return the same 0/1/2
contract as `check_pkg`/`cmd_gate`. "Advisory" output that exits 0 silently
disables the wrapper's `|| exit $?` guard and lets hard-blocked packages reach
pacman. Staging must always be gated by the scan result and, for review hits,
by explicit consent.
