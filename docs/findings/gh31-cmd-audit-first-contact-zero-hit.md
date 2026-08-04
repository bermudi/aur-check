---
Source: GitHub #31
Status: fixed
Severity: high
---

## Summary

`cmd_audit` (`src/commands.rs`) returned exit code 0 (clean) for a first-time
install whenever the deterministic whole-candidate scan produced zero rule hits
— no human review was prompted. A fresh AUR package carrying payload inside a
source tarball (invisible to the deterministic rules, which only inspect
PKGBUILD/.SRCINFO surfaces) would install unprompted through `yay -S <new-pkg>`.

This was inconsistent with `check_pkg`'s missing-cache gate, which ALWAYS
returns review (2) for first-contact packages (no accepted anchor): retained
AUR history is attacker-rewritable and the deterministic rules cannot see
inside source tarballs, so a clean scan does not establish that a new package
is safe. #4 (gh4) fixed `cmd_audit` to respect hard/review rules (block on
hard, prompt on review) but left the zero-hit first-contact case silent.

## Attack scenario

1. Attacker publishes a new AUR package with a clean PKGBUILD (no dangerous
   commands) but a malicious `source=()` tarball.
2. User runs `yay -S new-evil-pkg`.
3. `cmd_audit` scans the PKGBUILD → 0 hits → returns 0 → stages → proceeds.
4. makepkg downloads and builds the malicious source tarball without the user
   ever seeing the PKGBUILD.

## Fix

`cmd_audit` now detects first-contact packages (no `accepted/<pkgbase>` anchor,
or an empty one) and, when the deterministic scan produces zero rule hits,
stashes whole-candidate evidence under an `audit-first-contact` context and
requires explicit human review via `review_prompt` before staging. This mirrors
`check_pkg`'s missing-cache gate, which always returns 2 for first-contact
packages.

- Hard-rule hits still block (return 1) and never stage.
- Review-rule hits still stash under `audit-review` and prompt.
- First-contact zero-hit now stashes under `audit-first-contact` and prompts.
- `AUR_GATE_ALLOW_REVIEW=1` and interactive consent continue to clear the
  review prompt; only after consent does `cmd_audit` stage.
- `cmd_explain` describes the `audit-first-contact` context.

The trust invariant is unchanged: the anchor can only advance for a commit that
was audited, built under the wrapper's exact-SHA guard, and freshly confirmed
by pacman's root-owned DB. The fix closes the gap where a first-contact
candidate reached the helper without any human review.

## Verification

- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo test --all-targets` — all pass, including new regression
  `audit_first_contact_zero_hit_requires_review`:
  - first-contact zero-hit audit without `AUR_GATE_ALLOW_REVIEW` returns 2,
    stashes `audit-first-contact` evidence, and does NOT stage or append to the
    manifest;
  - the same audit with `AUR_GATE_ALLOW_REVIEW=1` returns 0 and stages the
    exact audited tip.
- `cargo run -- selftest` — 59 passed, 0 failed.
- `bash -n`/`zsh -n assets/wrapper.sh` — clean.
- Existing `explicit_aur_install_yay_audits_builds_accepts` still passes: with
  `AUR_GATE_ALLOW_REVIEW=1` the first-contact audit proceeds, builds, and
  accepts.

## Lesson

A zero-hit deterministic scan is not proof of safety: the rules inspect
PKGBUILD/.SRCINFO surfaces, not source tarballs. First-contact packages have
no prior accepted anchor to diff against, so the whole candidate is unseen and
must be reviewed regardless of rule output. `cmd_audit` and `check_pkg` must
share the same first-contact contract — whole-candidate review is mandatory
when there is no accepted baseline.
