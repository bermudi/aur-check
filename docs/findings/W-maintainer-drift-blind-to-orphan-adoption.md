# Finding W — Maintainer-drift blind to orphan adoption (empty baseline)

**Source:** follow-up red-team review (post A–V, 2026-07-27)
**Tracking:** [#24 (H6)](https://github.com/bermudi/aur-check/issues/24)
**Status:** fixed
**Severity:** high
**Lines:** `classify_diff_rules()` drift guard at aur-safe:1827-1838; comment
short-circuit in `_boring_pkgbuild_added_line_class()` at aur-safe:866;
`maintainer_domains()` at aur-safe:589-595. Asymmetry vs. source-side guard at
aur-safe:1840-1852.

## What happens

The maintainer email-domain drift signal — the impersonation backstop the threat
model leans on for the campaign's step-2 (adopt orphans) and step-4 (impersonate
maintainer) — only fires when **both** sides are non-empty:

```bash
old_d=$(maintainer_domains "$base_ref" "$dir")
new_d=$(maintainer_domains "origin/${AUR_REMOTE_BRANCH}" "$dir")
if [[ -n "$old_d" && -n "$new_d" ]]; then   # ← old_d empty ⇒ whole check skipped
  drift=$(comm -13 <(printf '%s\n' "$old_d") <(printf '%s\n' "$new_d"))
  ...
fi
```

A baseline with no `# Maintainer:` / `# Contributor:` line yields `old_d=""`, so
the set-diff is skipped entirely. The attacker's adoption commit then *adds* a
`# Maintainer: <impersonated> <evil-domain>` line, which is a comment — and
comments are deterministically boring (`grep -Eq '^[[:space:]]*#' … && return 0`
at aur-safe:591). Grep confirms no other structural rule keys on maintainer
lines. Net result: **exit 0, fully clean, no impersonation signal.**

This is an asymmetry, not a deliberate gate: the adjacent source-domain guard at
aur-safe:1566-1567 runs on `if [[ -n "$new_s" ]]` — only the *new* side required.
The maintainer guard was written to require both.

## Why the "narrow precondition" framing understates it

The empty-baseline state is **manufacturable** for *any* package, not just
naturally-maintainer-less ones, via a two-commit launder:

1. **Commit A** — delete the `# Maintainer:` line. Comment-only deletion → no
   added line → not scanned; drift guard: `old_d=[real]`, `new_d=[]` → skipped
   (new side empty). **Clean → accepted.** Baseline is now maintainer-less.
2. **Commit B** — add `# Maintainer: Impersonated <evil-domain>`. Now
   `old_d=[]` → drift skipped; added line is a comment → boring. **Clean →
   accepted.** Impersonation signal defeated.
3. **Commit C** — the payload (still scanned by the rule pipeline on its own
   merits, but now without the "a new person is touching this" heads-up that
   makes a reviewer slow down on a borderline diff).

Both launder commits pass with no review prompt. So this is not a rare-edge
blind spot — it is a deterministic defeat of the impersonation signal with a
trivial attack sequence.

## Impact

No trust-anchor break (the anchor only advances on `accept` after install
confirmation) and no payload execution bypass (commit C is still scanned). The
loss is the **impersonation early-warning signal** the threat model explicitly
relies on for the campaign's primary entry vector. A reviewer is less likely to
scrutinize a borderline version-bump/tarball-swap diff when the "new maintainer
domain" callout is absent.

## Fix

Drop the `-n "$old_d"` requirement so a maintainer domain present at the tip but
absent at the baseline fires review — mirroring the source-side guard:

```bash
if [[ -n "$new_d" ]]; then
  drift=$(comm -13 <(printf '%s\n' "$old_d") <(printf '%s\n' "$new_d"))
  [[ -n "$drift" ]] && { ... review_hits=1 ... }
fi
```

A legitimate first maintainer on a genuinely-unmaintained package also firing
review is correct and costs one review, once (the anchor advances on `accept`).

Optional companion signal (not required to close this finding): flag a
*removal* of all maintainer lines (`old_d` non-empty, `new_d` empty) as review
too, since silently going maintainer-less is itself suspicious and is step 1 of
the launder above. The minimal fix already defeats the launder at step B, so this
is hardening, not a closure requirement.

## Verification

- `bash -n aur-safe` clean; `shellcheck -s bash aur-safe` clean.
- `./aur-safe selftest </dev/null` → 309 passed, 0 failed.
- New selftest fixtures pin both directions:
  - `orphan-adopt-maintainer-drift` — baseline PKGBUILD has no maintainer line;
    tip adds `# Maintainer: Attacker <x@evil-cdn.xyz>` → now classifies `review`
    (was `boring`).
  - `same-maintainer-version-bump` — same `# Maintainer:` on both sides with a
    routine `pkgver` bump → still classifies `boring` (no false positive from the
    loosened guard).
- The remove-then-add launder (Finding H4, #8) is defeated because commit B, once
  the baseline is maintainer-less, now raises `review` for the new maintainer
  domain.
