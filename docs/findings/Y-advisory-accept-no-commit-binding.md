# Finding Y — Advisory (non-wrapper) `accept` has no commit-identity binding

**Source:** follow-up red-team review (post A–V, 2026-07-27)
**Tracking:** [#25 (M9)](https://github.com/bermudi/aur-gate/issues/25)
**Status:** fixed
**Severity:** medium
**Lines:** `_installed_matches()` at aur-gate:1149; `_cmd_accept_locked()` call
at aur-gate:~2310. Refines [Finding D](./D-accept-version-vs-sha.md); depends on
[Finding S](./S-helper-build-toctou.md)'s makepkg guard for the safe path.

## What happens

`_installed_matches()` confirms an install by **pkgbase + version string
(epoch:pkgver-pkgrel) + freshness**, read from the *staged* commit's `.SRCINFO`
and compared against `pacman -Q`. It does **not** bind the installed artifact to
the staged commit's SHA:

```bash
want="${pkgver}-${pkgrel}"
[[ -n "$epoch" && "$epoch" != 0 ]] && want="${epoch}:${want}"
...
[[ "$iver" == "$want" ]] || continue          # version match, not SHA match
[[ "$built_at" -ge "$not_before" ]] || continue
```

So `accept` will promote the staged (audited) commit X as the trust anchor even
when a *different* commit X′ with the same pkgver was what the helper fetched,
built, and installed.

## Why this is a refinement of D, not a duplicate

[Finding D](./D-accept-version-vs-sha.md) closed this exact behavior as "working
as designed," with the defense: *the next gate catches the delta* —
`git diff accepted(X)..origin/master` surfaces X→X′ and `scan_diff_rules` scans
it. That defense is correct **for post-hoc detection**, and the accepted-ref-
means-audited-not-installed invariant is intentionally preserved (requiring the
installed SHA to equal the staged SHA would reject benign routine race windows
where the helper fetched a later commit).

The gap D's rationale does **not** cover: build-time payload execution. The
defense assumes the damage is caught on the *next* update — but a malicious
`.install` hook / sourced PKGBUILD runs at `makepkg`/install time, before any
"next gate." Preventing that is exactly what [Finding S](./S-helper-build-toctou.md)'s
makepkg guard does: it requires the helper checkout HEAD to equal the staged SHA
and a fresh build immediately before PKGBUILD execution.

**That guard is wrapper-only.** It is injected by `aur-gate wrapper` and only
exists when the user has installed the wrapper function. Anyone using aur-gate
advisorily (`gate` / `check` + a manual `yay`/`paru`, without the wrapper) gets:

1. `gate` audits and stages commit X.
2. Manual helper run fetches X′ (same pkgver, malicious) in the window and
   builds+installs it — **payload executes at build time**.
3. `accept` sees version(X′ installed) == version(X staged) → match → promotes X
   as anchor.
4. Next gate: if X′ is still at `origin/master`, diff X..X′ surfaces it (too
   late — payload already ran). If the attacker force-pushed X′ away, the diff is
   X..X (clean) and the malicious install runs undetected until the next legit
   update.

## Impact

Confined to advisory / non-wrapper use, which is explicitly the weaker
deployment model. Under the wrapper, S's makepkg guard closes the build-time
window entirely. The concern is that the **assumption** — "the version-only
`accept` binding is only safe under the wrapper's makepkg guard" — is implied by
S's threat model but not called out anywhere as a standalone precondition, so a
user can reasonably believe `gate` + `check` + `accept` without the wrapper gives
them the full TOCTOU guarantee when it does not.

## Fix

Two options, in increasing effort:

1. **Document the assumption (minimum).** State explicitly in the design-ledger
   (§"Why staging") and in the `gate`/`check`/`accept` help text that, without
   the wrapper, `accept`'s install confirmation is version-equivalence only and
   does not prevent a same-version/different-commit build from executing in the
   fetch window; the full TOCTOU guarantee requires the wrapper's Finding-S
   makepkg guard. This makes D's "working as designed" conditional on the
   deployment mode, which it currently is not.

2. **Add a non-wrapper commit-binding (optional, design tradeoff).** Record the
   helper cache HEAD observed at `gate` time alongside the staged SHA, and have
   `accept` warn/reject when the current helper HEAD differs from the staged SHA
   *and* no freshness window explains it. This does not prevent the payload from
   executing (the build already happened by `accept`), but it stops the anchor
   from advancing to a build that was not the audited commit, so the next gate
   surfaces the delta instead of going clean. This is the binding D explicitly
   rejected to avoid false rejections on benign races — so if pursued, it must be
   advisory (warn) rather than fail-closed, or scoped to "HEAD moved backward /
   to a non-descendant," to avoid reintroducing D's false-rejection problem.

## Resolution

Implemented option 1 (documentation). `docs/design-ledger.md` §"Why staging" now
explicitly states that `accept` confirms installs by version + freshness, not by
installed commit SHA, and that the build-time `HEAD == staged SHA` guard is
injected **only** by the generated wrapper. `aur-gate` usage output now carries
the same advisory note under a `notes:` section. This makes the deployment
assumption explicit: the full build-time TOCTOU guarantee requires the wrapper;
direct `gate`/`check` + manual `yay`/`paru` usage provides post-build delta
detection through the next gate, not build-time protection.

## Verification

- `docs/design-ledger.md` §"Why staging" renders the version-equivalence
  assumption and the wrapper-only build-time guard clearly.
- `aur-gate --help` / `aur-gate -h` prints the advisory note that the wrapper is
  required for the full build-time TOCTOU guarantee.
- The wrapper path remains described as the full-protection deployment in both
  documents.
- `bash -n aur-gate` clean; `./aur-gate selftest` all green.
