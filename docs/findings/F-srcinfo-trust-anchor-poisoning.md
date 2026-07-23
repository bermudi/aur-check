# Finding F — Trust-anchor poisoning via attacker-crafted `.SRCINFO`

**Source:** glm-5.1 red-team review, session `019f0517-d737-732f-b8d6-6ae4c3208309`  
**Status:** fixed (2026-07-23)
**Severity:** critical  
**Lines:** `_pacman_local_record()`, `_installed_matches()`, `cmd_accept()`

## What happens

`_installed_matches` parses `pkgname`/`pkgver`/`pkgrel`/`epoch` from `.SRCINFO`
at the attacker's commit SHA — entirely attacker-controlled text. `makepkg`
builds from `PKGBUILD`, not `.SRCINFO`; the two are independent text files
committed by the maintainer. The attacker can lie in `.SRCINFO` to claim
arbitrary installed-system package name and version.

**End-to-end attack:**

1. Attacker maintains AUR pkg P. Pushes malicious commit X to AUR/master.
2. X's `PKGBUILD` contains a payload that trips no hard rule (e.g.
   `build() { python3 -c "import socket,subprocess,os;…" }`). Diff classifier:
   "build logic changed" → exit 2 (review).
3. X's `.SRCINFO` is crafted to lie: `pkgname = glibc`, `pkgver = 2.41`,
   `pkgrel = 1`, no epoch — exactly matches the system-glibc on a generic Arch
   system. PKGBUILD stays `pkgname=P pkgver=99 pkgrel=1`.
4. User runs gate. Exit 2 review; user clicks `y` (or `AUR_SAFE_ALLOW_REVIEW=1`).
5. Helper fetches X, builds P (`pkgname=P pkgver=99-1` by PKGBUILD — but
   `build()` runs the malicious shell → exfiltration already happened at
   build time).
6. Wrapper calls `aur-safe accept`.
7. `_installed_matches(cache_clone, X)`:
   - reads `X:.SRCINFO` → pkgname=glibc, want=2.41-1
   - `_pacman_query glibc` → "glibc 2.41-1"
   - match → `accepted/P := X`.
8. All future audit deltas of P are X..origin/master. The attacker's X payload
   is now baseline context — treated as known-good, never re-flagged.

This is exactly the original-bug class the trust-anchor design was supposed to
close ("Any change that lets the anchor advance to an unaudited commit reopens
the original bug this project was built to fix"). The `.SRCINFO` pkgname/version
are attacker-controlled and not verified against what `PKGBUILD` actually built.

## Exploitability

**High.** Requires the attacker to ship both a malicious PKGBUILD and a
mismatched `.SRCINFO` — trivial (both are text files committed by the same
maintainer). The only gate is the diff classifier catching non-boring PKGBUILD
changes → review exit 2, which users can consent to.

## Fix

Implemented without executing or trying to fully parse PKGBUILD shell.
`.SRCINFO` remains a candidate claim, but confirmation now requires a
root-owned pacman local-DB record whose `%BASE%` equals the staged trust-anchor
key, whose version matches, and whose `%BUILDDATE%` and `%INSTALLDATE%` are no
older than the staged ref. The candidate's column-0 `pkgbase` must also equal
the staged key and malformed metadata has no pkgname fallback. Thus a claimed
`glibc` record binds to base `glibc`, not attacker package P, and cannot promote
P. Freshness also rejects a pre-existing same-version install after a failed
build. `epoch=0` is normalized to no prefix.

## Verification

Selftests cover foreign-pkgname rejection, pkgbase mismatch via the trusted
local record, stale build/install timestamps, split members, missing/malformed
metadata, and epoch zero. Production `_pacman_local_record` was checked against
a real installed AUR package's local DB record.
