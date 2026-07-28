# Finding X — `source+=()` append invisible to source-domain drift

**Source:** follow-up red-team review (post A–V, 2026-07-27)
**Tracking:** [#26 (L6)](https://github.com/bermudi/aur-check/issues/26)
**Status:** open
**Severity:** low
**Lines:** `source_domains()` awk anchor at aur-safe:422. Same pattern family at
aur-safe:509, 758, 760, 770, 785 (contextual array helpers).

## What happens

`source_domains()` only enters array-tracking mode on lines matching
`source(_[[:alnum:]_]+)?=\(`, which does **not** match the append form
`source+=(`:

```bash
git -C "$dir" show "${ref}:PKGBUILD" 2>/dev/null \
  | awk '/^[[:space:]]*source(_[[:alnum:]_]+)?=\(/ { in_src=1 } in_src { print; if (/\)/) in_src=0 }' \
  | grep -aoE '://[a-zA-Z0-9._-]+' | ...
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
2. `_source_line_nonascii()` shape-2 (aur-safe:462) matches **any** added line
   containing `://` with a byte ≥ 0x80, so IDN homographs on an appended source
   URL are still forced to review regardless of the `+=` syntax.

The lost signal is the specific `[source-domain-new]` tag — i.e. the structural
"tarball swapped to a new domain" callout. The host is still visible in the diff
the reviewer consents to; it just isn't singled out.

## Fix

Add the optional `+` to the drift anchor (the load-bearing one for this finding):

```awk
/^[[:space:]]*source(_[[:alnum:]_]+)?\+?=\(/ { in_src=1 }
```

The same `+?` can be applied to the contextual array helpers at aur-safe:509,
758, 760, 770, 785 for consistency and to enable boring-edge classification of
appended-array members, but those are not required to close this finding — they
currently (and correctly) leave `source+=(...)` as review.

## Verification

- Selftest fixture (proposed name from the review): `h2-source-append-new-host`
  — a `source+=("https://evil-new-host.xyz/x")` append must list
  `evil-new-host.xyz` in `source_domains` on the tip (currently omitted).
- Confirm no false positive: a `source+=` append reusing an already-present host
  must not fire `[source-domain-new]` (version bump on the same host must stay
  clean — the whole point of the set-diff).
- `bash -n aur-safe` clean; `./aur-safe selftest` all green.
