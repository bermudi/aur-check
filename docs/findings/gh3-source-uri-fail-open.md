# gh3 — Source URI validation is fail-open and can silently accept dangerous source changes

**Source:** GitHub issue #3 (Cohort 2 C2, 2026-07-27)  
**Status:** fixed (2026-07-28)  
**Severity:** critical  
**Code:** `_source_line_values_are_safe()`, `_pkgbuild_safe_array_literal_line()`, `_boring_srcinfo_added_line_class()`, `source_domains()` in `aur-gate`

## Summary

The diff gate classified `source=()` and `.SRCINFO` `source = ...` lines as
inert metadata too readily. The previous logic proved only the *lexical shape* of
the array; it did not validate the source URI. Combined with a host-extractor
(`source_domains()`) that stopped at the first `:`/`@` and only recognized
`://`, the whole path was fail-open for several exploit classes:

- **Userinfo host bypass** — `https://example.com@evil.example/foo.tar` looked
  like a same-host `example.com` change, but the real authority is `evil.example`.
- **Scheme downgrade** — `http://example.com/foo.tar` has no `https` guarantee.
- **Local file source** — `source=(/dev/null)` has no `://`, so it slipped past
  the host extractor entirely.
- **IPv6 literal** — `https://[::1]/payload.tar.gz` was invisible to the ASCII
  hostname extractor.
- **VCS transport change + `SKIP` checksum** — `git+https://...#commit=...`
  swapped a tarball for an unverified VCS checkout.
- **Port change** — `https://example.com:8443/...` changed the authority without
  changing the extracted host.
- **scp-like remote URLs** — `git@evil.example:repo.git` has no `://` and was
  ignored.

Because the per-line classifier allowed these shapes through as `boring_edge`,
the optional LLM verifier could auto-clear them. That is a deterministic gate
letting silent source swaps through.

## Fix

A new fail-closed source policy is enforced **before** the per-line classifier
can declare a source line `boring`:

- `_source_line_values_are_safe()` tokenizes one `source=()` or `.SRCINFO`
  `source = ...` line and rejects any source value that is not:
  - `https://` (or a `filename::https://` alias), and
  - a dotted, non-IPv4 hostname, and
  - free of `@` (userinfo), `?` or `#` (query/fragment), `[`/`]` (IPv6 literals),
    and any other scheme/VCS prefix (`git+https`, `http`, `ftp`, `file`, `data`,
    `ext::`, etc.).
- It is called from `_pkgbuild_safe_array_literal_line()` for `source` arrays and
  from `_boring_srcinfo_added_line_class()` for `.SRCINFO` source lines.
- `source_domains()` was also hardened: it now strips `userinfo@` and parses
  bracketed IPv6 literals, so the set-diff signal is not tricked by `a@b` or
  `[::1]`. It remains a *host-drift* signal; the per-line check is the primary
  fail-closed enforcement.

The fix also recognizes that an unquoted/quoted **local filename** (e.g.
`"foo-1.1.tar.gz"`) is not a proven safe source. The previous Finding P
classification that treated such filenames as `boring_edge` is reclassified as
part of this fail-open surface; local paths now go to `review`. Only
`filename::https://...` aliases are still accepted, because the remote URL after
`::` is checked by the same policy.

## Verification

- `bash -n aur-gate` — clean.
- `shellcheck -s bash aur-gate` — clean (SC2016/SC2001 excluded via `.shellcheckrc`).
- `./aur-gate selftest` — **292/292**.
- New regression fixtures in `run_selftest` pin each exploit class plus negative
  controls:
  - `source-userinfo-bypass`
  - `source-scheme-downgrade`
  - `source-local-file`
  - `source-scp-like`
  - `source-ipv6-literal`
  - `source-vcs-plus-skip`
  - `source-https-port`
  - `source-variable-in-host`
  - `source-filename-alias-boring` (negative control)
- Existing source-related fixtures remain green, including version-only path
  bumps (`same-host-source`, `multiline-source`, `source-simple-variable-boring`,
  `opera` reflow, `srcinfo-arch-source-boring`).

## Lesson

A source line is not "metadata" just because it is an array literal. The
authority, scheme, port, and transport semantics matter as much as the host
domain. Positive-grammar validation of shell syntax must be paired with
positive-grammar validation of the *data* being classified, or the classifier
will silently accept attacker-chosen source changes. Set-diffs and host-only
extractors are too coarse for source URLs; the parser must fail closed on any
source value it cannot prove safe.