# Finding U — PKGBUILD source-time execution auto-cleared as metadata

**Source:** opera-developer false-positive investigation + independent trust-path review, 2026-07-27  
**Status:** fixed in working tree (2026-07-27)  
**Severity:** critical  
**Surface:** `diff_added`, `classify_diff_rules`, the former shared `_boring_added_line_class`, contextual array helpers

## What happened

The deterministic boring classifier erased the changed file's identity and fed
raw added lines from both `.SRCINFO` and `PKGBUILD` into one allowlist. That
collapsed two different trust domains:

- `.SRCINFO` is attacker-authored **data**; and
- `PKGBUILD` is attacker-authored **Bash executed by makepkg**.

Several permissive regular expressions then recognized executable PKGBUILD
syntax as inert metadata. Confirmed classes included:

1. shell substitution in `pkgver=` and one-line metadata arrays;
2. command/operator text after an assignment or an early array closer;
3. Bash 5.3 alternate command substitution and indirect expansion forms not
   covered by a `$(`/backtick blacklist;
4. an apparently inert added line whose meaning changed because an unchanged
   earlier line opened a quote, heredoc, or backslash continuation;
5. PKGBUILD commands shaped like `.SRCINFO` (`source = ...`, dependency data),
   including contextual `.SRCINFO` helpers invoked before PKGBUILD checks;
6. a whitespace-only `.SRCINFO` exception masking an identical executable
   PKGBUILD line; and
7. NUL-bearing PKGBUILD blobs rendered by git as an empty binary diff, leaving
   no added lines and falling through to `boring`.

These are source-time execution paths: makepkg sources PKGBUILD before source
integrity checks, so a matching checksum does not contain the damage.

## Root causes

- `diff_added()` returned only line text, not a `(path, line)` record.
- The shared classifier used prefix matches and `.*` inside executable Bash
  assignments.
- A blacklist for a few expansion spellings was treated as a complete Bash
  execution boundary. Bash has more expansion and compound-command syntax than
  such a blacklist can safely enumerate.
- Physical diff lines were classified without proving their lexical context in
  the complete candidate PKGBUILD.
- Git/Bash text handling assumed metadata blobs contained no NUL.
- Generic `source=`/checksum/`)` fallbacks could become `boring_edge`, exposing
  executable ambiguity to the optional LLM auto-green seam.

## Fix

The boring pipeline is now file-aware and positive-grammar-only:

1. `_diff_added_metadata_file` extracts PKGBUILD and `.SRCINFO` separately.
   `.SRCINFO` helpers run only on `.SRCINFO`; PKGBUILD helpers run only on
   PKGBUILD.
2. `_metadata_blobs_are_text` checks both baseline and candidate metadata blobs
   before git output enters a Bash scalar. NUL/unreadable metadata is
   `audit_unavailable` and blocks.
3. `_pkgbuild_line_has_plain_context` reads the complete candidate and requires
   every byte-identical occurrence of an added PKGBUILD line to precede no
   ambiguous multiline quote/backtick, heredoc, or backslash state. It is
   intentionally sticky/fail-closed rather than pretending to be a Bash parser.
4. PKGBUILD boring forms use exact, balanced, EOL-anchored positive grammars.
   One-line arrays are scanned for a real unquoted outer closer; only literal
   data is accepted. `source=()` additionally permits only simple `$name` and
   `${name}` expansion. Expansion operators, arithmetic, command/process
   substitution, operators, redirections, subscripts, and trailing commands
   review.
5. Checksum members are literal hex/`SKIP` with balanced quoting. Source
   continuation lines require both the positive source grammar and proven
   complete-candidate `source=()` context.
6. Only context-proven source/checksum openers, members, and closers can become
   `boring_edge`. Unknown shell/array syntax is deterministic `review`, so the
   LLM cannot override it.
7. Broad hard/review rules still inspect all eligible changed files; metadata
   streams are appended explicitly so hostile `.gitattributes` cannot hide
   PKGBUILD/.SRCINFO from those rules.

The parser deliberately accepts false positives after an unrelated earlier
heredoc or multiline quote. Availability is cheaper than silently blessing
Bash whose lexical context the gate cannot prove.

## Regression coverage

Selftests pin:

- ordinary `$()` and backtick substitution in scalar/array fields;
- Bash 5.3 alternate substitution;
- process substitution;
- scalar operator chaining;
- adjacent and whitespace-separated early array close;
- multiline quote plus comment-looking payload line;
- `.SRCINFO`-shaped PKGBUILD command and dependency-helper collisions;
- `.SRCINFO` whitespace exception vs identical PKGBUILD text;
- prompt expansion and legacy arithmetic expansion;
- NUL-bearing PKGBUILD → non-consentable block;
- balanced quoted scalar/comment, quoted literal `)`, a prior here-string, and
  simple source-variable positive controls;
- existing validpgpkeys leakage, duplicate occurrence, deep-array, homograph,
  boring-edge/LLM, and trust-anchor suites.

Verification at implementation time: `bash -n`, shellcheck, and 274 selftests
passed. The separate opera-developer inline-opener/final-checksum false positive
remains fail-closed and is not part of this security fix.
