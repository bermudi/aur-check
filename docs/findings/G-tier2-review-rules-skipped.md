# Finding G — Missing-cache tier-2 silently passes review-only payloads

**Source:** glm-5.1 red-team review, session `019f0517-d737-732f-b8d6-6ae4c3208309`  
**Status:** open  
**Severity:** high  
**Lines:** `_scan_whole_pkg()` at aur-safe:380-388, `missing_cache_gate()` at aur-safe:964-976

## What happens

`_scan_whole_pkg` only iterates `RULE_NAMES` (hard rules). It **never iterates
`REVIEW_NAMES`** (pip/gem/cargo/go/python-inline-net). This is intentional for
FP-reduction — but only safe on a baseline-less scan that isn't attacker-reachable.

When the missing-cache path falls back to tier-2 (installed version not found in
AUR history), `SCAN_HITS` is 0 for review-rule payloads → `log "ok"` →
`_stage_scan_if_gating` → `return 0` (clean, no consent, trust anchor staged).

**Attack scenario:**

1. Attacker controls AUR pkg P, installed at v1 on victim's machine.
2. Attacker force-pushes AUR/master so v1 commit is gone; oldest retained commit
   is X at v2 with `build() { pip install malicious-pypkg; }`.
3. Victim clears cache (`yay -Sc`), runs `yay -Syu`.
4. `missing_cache_gate`: `find_baseline_commit` → v1 not found → tier 2.
5. `_scan_whole_pkg`: pip isn't hard. No hits → stage X → exit 0 → "ok".
6. Helper builds X. `build()` runs → `pip install malicious-pypkg` executes
   malicious `setup.py` at build time → exfiltration.
7. If combined with Finding F (`.SRCINFO` poisoning), `accept` promotes X.

The ledger acknowledges that tier-2 review rules are skipped, but the
attacker-force-push path makes this adversarially reachable.

## Fix

- Run `REVIEW_NAMES` in tier-2; escalate to exit 2 (consent) on any review hit,
  never exit 1.
- More conservative: never exit 0 silently from tier-2. Force exit 2 on
  `SCAN_CONTENT` non-empty and require consent even on no rule hit.
- Safest: in `missing_cache_gate` tier-2, never call `_stage_scan_if_gating`
  (denied-signal path should not advance the trust anchor).

## Test gap

No selftest for tier-2 path with a review-only payload (pip/cargo/gem). A
fixture with `pip install foo` in PKGBUILD and a force-pushed history that
collapses to tier-2 should verify exit 2, not 0.
