# Finding D — Version-vs-SHA mismatch in `accept` (working as designed)

**Source:** glm-5.1 delegate review, session `019f0184-3dba-7727-bac9-7f203e6516af`  
**Status:** closed (working as designed, documentation note only)  
**Lines:** `_installed_matches()` at `aur-safe:253`, `cmd_accept()` at `aur-safe:733,751`

## What the reviewer flagged

`_installed_matches` compares installed version (`pacman -Q`) against the staged
commit's `.SRCINFO` *version* (pkgver+pkgrel+epoch), not against the installed
commit's *SHA*. `cmd_accept` at line 751 calls it:

```bash
if _installed_matches "$dir" "$staged_sha"; then
  mv -f "$staged_file" "$ACCEPTED_DIR/$pkgbase"
```

If an attacker pushes a different commit X′ with the same pkgver in the TOCTOU
window between gate and helper's fetch, `accept` promotes the staged commit X
(audited) even though yay built+installed X′.

## Why this is NOT a bug

The TOCTOU guarantee is preserved by the *next* gate, not by `accept`:

1. `check_pkg` stages commit X (the gate-time tip).
2. Helper fetches X′ (same pkgver) and installs it.
3. `accept` compares installed version → `.SRCINFO` version of X → match →
   promotes X as the trust anchor.
4. Next gate: `git diff accepted(X)..origin/master` — the diff X→X′ surfaces
   as a delta, the malicious commit is scanned by `scan_diff_rules`.

The **accepted ref = audited commit, not installed commit** — this is exactly
the finding-1.2 guarantee. If we required the installed SHA to match the staged
SHA, `accept` would reject legitimate windows where the helper fetched a benign
later commit (a regular update pushed between gate and helper).

The reviewer's proposed fix (require `helper-cache-HEAD == staged_sha`) would
create false rejections on routine race windows. The current design correctly
lets the next gate catch any window-commit delta.

## Action

No code change. The REVIEWER-NOTES §"Why staging" paragraph should be refined to
clarify the version-equivalence-vs-SHA-equivalence distinction: the staged commit
is the *audited* commit; what got installed is version-confirmed but may be a
different SHA — and that's fine, because the next gate audits the delta.
