# Finding P — Quoted PKGBUILD `source=()` entries false-positive as review

**Source:** qwen3.7-max red-team review, session `019f0517-d73a-78d5-929f-caae55c267e2`; also flagged by kimi-k2.6 as "new optdepends array" variant  
**Status:** fixed (2026-07-23)
**Severity:** medium  
**Lines:** `_boring_added_line_class()` at aur-safe:293

## What happens

Multi-line `source=()` arrays with quoted filenames like `"foo-1.1.tar.gz"` don't
match any boring/boring-edge pattern in `_boring_added_line_class`. The regex at
line 293 requires a URL scheme (`http://`, `ftp://`, etc.) or a hex checksum —
quoted filenames match neither.

```bash
# Diff of a routine version bump:
-source=("foo-1.0.tar.gz")
+source=(
+  "foo-1.1.tar.gz"
+)

# After diff_added processing:
  "foo-1.1.tar.gz"
)
```

- `)` → matches `^[[:space:]]*\)[[:space:]]*$` → boring_edge ✓
- `  "foo-1.1.tar.gz"` → matches nothing → `return 2` (review) ✗

**Impact:** Benign version bumps trigger review prompts. Users without
`AUR_SAFE_LLM_AUTO_BORING=1` see false positives on routine updates. The LLM
verifier would auto-clear these, but it's opt-in.

## Fix and verification

Implemented with array-context proof, not a global filename regex. Literal
quoted filenames are `boring_edge` only when the shared diff state machine
proves they are inside a multiline `source=()`/`source_<arch>=()` array. This
avoids treating a quoted top-level shell command as metadata. A classifier
fixture pins the quoted filename version-bump shape.
