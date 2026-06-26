# Finding L — Concurrent gate runs corrupt the per-run manifest

**Source:** kimi-k2.6 red-team review, session `019f0517-d73a-78d5-929f-c514eed1880d`  
**Status:** open  
**Severity:** high  
**Lines:** `MANIFEST_FILE` at aur-safe:46, `_stage_if_gating()` at aur-safe:591-595, `_stage_scan_if_gating()` at aur-safe:675-680, `cmd_gate()` at aur-safe:1215, `cmd_accept()` at aur-safe:1270-1295

## What happens

`MANIFEST_FILE` is a single global file (`$STATE_DIR/last-gate`). Each
`cmd_gate` starts with `: >"$MANIFEST_FILE"` (truncate), and
`_stage_if_gating`/`_stage_scan_if_gating` append with `printf ... >>`. Shell
`>>` is not atomic across processes — concurrent appends can interleave lines.
A concurrent gate can:

- Truncate the manifest while another gate is still appending, causing `accept`
  to miss packages that should be promoted.
- Interleave manifest lines, causing `cmd_accept` to look for staged files with
  garbage names.
- Race on `staged/<pkgbase>` writes: the last writer wins, so the SHA written
  by one gate overwrites the other.

**Impact:** Breaks the TOCTOU staging invariant. A package whose staged entry
is lost or overwritten will not be promoted by `accept`; the next gate re-audits
from the old anchor. Worse, a race winner with a stale SHA could be promoted if
install-confirmation happens to match.

## Fix

Use per-run manifest files (e.g. `last-gate.$$.$RANDOM`) with `cmd_accept`
processing the most recent one, or use `flock` on the manifest during gate and
accept. Since this is single-user, `flock` is simpler and sufficient.

## Test gap

No test exercises two simultaneous gates. Add a selftest with two concurrent
`aur-safe check` invocations on different packages and verify manifest integrity.
