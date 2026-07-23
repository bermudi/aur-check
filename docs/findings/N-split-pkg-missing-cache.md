# Finding N — Split-package missing-cache clone failure (no scan, wrong staging key)

**Source:** kimi-k2.6 red-team review, session `019f0517-d73a-78d5-929f-c514eed1880d`  
**Status:** closed (2026-06-28)  
**Severity:** medium (see "Severity reassessment" below)  
**Lines:** `_clone_aur()`, `missing_cache_gate()`

## What happens

A split package (pkgname ≠ pkgbase, e.g. `opencl-nvidia-580xx` in the
`nvidia-580xx-utils` pkgbase) whose helper cache clone has been deleted: `yay
-Qua` reports the pkgname. `check_pkg` receives `$pkg` = pkgname.
`find_pkg_dir` fails (no cache). Falls through to `missing_cache_gate "$pkg"`,
which calls `_clone_aur dir "$pkg"`. `_clone_aur` constructs the URL as
`${AUR_URL}/${pkg}.git` — but AUR git repos are keyed by **pkgbase**, not
pkgname. Clone of `pkgname.git` 404s → `missing_cache_gate` returns 2
immediately (clone-fail path), **before** tier-2 ever runs.

Two consequences:

1. **No scan at all.** The original finding text said clone failure returns 2
   "after tier-2 whole-file scan." This was inaccurate — `missing_cache_gate`
   returns 2 *immediately* on clone failure (aur-safe:1027-1029), so the split
   member got neither baseline recovery (tier 1) nor a whole-file scan (tier
   2). The user sees a consent prompt with zero diff content.

2. **Wrong staging key.** Even when the pkgbase-named sibling *was* in the
   update batch and got a real scan, the split member's own staging wrote
   `staged/<pkgname>` (via `_stage_scan_if_gating "$pkg"`). The trust anchor is
   keyed by pkgbase (`accepted/<pkgbase>`), so this entry was invisible to
   `accept`'s pkgbase lookup — the next gate would silently re-seed the anchor
   from the helper-cache HEAD, losing the prior audit.

## Severity reassessment

The original severity (medium) was set assuming the clone failure still
produced a tier-2 scan. It didn't — the split member got zero signal, not a
coarse scan. The real risk vector is a machine where *only* the split member is
installed (no pkgbase-named sibling in the batch): then yay reports only the
pkgname, the clone 404s, and the user gets a consent prompt with no diff and
no pkgbase sibling to cover it — a genuine review gap. This arguably pushes
toward high. Current policy is stronger than at discovery: clone failure is
blocking audit-unavailable (exit 1), so zero signal cannot be consented past.

## Fix (implemented 2026-06-28)

`_clone_aur` now resolves pkgbase from pkgname via AUR RPC v5 (`_resolve_pkgbase`)
before constructing the clone URL. If resolution fails (offline, package not
found), it falls back to `$pkg` — non-split packages (pkgname == pkgbase) still
clone correctly; split packages fail closed if the mapping cannot be resolved.

`missing_cache_gate` derives `pkgbase` from the clone dir name (`${dir##*/}`,
mirroring the cached path) and uses it for `_stage_scan_if_gating`, so the trust
anchor is keyed correctly. Flag files stay keyed by pkgname for user-facing
display (`explain <pkgname>`).

The RPC call adds ~200ms latency (online) to the missing-cache path; the
missing-cache path already does a git clone, so this is negligible. Offline, the
`--connect-timeout 3 --max-time 8` bounds the worst case.

### Known limitations (non-blocking)

1. **Offline latency at scale.** Each missing-cache package incurs up to
   `--connect-timeout 3` (3s) before falling back to `$pkg`. A batch of N
   missing-cache packages adds up to 3N seconds. Not a security issue. A
   per-run "RPC unreachable" short-circuit flag could optimize this.

2. **Mirror without RPC.** `${AUR_URL}/rpc/v5/info` uses the same base URL as
   the clone. If `AUR_URL` is overridden to a cgit-only mirror lacking the RPC
   endpoint, all split members block as audit-unavailable. The failure mode is
   safe (exit 1) but the log may not diagnose the missing RPC precisely.

## Test coverage

Five selftests added under `-- split-package missing-cache (Finding N) --`:

- `split-pkg-baseline-recovery-review` — split member routes through
  `missing_cache_gate`, pkgbase resolution makes the clone succeed, and baseline
  recovery diffs at full precision. Current policy still requires review (2)
  because retained AUR history cannot earn silent trust.
- `split-pkg-stages-under-pkgbase` — staging writes `staged/<pkgbase>`, not
  `staged/<pkgname>`.
- `split-pkg-stages-audited-tip` — staged SHA is the origin/master tip
  (finding-1.2 TOCTOU guarantee).
- `split-pkg-manifest-pkgbase` — manifest entry is pkgbase, so `accept` can
  `find_pkg_dir` it after the build.
- `split-pkg-no-resolution-clonefail` — without a pkgbase map, clone of
  `pkgname.git` 404s → block (1), never consentable passthrough.

## Live confirmation

Observed in production on 2026-06-28: `opencl-nvidia-580xx` and
`nvidia-580xx-dkms` (split members of `nvidia-580xx-utils`) both produced
"could not clone" review prompts during a `yay` update, while the
pkgbase-named sibling (`nvidia-580xx-utils`) succeeded with a real diff. After
the fix, all three resolve to `nvidia-580xx-utils` and get full baseline
recovery.
