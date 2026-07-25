# Finding T — changed patch content omitted from review evidence

**Status:** Fixed 2026-07-25  
**Severity:** High (review consent could be based on incomplete evidence)

## Finding

`EXCLUDE_PATHS` excluded `*.patch` and `*.diff` from deterministic scanning to
avoid interpreting nested diff additions as additions to the AUR repository.
The same pathspec list was also used by `stash_flag`.

A changed patch correctly triggered structural review as a
`[non-metadata-file]`, but the stashed diff consumed by both `view` and
`explain` omitted that patch entirely. In the observed `ventoy-bin` update,
`sanitize.patch` was reported as changed while the advisory model saw only
`.SRCINFO` and `PKGBUILD`, then incorrectly described the visible sed edit as
the only functional change.

The gate did not silently pass—the result remained review—but the review UI
withheld the exact evidence the user was being asked to approve. The same
incomplete-evidence class also affected baseline-less/first-contact review:
`_scan_whole_pkg` called its output the whole candidate but stashed only
PKGBUILD, hooks, and shell scripts, omitting tracked patches and other text.

## Fix

Split pathspec policy by purpose:

- `EXCLUDE_PATHS` still excludes binary content and nested `*.patch`/`*.diff`
  files from deterministic added-line rules.
- Review evidence uses no suffix exclusions; extension is attacker-controlled.
  Real binaries retain git's marker and blob identities.
- `_review_diff_to_file` disables textconv and rejects empty/NUL-bearing output
  or an opaque changed patch/diff, so hostile attributes cannot silently hide
  review-critical text.
- Baseline-less whole-candidate review now stashes the tracked tip as an
  empty-tree diff, while deterministic rules remain restricted to executable
  package surfaces.
- Baseline-recovery review always replaces a consentable delta stash with whole
  candidate evidence, including when the delta itself fired a review rule. An
  attacker-retained baseline is never accepted as review context.

Selftests cover cached and uncached patch evidence, a review-triggering delta
with content retained in its reconstructed baseline, extension-disguised text,
opaque patch attributes, and NUL-bearing evidence.
