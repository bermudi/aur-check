# Finding V — inline checksum-array reflow forces review

**Source:** live `opera-developer` update, 2026-07-27  
**Status:** fixed (2026-07-27)  
**Severity:** false positive / availability

## What happened

`opera-developer` reformatted a multiline checksum array from an EOL opener and
bare closer:

```bash
sha256sums=(
    'first'
    'unchanged'
    'last'
)
```

to an inline first and final member:

```bash
sha256sums=('first'
            'unchanged'
            'last')
```

The unchanged middle checksums appeared as removed/added lines because their
indentation changed. The contextual tracker recognized only an opener ending at
`(`, while its input grammar rejected both the inline opener and final-member
closer. The update therefore remained review even after the broader Finding U
security repair.

## Fix

`_pkgbuild_checksum_array_line` now has a checksum-specific opener grammar. It
accepts only:

- the existing `*sums=(` EOL opener; or
- `*sums=(` followed by exactly one balanced literal hex/`SKIP` token and EOL.

Eligible added lines are exactly an inline literal opener, a standalone literal
member, a literal final member followed by the real `)` and optional comment,
or a standalone closer proven against the same checksum-specific opener. The
complete-candidate tracker still records membership before processing the
closer, closes state on either closer shape, and requires every byte-identical
occurrence to remain inside the checksum array.

The shared source/dependency opener remains EOL-only. Substitution, operators,
mismatched quotes, continuations, trailing commands, and bare fingerprints
outside checksum context remain review. A regression duplicates the same
fingerprint inside an inline-open checksum array and `validpgpkeys=()`; the
outside occurrence prevents auto-clear.

## Verification

- faithful four-element `opera-developer` reflow: `boring`, rc 0;
- inline-opener duplicate cannot mask `validpgpkeys`: `review`, rc 2;
- inline opener plus standalone closer: `boring`, rc 0;
- `bash -n`, shellcheck, and 277 selftests pass;
- live `./aur-gate check opera-developer`: `ok`, rc 0.
