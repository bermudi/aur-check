# Finding S — helper can build a commit newer than the audited gate-time tip

**Source:** 2026-07-23 trust-path review
**Status:** fixed in generated wrapper (2026-07-23; existing wrappers must be regenerated)
**Severity:** critical
**Surface:** generated wrapper, yay/paru `--makepkg`, staged refs

## What happens

The gate fetches and audits commit X, then invokes yay/paru. The helper performs
its own fetch before calling makepkg. If commit X′ lands between those fetches,
the helper can check out and build X′ even though only X was audited.

Staging alone correctly prevents **anchor poisoning**: `accepted/<pkgbase>`
would advance to X (the audited SHA), not X′. Before the final guard, however,
that did not prevent X′'s PKGBUILD/build hooks from executing during the first
helper run. Catching it next time was too late for aur-safe's primary promise:
stop malicious AUR updates before execution/pacman.

Gate-time fetch failures already blocked; the mechanism below closes the
remaining ordinary two-fetch race.

## Implemented mechanism

The generated wrapper passes the aur-safe executable through both helpers'
`--makepkg` option. `AUR_SAFE_AS_MAKEPKG=1` selects `cmd_makepkg`, which runs at
the final safe seam before PKGBUILD is sourced and requires:

1. a valid git checkout whose directory names the pkgbase;
2. that pkgbase in the current transaction manifest;
3. a valid `staged/<pkgbase>` record;
4. `HEAD == staged SHA`;
5. no tracked/index changes; and
6. no untracked PKGBUILD, `.SRCINFO`, `*.install`, or `*.sh` files.

The wrapper injects yay `--rebuildall --nomakepkgconf` or paru
`--rebuild=all --nochroot --nolocalrepo`, replaces persisted helper mflags with
the fixed safe set `--cleanbuild --force`, and rejects caller-supplied
rebuild/custom makepkg/mflags/build-context options. The adapter rejects
artifact-reuse, integrity-skip, alternate-directory, PKGBUILD, and config modes,
then adds
`--cleanbuild --force` when executing
`/usr/bin/makepkg`, ensuring stale source/build state is removed and an existing
`.pkg.tar.*` is overwritten by this guarded build rather than reused. X→X′,
dirty checkout, cached artifacts, and missing staged records all block or
rebuild before installation. Missing state also prevents a helper-discovered
transitive AUR dependency from building without an audit. The transaction lock
remains in the parent wrapper, but its fd and capability environment are removed
from the untrusted helper.

## Verification

Selftests cover matching SHA + forced fresh build/argument preservation,
X→X′ mismatch, tracked dirt, untracked scriptlets, artifact-reuse mode rejection,
and a missing manifest/staged entry. A stub wrapper
run verified gate/audit → helper → accept order and that helper code cannot
inherit the lock capability. Generated wrapper syntax passes bash and zsh.
