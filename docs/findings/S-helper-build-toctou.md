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
helper run. Catching it next time was too late for aur-gate's primary promise:
stop malicious AUR updates before execution/pacman.

Gate-time fetch failures already blocked; the mechanism below closes the
remaining ordinary two-fetch race.

## Implemented mechanism

The generated wrapper passes the aur-gate executable through both helpers'
`--makepkg` option. `AUR_GATE_AS_MAKEPKG=1` selects `cmd_makepkg`, which runs at
the final safe seam before `makepkg` is invoked and requires:

1. a valid git checkout whose directory names the pkgbase;
2. that pkgbase in the current transaction manifest;
3. a valid `staged/<pkgbase>` record;
4. the staged SHA's tree consists of only regular files with PKGBUILD and `.SRCINFO`.

`cmd_makepkg` then materializes the exact staged tree into a private build
directory at `~/.cache/aur-gate/build/<pkgbase>/` using `git archive <staged_sha>`
|`tar -x`, and runs `/usr/bin/makepkg` there with `PKGDEST` redirected back to the
helper checkout. The helper checkout's `HEAD`, index, worktree, and refs are not
used as the build surface, so a moved branch, dirty tree, staged changes,
`skip-worktree`/`assume-unchanged` flags, or untracked files cannot influence the
build. The build directory is re-materialized on every invocation (no sentinel
reuse, preventing cross-package poisoning in multi-package transactions) and is
swept at `begin`, `accept`, and `abort` boundaries. Post-extraction verification
re-hashes every file with `git hash-object` and compares to `git ls-tree -r -z
<staged_sha>`, catching `export-subst`/`export-ignore` divergence and any extra
or missing files.

The wrapper injects yay `--rebuildall --nomakepkgconf` or paru
`--rebuild=all --nochroot --nolocalrepo`, replaces persisted helper mflags with
the fixed safe set `--cleanbuild --force`, and rejects caller-supplied
rebuild/custom makepkg/mflags/build-context options. The adapter rejects
artifact-reuse, integrity-skip, alternate-directory, PKGBUILD, and config modes.
`--cleanbuild --force` are enforced for build calls; `makepkg --packagelist` (the
only read-only metadata call the helpers use for package discovery) passes
through without the build flags. Package discovery works because `PKGDEST` points
at the helper checkout, so `makepkg --packagelist` returns the absolute paths
where the built packages will land. Missing state also prevents a helper-discovered transitive AUR
dependency from building without an audit. The transaction lock remains in the
parent wrapper, but its fd and capability environment are removed from the
untrusted helper.

## Verification

Selftests cover matching SHA + forced fresh build/argument preservation,
X→X′ mismatch, tracked dirt, untracked scriptlets, artifact-reuse mode rejection,
and a missing manifest/staged entry. A stub wrapper
run verified gate/audit → helper → accept order and that helper code cannot
inherit the lock capability. Generated wrapper syntax passes bash and zsh.
