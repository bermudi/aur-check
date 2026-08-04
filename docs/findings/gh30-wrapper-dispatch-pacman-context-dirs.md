# gh#30 — Wrapper dispatch does not reject `--hookdir`/`--cachedir`/`--gpgdir`/`--logfile`

**Source:** GitHub issue [#30](https://github.com/bermudi/aur-gate/issues/30)
(adversarial review, H9)
**Status:** fixed
**Severity:** high
**Lines:** `assets/wrapper.sh:122-140` (dispatch reject list)

## Summary

The wrapper's dispatch reject list blocked `--config`, `--root`, `--dbpath`,
`--pacman`, `--git`, `--gpg`, `--sudo` and other trust-context options, but did
NOT block `--hookdir`, `--cachedir`, `--gpgdir`, or `--logfile`. The classifier
(`assets/wrapper.sh:66-72`) already skipped these flags so their values were not
fed to `aur-gate audit`, but dispatch passed them through to yay/paru as `"$@"`,
so they reached `pacman -U` as root during install.

## Attack scenario

1. User runs `yay -Syu --hookdir /tmp/evil some-aur-pkg`.
2. Wrapper classifier skips the `--hookdir` value (not audited); dispatch does
   not reject it.
3. yay calls `pacman -U --hookdir /tmp/evil <pkg.tar.zst>`.
4. ALPM hooks from `/tmp/evil` execute as root during install, completely
   bypassing the auditor.

`--cachedir`, `--gpgdir`, and `--logfile` are analogous: they redirect
pacman's package cache, gpg trust directory, or log stream to an
attacker-controlled location during the privileged install step.

## Fix

Added `--hookdir`, `--cachedir`, `--gpgdir`, `--logfile` (and their
`--opt=value` forms) to the dispatch reject list at
`assets/wrapper.sh:130-132`, alongside the existing `--config`/`--root`/`--dbpath`
pacman context options. Any of these flags now aborts dispatch with the existing
`custom helper/build trust context is unsupported` message before the helper is
invoked.

The wrapper contract unit test (`src/wrapper.rs`) now asserts the reject-list
fragments are present, and a new integration test
`wrapper_dispatch_rejects_pacman_context_dirs` exercises both bare and
`--opt=value` forms under bash and zsh, confirming the helper never runs.

## Verification

- `bash -n assets/wrapper.sh` and `zsh -n assets/wrapper.sh` — clean.
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings` — clean.
- `cargo test --all-targets` — all tests pass, including
  `wrapper_dispatch_rejects_pacman_context_dirs` (bash + zsh, 8 flag forms).
- `cargo run --quiet -- selftest` — 59 passed, 0 failed.

## Lesson

A reject list that blocks *some* pacman context-changing options but not others
is a classic allowlist/denylist drift: the classifier's skip-list and the
dispatch's reject-list were maintained separately and diverged. Any pacman
option that redirects where pacman reads hooks, caches, gpg state, or logs from
is a trust-context override and belongs in the same denylist as `--config` and
`--root`. When a flag is added to the classifier's skip list because its value
is unsafe to audit, the same flag must be evaluated against the dispatch reject
list — skipping audit is not the same as safe passthrough.
