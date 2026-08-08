# GH #5 — Repo-local git config is trusted; git invocation hardening is incomplete

**Source:** Cohort 2 red-team review, GitHub issue #5
**Status:** fixed (2026-07-28; local-config strategy superseded 2026-08-05)
**Severity:** critical
**Lines:** historical Bash implementation; current Rust boundary is `src/git.rs`
(`safe_git_command`, `reset_local_config`, `isolate_git_env`).

## What happens

`aur-gate` already set `GIT_CONFIG_GLOBAL=/dev/null` and `GIT_CONFIG_SYSTEM=/dev/null` at load (Finding J), which neutralised the user's `~/.gitconfig`. It did **not** isolate:

1. **Repo-local `.git/config`**. A malicious build that can write to the helper's cached clone can set `diff.wordDiff=porcelain`, `diff.colorWords=true`, `diff.noprefix=true`, `diff.mnemonicPrefix=true`, `diff.external`, `core.pager`, `core.gitProxy`, `core.attributesFile`, `core.hooksPath`, `core.sshCommand`, `core.worktree`, `remote.*.proxy`, `url.insteadOf`, etc. These can change `git diff` output, execute arbitrary code via `diff.external`/`textconv`, `core.gitProxy`/`remote.*.proxy`, redirect fetches via `url.*`, or make `git` operate on a different worktree.

2. **Environment variables**. `GIT_EXTERNAL_DIFF`, `GIT_PAGER`, `PAGER`, `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE`, `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES`, `GIT_CONFIG_COUNT`/`KEY_*`/`VALUE_*`, `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_PROXY_COMMAND`, and `GIT_TERMINAL_PROMPT` all leak from the caller and can alter git behaviour or fetch target.

3. **`.gitattributes` in the tree**. A committed `.gitattributes` line like `PKGBUILD binary` causes `git diff` to emit only "Binary files differ" instead of the added lines. `diff_added` then returns nothing and the hard rules silently miss `curl | sh` payloads.

## Fix

A single `git()` wrapper function shadows the external `git` binary for all git calls inside `aur-gate`:

- At script load, unset the dangerous `GIT_*` and `PAGER` environment variables and export safe defaults: `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_SYSTEM=/dev/null`, `GIT_TERMINAL_PROMPT=0`, `GIT_ASKPASS=/bin/true`.
- For **every** git call, prepend `--no-pager` and a short list of `-c` overrides that win over repo-local config: `core.pager=cat`, `pager.diff/show=cat`, `core.quotepath=false`, `core.attributesFile=`, `core.excludesFile=`, `core.hooksPath=`, `color.ui=false`, `color.diff=false`, `diff.wordDiff=none`, `diff.colorWords=false`, `diff.mnemonicPrefix=false`, `diff.noprefix=false`, `diff.colorMoved=false`, `http.sslVerify=true`.
- For `diff` and `show`, add subcommand options `--no-ext-diff --no-textconv --word-diff=none --text`. `--text` defeats `.gitattributes` binary markers; `--no-ext-diff` and `--no-textconv` defeat external diff drivers and textconv filters.
- Every git() call runs with `GIT_PROXY_COMMAND=` (empty), overriding `core.gitProxy`/`remote.*.proxy` and any inherited `GIT_PROXY_COMMAND` environment. Git's `core.gitProxy` cannot be reliably neutralised with a `-c` override because it is a multi-valued "first match wins" config, so the env var is the correct kill switch.
- The Rust implementation now atomically replaces repo-local `.git/config`
  with the fixed values required by the checkout (plus the validated SHA-256
  repository marker when present). Its fallback guard is an exact generated
  key/value contract; changed, duplicate, unknown, and future keys fail
  closed. Each repo-bound Rust Git child receives a private metadata view
  containing that validated config, so it cannot reopen a mutable local file.
  Cached clones, fresh clones, the makepkg seam, and accept all reset before
  repo-bound Git work.

## Verification

- `bash -n aur-gate` and `shellcheck -s bash aur-gate` are clean.
- `./aur-gate selftest` passes (303/0 as of 2026-07-28).
- Selftest fixtures cover:
  - `git-config-isolation-hard-rules-fire` — `GIT_CONFIG_GLOBAL/SYSTEM=/dev/null` still active, hard rules fire.
  - `git-config-local-unsafe-blocks` — a `.git/config` poisoned with `diff.*`, `color.*`, `core.pager`, `core.gitProxy`, `core.worktree`, `url.insteadOf`, `remote.*.proxy`, `credential.*`, and `submodule.*` returns rc 1 (fail-closed).
  - `git-config-local-override-hard-rules-fire` — a repo with `color.ui=always`, `color.diff=always`, `core.quotepath=true`, and a committed `.gitattributes` that marks `PKGBUILD` as `binary` still has its diff parsed deterministically and the `curl | sh` payload is detected.
  - `git-proxy-command-env-neutralized` — a repo with a `git://` remote and an inherited `GIT_PROXY_COMMAND` pointing to an evil script does not execute the script.
- `cargo test --all-targets --no-fail-fast` passes; the `git` module in `src/git.rs` exercises the Rust local-config hardening with:
  - `git::tests::generated_local_config_rejects_mutated_values` — after `reset_local_config` writes the exact generated local config, mutating any allowed key to a new value (core fields, `extensions.objectFormat`, or `remote.origin.*`) is rejected and fails closed.
  - `git::tests::generated_local_config_rejects_duplicate_allowed_keys` — adding a duplicate value for an allowed key (`core.bare` or `remote.origin.url`) breaks the exact key/value contract and is rejected.
  - `git::tests::safe_git_uses_validated_config_snapshot_after_local_swap` — a `safe_git_command` is built with the validated private metadata view, `.git/config` is then swapped for an attacker-controlled symlink, and the spawned Git child still succeeds without consulting the swapped local config.

## Lesson

User/system config isolation is necessary but not sufficient. Any Git call inside a security gate must treat the repo's own `.git/config` and the caller's environment as untrusted. The durable Rust fix is to regenerate the small local-config namespace rather than grow a denylist; the exact-contract guard and private command view remain fail-closed tripwires for a missed refresh or a concurrent local-file swap.
