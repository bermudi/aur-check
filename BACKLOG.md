# BACKLOG

Red-team review backlog — 2026-06-26 session (glm-5.1, kimi-k2.6, qwen3.7-max).
23 findings across three reviewers. Session transcripts in
`~/.pi/agent/sessions/--home-daniel-build-aur-check--/`.

| Status | Symbol |
|--------|--------|
| Open | `[ ]` |
| In progress | `[~]` |
| Closed | `[x]` |

---

## 🔴 Critical

- [x] **E — IDN homograph `source=()` bypass → silent exit 0** (mitigated 2026-07-01, review-level)
  [docs/findings/E-homograph-source-bypass.md](docs/findings/E-homograph-source-bypass.md)
  glm-5.1 (CRITICAL #1). Single-line `source=('https://іnstall...')` with
  Cyrillic chars → boring classifier accepts → exit 0. Threat model's own
  example. Fixed: `_source_line_nonascii()` guard in `classify_diff_rules`
  (before the boring loop) forces review on any `source`/`source_*= line with
  a byte ≥ 0x80. Covers `.SRCINFO` space-delimited + PKGBUILD array + bare
  assignment syntaxes. Triggered by the `.SRCINFO source_<arch> =` FP fix
  (opencode-bin / vscode-bin) — closing that classifier gap without the guard
  would have re-opened this finding. 3 selftest fixtures pin it. Hard-block
  upgrade still open if review proves too noisy.

- [x] **F — Trust-anchor poisoning via attacker-crafted `.SRCINFO`** (fixed 2026-07-23)
  [docs/findings/F-srcinfo-trust-anchor-poisoning.md](docs/findings/F-srcinfo-trust-anchor-poisoning.md)
  glm-5.1 (CRITICAL #2). Attacker-controlled `.SRCINFO` could claim glibc and
  promote the wrong anchor. Fixed by binding the claim to root-owned pacman
  pkgbase/version/build/install records and the staged pkgbase; stale or
  malformed claims fail closed.

- [x] **S — Helper build TOCTOU: X audited, newer X′ can execute** (fixed 2026-07-23; regenerate wrapper)
  [docs/findings/S-helper-build-toctou.md](docs/findings/S-helper-build-toctou.md)
  The wrapper now injects a makepkg guard that requires manifest membership,
  exact staged HEAD, and a clean checkout immediately before `/usr/bin/makepkg`.
  It forces rebuild/overwrite and rejects artifact-reuse flags. Missing,
  mismatched, dirty, cached, or transitive unaudited builds stop or rebuild
  before PKGBUILD.

## 🟠 High

- [x] **G — Missing-cache tier-2 silently passes review payloads** (fixed 2026-07-23)
  [docs/findings/G-tier2-review-rules-skipped.md](docs/findings/G-tier2-review-rules-skipped.md)
  glm-5.1 (HIGH #3). Attacker force-pushes history → tier-2 → review payload
  once exited 0 clean. Tier 2 now scans both rule sets and always returns 2,
  even with no known regex hit.

- [x] **H — `bunx`, `pnpm exec`, `yarn dlx` missing from JS pkg-mgr rules** (fixed 2026-07-23)
  [docs/findings/H-bunx-pnpm-exec-yarn-dlx-missing.md](docs/findings/H-bunx-pnpm-exec-yarn-dlx-missing.md)
  glm-5.1 (HIGH #4). Campaign exec-equivalents not matched. Fix: add `bunx` rule
  (mirror `npx`), add `exec` to pnpm alts, add `dlx` to yarn alts.

- [x] **I — `pip3 install` bypasses pip review rule** (fixed 2026-07-23)
  [docs/findings/I-pip3-bypass.md](docs/findings/I-pip3-bypass.md)
  glm-5.1 (HIGH #5). Regex requires literal `pip`. Fix: `pip3?` or
  `(pip|pip3|python -m pip)`.

- [x] **J — User git config breaks diff parsing** (FIXED 2026-06-28)
  [docs/findings/J-git-config-breaks-diff.md](docs/findings/J-git-config-breaks-diff.md)
  kimi-k2.6 (HIGH #2). `diff.colorWords`, `diff.noprefix`, `textconv` filters
  can break the entire classification pipeline. Fix: export
  `GIT_CONFIG_GLOBAL=/dev/null` + pass normalizing flags to all git diff/show
  commands in the trust path. **Applied:** `export GIT_CONFIG_GLOBAL=/dev/null
  GIT_CONFIG_SYSTEM=/dev/null` at script load (overrides hostile caller env);
  +1 selftest (`git-config-isolation-hard-rules-fire`).

- [x] **K — `epoch=0` breaks install confirmation and baseline recovery** (fixed 2026-07-23)
  [docs/findings/K-epoch-zero.md](docs/findings/K-epoch-zero.md)
  kimi-k2.6 (HIGH #3). `pacman -Q` omits `0:` prefix but `.SRCINFO` has
  `epoch = 0` → version strings never match → anchor never advances. Fix: treat
  `epoch=0` same as empty.

- [x] **L — Concurrent gate runs corrupt the per-run manifest** (fixed 2026-07-23; regenerate wrapper)
  [docs/findings/L-manifest-race.md](docs/findings/L-manifest-race.md)
  kimi-k2.6 (CRITICAL #1 in their review). The generated wrapper now holds one
  `flock` across gate → helper → accept; direct state commands share the lock.

## 🟡 Medium

- [x] **M — `AUR_SAFE_ALLOW_REVIEW=0` enables auto-proceed** (fixed 2026-07-23)
  [docs/findings/M-allow-review-boolean.md](docs/findings/M-allow-review-boolean.md)
  kimi-k2.6 (MED #4). `[[ -n "0" ]]` is truthy. Fix: `== "1"`.

- [x] **N — Split-package missing-cache degrades to tier-2** (FIXED 2026-06-28)
  [docs/findings/N-split-pkg-missing-cache.md](docs/findings/N-split-pkg-missing-cache.md)
  kimi-k2.6 (MED #5). Clone URL uses pkgname, not pkgbase → clone fails → tier-2
  fallback. Fix: `_clone_aur` resolves pkgbase via AUR RPC v5 before cloning;
  `missing_cache_gate` stages under pkgbase (trust-anchor key). 5 selftests added.

- [x] **O — `find_pkg_dir` slow path no `.git` check → silent skip** (fixed 2026-07-23)
  [docs/findings/O-find-pkg-dir-no-git.md](docs/findings/O-find-pkg-dir-no-git.md)
  qwen3.7-max (MED #1) + glm-5.1 (LOW #8). Documented blindspot, unfixed. Fix:
  `[[ -d "${d}/.git" && -f "${d}/.SRCINFO" ]]`.

- [x] **P — Quoted `source=()` filenames false-positive as review** (fixed 2026-07-23)
  [docs/findings/P-quoted-source-filenames-fp.md](docs/findings/P-quoted-source-filenames-fp.md)
  qwen3.7-max (MED #2) + kimi-k2.6 (MED #8). Fixed as boring-edge only after
  the shared parser proves multiline `source=()` array context.

- [x] **Q — `files_with_status` swallows git exit code** (fixed 2026-07-23)
  [docs/findings/Q-files-with-status-swallows-rc.md](docs/findings/Q-files-with-status-swallows-rc.md)
  kimi-k2.6 (MED #7). `git diff ... 2>/dev/null | awk` never checks pipeline
  exit. Fix: capture output, assert rc, then process.

- [x] **R — Package name regex allows `.`, `..`, `.git`** (fixed 2026-07-23)
  [docs/findings/R-pkg-name-path-traversal.md](docs/findings/R-pkg-name-path-traversal.md)
  kimi-k2.6 (LOW #6). `aur-safe check ..` passes validation. Fix: reject names
  matching `^\.`, `^\.\.$`, `^\.git$`.

## ⚪ Low

These don't have individual finding files; details in delegate transcripts.

- [x] **L1 — `audit` path trust anchor autoseeds without install-confirmation** (fixed 2026-07-23; regenerate wrapper)
  New AUR installs now run under the transaction lock: `audit` stages the
  scanned SHA/pkgbase, the helper installs, and `accept` performs the same
  pacman-backed confirmation before the first anchor is created.

- [ ] **L2 — LLM boring-edge verifier prompt injection**
  glm-5.1 (MED #7). Opt-in `AUR_SAFE_LLM_AUTO_BORING=1` sends attacker-controlled
  diff text unfiltered to LLM. Currently off by default. Fix: document the risk,
  keep off, or restrict verifier surface to deterministic metadata structures
  only.

- [x] **L3 — `classify_diff_rules` prints entire `$name_status` instead of `$path`** (fixed 2026-07-23)
  qwen3.7-max (LOW #3). Line 756 prints all changed files, not just the
  triggering file. Cosmetic. Fix: use `$path` (like line 763 does).

- [x] **L4 — `write_ref` doesn't validate `git rev-parse` success** (fixed 2026-07-23)
  qwen3.7-max (LOW #4). Empty SHA possible if rev-parse fails. Callers
  compensate but fragile. Fix: validate in `write_ref` or assert preconditions.

- [x] **L5 — `source_domains` awk overmatches `source_dir=` variables** (fixed 2026-07-23)
  qwen3.7-max (LOW #5) + glm-5.1 (LOW #8) + kimi-k2.6 (LOW #12).
  `/^[[:space:]]*source/` matches variables like `source_dir`, not just arrays.
  Low likelihood in practice. Fix: tighten to
  `/^[[:space:]]*source(_[[:alnum:]_]+)?=\(/`.

- [x] **L6 — `python-inline-net` misses aliased imports and raw sockets** (fixed 2026-07-23)
  glm-5.1 (LOW #9). `python -c "import requests as r"` and
  `python -c "import socket"` not tagged. Diff classifier catches as non-boring
  → review (safety net holds). Fix: broaden to generic `python[23]?[[:space:]]+-c`
  review tag.

- [x] **L7 — No `GIT_CONFIG_GLOBAL` isolation** (fixed with J, 2026-06-28)
  kimi-k2.6 (LOW #9). Used throughout without isolation. Fix: same as J — export
  at script top.

- [x] **L8 — Temp directories leak on SIGINT** (fixed 2026-07-23)
  kimi-k2.6 (LOW #10). No `trap` for EXIT/INT/TERM cleanup. Fix: add trap
  handler.

- [x] **L9 — `git diff --name-status` without `-z` breaks on tab-in-filename** (fixed 2026-07-23)
  kimi-k2.6 (LOW #11). Latent parsing bug, no real AUR filenames contain tabs.
  Fix: add `-z` + null-delimited parsing.

---

## Suggested fix order

| Priority | Finding | Effort | Surface |
|---|---|---|---|
| 1 | L2 — optional LLM prompt injection | Small | verifier policy/docs |

All deterministic findings through S are closed in the working tree as of
2026-07-23. L2 remains an explicit opt-in nondeterministic risk.

## Reviewer transcripts

| Reviewer | Session |
|---|---|
| glm-5.1 | `019f0517-d737-732f-b8d6-6ae4c3208309` |
| kimi-k2.6 | `019f0517-d73a-78d5-929f-c514eed1880d` |
| qwen3.7-max | `019f0517-d73a-78d5-929f-caae55c267e2` |
