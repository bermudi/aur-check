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

- [ ] **E — IDN homograph `source=()` bypass → silent exit 0**
  [docs/findings/E-homograph-source-bypass.md](docs/findings/E-homograph-source-bypass.md)
  glm-5.1 (CRITICAL #1). Single-line `source=('https://іnstall...')` with
  Cyrillic chars → boring classifier accepts → exit 0. Threat model's own
  example. Fix: refuse boring on lines with bytes ≥ 0x80, or extend
  `source_domains` regex to capture IDN hosts.

- [ ] **F — Trust-anchor poisoning via attacker-crafted `.SRCINFO`**
  [docs/findings/F-srcinfo-trust-anchor-poisoning.md](docs/findings/F-srcinfo-trust-anchor-poisoning.md)
  glm-5.1 (CRITICAL #2). `_installed_matches` parses pkgname/pkgver from
  attacker-controlled `.SRCINFO`, not PKGBUILD. Attacker claims pkgname=glibc →
  `pacman -Q` matches → `accept` promotes malicious SHA. Fix: parse PKGBUILD
  instead, assert pkgname ∈ pkgbase's split set.

## 🟠 High

- [ ] **G — Missing-cache tier-2 silently passes review payloads**
  [docs/findings/G-tier2-review-rules-skipped.md](docs/findings/G-tier2-review-rules-skipped.md)
  glm-5.1 (HIGH #3). `_scan_whole_pkg` only runs hard rules. Attacker
  force-pushes history → tier-2 → `pip install evil` exits 0 clean. Fix: run
  `REVIEW_NAMES` in tier-2 (exit 2, never 1), or never stage from tier-2.

- [ ] **H — `bunx`, `pnpm exec`, `yarn dlx` missing from JS pkg-mgr rules**
  [docs/findings/H-bunx-pnpm-exec-yarn-dlx-missing.md](docs/findings/H-bunx-pnpm-exec-yarn-dlx-missing.md)
  glm-5.1 (HIGH #4). Campaign exec-equivalents not matched. Fix: add `bunx` rule
  (mirror `npx`), add `exec` to pnpm alts, add `dlx` to yarn alts.

- [ ] **I — `pip3 install` bypasses pip review rule**
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

- [ ] **K — `epoch=0` breaks install confirmation and baseline recovery**
  [docs/findings/K-epoch-zero.md](docs/findings/K-epoch-zero.md)
  kimi-k2.6 (HIGH #3). `pacman -Q` omits `0:` prefix but `.SRCINFO` has
  `epoch = 0` → version strings never match → anchor never advances. Fix: treat
  `epoch=0` same as empty.

- [ ] **L — Concurrent gate runs corrupt the per-run manifest**
  [docs/findings/L-manifest-race.md](docs/findings/L-manifest-race.md)
  kimi-k2.6 (CRITICAL #1 in their review). `MANIFEST_FILE` is a single global
  file with truncate + `>>`, no locking. Two concurrent gates interleave/corrupt
  entries. Fix: `flock` or per-run manifest files (`last-gate.$$.$RANDOM`).

## 🟡 Medium

- [ ] **M — `AUR_SAFE_ALLOW_REVIEW=0` enables auto-proceed**
  [docs/findings/M-allow-review-boolean.md](docs/findings/M-allow-review-boolean.md)
  kimi-k2.6 (MED #4). `[[ -n "0" ]]` is truthy. Fix: `== "1"`.

- [x] **N — Split-package missing-cache degrades to tier-2** (FIXED 2026-06-28)
  [docs/findings/N-split-pkg-missing-cache.md](docs/findings/N-split-pkg-missing-cache.md)
  kimi-k2.6 (MED #5). Clone URL uses pkgname, not pkgbase → clone fails → tier-2
  fallback. Fix: `_clone_aur` resolves pkgbase via AUR RPC v5 before cloning;
  `missing_cache_gate` stages under pkgbase (trust-anchor key). 5 selftests added.

- [ ] **O — `find_pkg_dir` slow path no `.git` check → silent skip**
  [docs/findings/O-find-pkg-dir-no-git.md](docs/findings/O-find-pkg-dir-no-git.md)
  qwen3.7-max (MED #1) + glm-5.1 (LOW #8). Documented blindspot, unfixed. Fix:
  `[[ -d "${d}/.git" && -f "${d}/.SRCINFO" ]]`.

- [ ] **P — Quoted `source=()` filenames false-positive as review**
  [docs/findings/P-quoted-source-filenames-fp.md](docs/findings/P-quoted-source-filenames-fp.md)
  qwen3.7-max (MED #2) + kimi-k2.6 (MED #8). `"foo-1.1.tar.gz"` doesn't match
  boring patterns → routine version bumps trigger review. Fix: extend
  boring-edge regex to recognize quoted filenames.

- [ ] **Q — `files_with_status` swallows git exit code**
  [docs/findings/Q-files-with-status-swallows-rc.md](docs/findings/Q-files-with-status-swallows-rc.md)
  kimi-k2.6 (MED #7). `git diff ... 2>/dev/null | awk` never checks pipeline
  exit. Fix: capture output, assert rc, then process.

- [ ] **R — Package name regex allows `.`, `..`, `.git`**
  [docs/findings/R-pkg-name-path-traversal.md](docs/findings/R-pkg-name-path-traversal.md)
  kimi-k2.6 (LOW #6). `aur-safe check ..` passes validation. Fix: reject names
  matching `^\.`, `^\.\.$`, `^\.git$`.

## ⚪ Low

These don't have individual finding files; details in delegate transcripts.

- [ ] **L1 — `audit` path trust anchor autoseeds without install-confirmation**
  glm-5.1 (MED #6). New installs via `yay -S` never run `accept` → anchor seeds
  from clone HEAD on next gate. Design-ledger pressure point #3. Fix: make
  `cmd_audit` stage + manifest entry so `accept` runs, or gate on `SCAN_HITS`.

- [ ] **L2 — LLM boring-edge verifier prompt injection**
  glm-5.1 (MED #7). Opt-in `AUR_SAFE_LLM_AUTO_BORING=1` sends attacker-controlled
  diff text unfiltered to LLM. Currently off by default. Fix: document the risk,
  keep off, or restrict verifier surface to deterministic metadata structures
  only.

- [ ] **L3 — `classify_diff_rules` prints entire `$name_status` instead of `$path`**
  qwen3.7-max (LOW #3). Line 756 prints all changed files, not just the
  triggering file. Cosmetic. Fix: use `$path` (like line 763 does).

- [ ] **L4 — `write_ref` doesn't validate `git rev-parse` success**
  qwen3.7-max (LOW #4). Empty SHA possible if rev-parse fails. Callers
  compensate but fragile. Fix: validate in `write_ref` or assert preconditions.

- [ ] **L5 — `source_domains` awk overmatches `source_dir=` variables**
  qwen3.7-max (LOW #5) + glm-5.1 (LOW #8) + kimi-k2.6 (LOW #12).
  `/^[[:space:]]*source/` matches variables like `source_dir`, not just arrays.
  Low likelihood in practice. Fix: tighten to
  `/^[[:space:]]*source(_[[:alnum:]_]+)?=\(/`.

- [ ] **L6 — `python-inline-net` misses aliased imports and raw sockets**
  glm-5.1 (LOW #9). `python -c "import requests as r"` and
  `python -c "import socket"` not tagged. Diff classifier catches as non-boring
  → review (safety net holds). Fix: broaden to generic `python[23]?[[:space:]]+-c`
  review tag.

- [ ] **L7 — No `GIT_CONFIG_GLOBAL` isolation** (general note)
  kimi-k2.6 (LOW #9). Used throughout without isolation. Fix: same as J — export
  at script top.

- [ ] **L8 — Temp directories leak on SIGINT**
  kimi-k2.6 (LOW #10). No `trap` for EXIT/INT/TERM cleanup. Fix: add trap
  handler.

- [ ] **L9 — `git diff --name-status` without `-z` breaks on tab-in-filename**
  kimi-k2.6 (LOW #11). Latent parsing bug, no real AUR filenames contain tabs.
  Fix: add `-z` + null-delimited parsing.

---

## Suggested fix order

| Priority | Finding | Effort | Surface |
|---|---|---|---|
| 1 | E — homograph bypass | Small | `_boring_added_line_class` + `source_domains` |
| 2 | F — .SRCINFO anchor poisoning | Medium | `_installed_matches` + PKGBUILD parser |
| 3 | J — git config isolation | Small | Export at script top; blankets all git commands |
| 4 | H — bunx/pnpm exec/yarn dlx | Small | 2 lines added to rule arrays |
| 5 | K — epoch=0 | Small | 2 comparisons in `_installed_matches` + `find_baseline_commit` |
| 6 | I — pip3 bypass | Small | 1 regex tweak |
| 7 | G — tier-2 review rules | Medium | `_scan_whole_pkg` + `missing_cache_gate` restructure |
| 8 | L — manifest race | Small | `flock` or per-run filename |
| 9 | M — ALLOW_REVIEW boolean | Small | 2 `-n` → `== "1"` |
| 10 | O — find_pkg_dir .git check | Small | 1 condition |
| 11 | Q — files_with_status rc | Small | Capture + assert pattern |
| 12 | R — pkg name regex | Small | 1 guard clause |
| 13 | P — quoted source FP | Small | 1 regex extension |
| 14 | N — split-pkg missing cache | Medium | **FIXED** — RPC pkgbase resolution |
| 15 | L1–L9 (low) | Varies | Various |

## Reviewer transcripts

| Reviewer | Session |
|---|---|
| glm-5.1 | `019f0517-d737-732f-b8d6-6ae4c3208309` |
| kimi-k2.6 | `019f0517-d73a-78d5-929f-c514eed1880d` |
| qwen3.7-max | `019f0517-d73a-78d5-929f-caae55c267e2` |
