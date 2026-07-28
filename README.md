# aur-safe

Deterministic gate for [Arch Linux AUR](https://aur.archlinux.org/) package
updates. Born during the May–June 2026 AUR supply-chain attack — catches
malicious updates before they reach pacman. Deterministic rules are the gate;
an opt-in LLM verifier can only auto-clear narrowly classified boring-edge
diffs. See
[docs/design-ledger.md](./docs/design-ledger.md) for the full design ledger (threat
model, settled decisions, rejected approaches, verification status).

## How it works

yay/paru keep a per-package git clone of the AUR repo (`~/.cache/yay/<pkg>` or
`~/.cache/paru/clone/<pkg>`). `origin/master` is the candidate update.
aur-safe keeps its **own** trust anchor, decoupled from the helper:

```
~/.cache/aur-safe/
  accepted/<pkgbase>   ← last audited+installed commit (trust anchor)
  staged/<pkgbase>     ← gate-time tip, pending build confirmation
  last-gate            ← per-run manifest for accept
  run.lock             ← gate → helper → accept transaction lock
```

On update, aur-safe runs before yay/paru and injects an exact-SHA guard through
the helpers' `--makepkg` option. The guard rechecks the staged checkout at the
last point before PKGBUILD is sourced. This is a shell wrapper, not a pacman
hook (hooks run after install—too late).

### Two gate paths

| Path | Condition | Mechanism |
|---|---|---|
| **Cached** | Helper has a git clone | `git diff accepted..origin/master` → rules |
| **Missing-cache** | Clone deleted/absent | Clone fresh, use retained history for a precise diff, then require whole-candidate review because that history is attacker-rewritable. Falls back to the same mandatory review if no baseline is found. |

Both paths share the same diff-based rule pipeline (`scan_diff_rules`), so they
can't drift.

### Two rule pipelines

| Pipeline | When used | Rules applied |
|---|---|---|
| **Diff** (`scan_diff_rules`) | Cached path, baseline recovery (tier 1) | Hard-fail + deterministic boring metadata allowlist + boring-edge review/optional verifier + structural review |
| **Whole-file** (`_scan_whole_pkg`) | `audit`, missing-cache fallback (tier 2) | Hard + review rules |

`audit` remains advisory for deliberate new installs. Missing-cache tier 2
always requires review (exit 2), even with no known pattern: without a baseline,
regex absence cannot prove arbitrary PKGBUILD shell is safe.

### Exit codes

| Code | Meaning | Wrapper action |
|---|---|---|
| 0 | Clean — no rule hits | Proceed |
| 1 | Block — deterministic risk or audit unavailable | Abort; cannot be consented past |
| 2 | Review — a real candidate was audited and needs consent | `aur-safe gate` / wrapper prompt: `[l]ist`, `[v]iew` diff, `[e]xplain`, `[y]es`, or `[N]o` (or auto-proceed if `AUR_SAFE_ALLOW_REVIEW=1`); `check` exits 2 for caller handling |
| 3 | Usage/env error | Surface |

## Install

```sh
git clone https://github.com/bermudi/aur-safe ~/build/aur-check
ln -s ~/build/aur-check/aur-safe ~/.local/bin/aur-safe
```

Dependencies: `bash` ≥ 5.3, `git`, `flock` (util-linux), and an AUR helper (`yay` or `paru`). `pi` is
required only for `explain` and the optional boring-edge verifier.

## Enable

Run `aur-safe wrapper`, paste the `yay()` / `paru()` function into your shell rc
(`~/.bashrc` or `~/.zshrc`), `exec $SHELL`. Regenerate this function after
every aur-safe upgrade: the wrapper owns transaction locking and injects the
exact-SHA/fresh-artifact makepkg guard.
From then on:

- `yay -Syu` / `paru -Syu` — gated before pacman
- `yay -S <pkg>` / `paru -S <pkg>` — advisory audit, then confirmed first-anchor staging for new AUR installs
- Non-building operations (`-Q`, `-R`, repo `-S`) pass through; any unexpected
  makepkg invocation outside an audited transaction blocks
- Custom makepkg/rebuild/mflags, alternate pacman roots/configs, and alternate
  AUR endpoints are rejected because they change the trust context

```
$ yay -Syu
aur-safe: gating 4 AUR update(s)
▶ cursor-bin  ok
▶ ventoy-bin  ok (baseline recovery)
▶ discord-ptb review — .install hook modified (consent required)
▶ some-pkg    BLOCKED — npm install in .install
```

## Usage

```
aur-safe gate              gate every pending AUR update
aur-safe check <pkg> ...   gate specific cached package(s); exits 2 on review
aur-safe audit <pkg>       advisory scan of an uncached/new package
aur-safe scan              retroactive scan of installed packages
aur-safe explain [pkg]     LLM second-opinion on last flagged diff
aur-safe accept            promote staged refs (called by the wrapper)
aur-safe rules             list active rules
aur-safe wrapper           print the suggested shell wrapper
aur-safe selftest          run built-in rule tests (249/249)
```

When several packages need review, choose `e`; an empty package selection
explains all flagged packages in gate order. Press Esc at any menu to cancel
immediately; the main review prompt also accepts `N`.

## Environment

| Variable | Default | Purpose |
|---|---|---|
| `AUR_SAFE_YAY_CACHE` | `~/.cache/yay` | yay cache directory |
| `AUR_SAFE_PARU_CACHE` | `~/.cache/paru/clone` | paru cache directory |
| `AUR_SAFE_STATE_DIR` | `~/.cache/aur-safe` | State directory (accepted/staged/manifest) |
| `AUR_SAFE_MODEL` | `zai/glm-5.2` | LLM model for `explain` |
| `AUR_SAFE_BRANCH` | `master` | AUR remote branch |
| `AUR_SAFE_AUR_URL` | `https://aur.archlinux.org` | AUR base URL (mirrors, testing) |
| `AUR_SAFE_EXPLAIN_MAXLINES` | `1000` | Diff truncation for `explain` |
| `AUR_SAFE_CONFIG` | `~/.config/aur-safe/config` | Optional config file path |
| `AUR_SAFE_LLM_AUTO_BORING` | `0` | Set `1` to let the strict LLM verifier auto-clear boring-edge diffs |

Optional config file:

```sh
mkdir -p ~/.config/aur-safe
printf 'AUR_SAFE_LLM_AUTO_BORING=1\n' > ~/.config/aur-safe/config
```

Environment variables override the config file. Enabling
`AUR_SAFE_LLM_AUTO_BORING=1` trades deterministic-only gating for convenience on
diffs that deterministic checks already confined to parser-ambiguous metadata,
optional dependency, checksum, or same-host `source=()` changes. It cannot
override hard blocks, review hits, audit-unavailable results, or staging/accept
checks. The candidate diff is untrusted prompt content; prompt injection has no
fully reliable textual defense. Keep this option disabled if deterministic-only
gating is the requirement.

Wrapper-level (set in your shell rc):

| Variable | Purpose |
|---|---|
| `AUR_SAFE_ALLOW_REVIEW=1` | Auto-proceed on review flags (non-interactive) |

`AUR_SAFE_ALLOW_REVIEW=1` applies only after a real candidate was audited.
Fetch/clone/diff/state failures are exit 1 and cannot be auto-consented.

## Maintainer issue loop

`./ralph-loop` is a bounded, sequential GitHub-issue relay for this repository.
It snapshots open `security` issues in severity order (`critical` → `high` →
`medium` → `low`, then issue number), gives one issue to SWE-1.7, runs the full
deterministic gate, and asks a fresh GLM-5.2 session to review the complete
branch diff. Substantive review findings return to a fresh SWE-1.7 session; an
exact approval plus green checks fast-forwards `main`, pushes, writes the durable
finding pointer, and closes the issue.

```sh
./ralph-loop list       # inspect the ranked queue; no mutation
./ralph-loop run 1      # process one issue
./ralph-loop run        # process the captured, finite queue
```

The loop requires `devin`, `gh`, `git`, `jq`, `bwrap`, `flock`, and
`shellcheck`, starts only from a clean `main` equal to `origin/main`, and never
rebases, force-pushes, resets, or discards interrupted work. Agent processes run
in a bubblewrap mount namespace with the maintainer's home, SSH agent, desktop
keyring, and GitHub credentials hidden; the reviewer sees the worktree
read-only. Candidate-controlled verification runs separately with a read-only
worktree, empty environment, and no network. Runtime context and transcripts
live in ignored `.ralph-loop/`. While Devin is in non-interactive print mode,
the harness emits a progress heartbeat every 60
seconds with elapsed time, age of the latest internal Devin activity, and
worktree state. Five minutes without recorded activity is called out explicitly;
this is a stall signal, not proof that the process is dead. Set
`RALPH_HEARTBEAT_SECONDS=0` to disable heartbeats or choose another positive
interval.
Review/fix passes are capped; configure the caps, models, and heartbeat with the
`RALPH_*` variables shown by `./ralph-loop --help`.

This command directly pushes approved commits and closes issues. `run` is the
explicit publication boundary; use `list` when you only want to inspect order.

## Status

Single-user, single-machine. Hardened through multiple independent reviews (see
commit history and `docs/findings/`). A 2026-06-26 red-team review by three
delegate models found 23 findings — see [docs/findings/](./docs/findings/) for
the writeups and [docs/findings/README.md](./docs/findings/README.md) for the
catalog (open work tracked on GitHub issues). The trust anchor is aur-safe's own
accepted-ref state, created only after first-contact whole-candidate review and
advanced only after a gate-audited build that pacman's root-owned local DB binds
to the expected pkgbase and a fresh build/install. The generated wrapper also
injects an exact-staged-SHA guard through yay/paru's `--makepkg` seam, forces a
fresh artifact build, and rejects cache-reuse flags. Selftest: 249/249.

Licensed under the [MIT License](./LICENSE).

## Docs

- [docs/design-ledger.md](./docs/design-ledger.md) — canonical design ledger (threat model,
  architecture, settled decisions, rejected approaches, verification)
- [docs/threat-model.md](./docs/threat-model.md) — attacker profile, defensive
  principles, rule classification
- [docs/findings/](./docs/findings/) — documented security findings and fixes
  (catalog: [README](./docs/findings/README.md)); open work tracked on GitHub issues
