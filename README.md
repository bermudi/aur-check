# aur-gate

A deterministic pre-install gate for Arch Linux AUR updates, implemented in
Rust. It was created during the May–June 2026 AUR supply-chain attack to stop a
malicious candidate before yay/paru reaches makepkg or pacman.

The former Bash implementation is frozen under [`archive/bash/`](archive/bash/README.md).
Rust is the supported implementation and policy oracle.

## Trust model

```text
~/.cache/aur-gate/
  accepted/<pkgbase>   last exact commit audited and freshly installed
  staged/<pkgbase>     audited candidate awaiting install confirmation
  last-gate            active transaction manifest
  run.lock             gate → helper → accept lock
```

The generated shell wrapper intercepts yay/paru and holds one lock across the
complete transaction. The gate captures one immutable candidate SHA. At the
makepkg seam, aur-gate requires the helper checkout to equal that staged SHA,
checks committed regular-file surfaces, rejects dirty or untracked files, and
forces a fresh build. `accept` advances the anchor only when pacman's root-owned
local database confirms the staged version, pkgbase identity, build time, and
install time.

A blocked, unavailable, moved, stale, or uninstalled candidate cannot advance
the trust anchor.

### Gate paths

- **Cached:** validate canonical AUR origin, fetch explicit HTTP(S) refspec, and
  classify `accepted..candidate`.
- **Missing cache:** clone fresh, reconstruct the installed-version baseline
  when retained history permits, run the same diff pipeline, and always require
  whole-candidate review because AUR history is attacker-rewritable. Without a
  baseline, whole-candidate review remains mandatory.

### Classification

- Hard deterministic findings block (`1`).
- Narrow positive-grammar metadata can pass (`0`).
- Human review is required for review signals and baseline-less candidates (`2`).
- Audit, transport, framing, state, or evidence failure blocks (`1`).
- The optional LLM verifier can clear only deterministic `BoringEdge`; it can
  never override hard, review, or unavailable classifications.

See [`docs/design-ledger.md`](docs/design-ledger.md) and
[`docs/threat-model.md`](docs/threat-model.md).

## Build and install

```sh
cargo build --release
install -Dm755 target/release/aur-gate ~/.local/bin/aur-gate
```

Runtime dependencies: `/usr/bin/git`, `/usr/bin/curl`, `/usr/bin/less`,
pacman/pacman-conf, util-linux `flock`, and yay or paru. Building requires a current Rust toolchain.
Pi is not used; advisory LLM support uses the Rust `llm` crate directly.

## Enable the wrapper

Generate and source a fresh wrapper after every upgrade:

```sh
aur-gate wrapper > ~/.config/aur-gate-wrapper.sh
printf '\nsource ~/.config/aur-gate-wrapper.sh\n' >> ~/.bashrc  # or ~/.zshrc
exec "$SHELL"
```

The wrapper is required for the full exact-SHA build-time guarantee.

- `yay -Syu` / `paru -Syu` gates pending AUR updates.
- `yay -S <pkg>` / `paru -S <pkg>` audits explicit AUR installs.
- Repository packages and non-building operations pass through.
- Alternate helper trust contexts, custom makepkg programs/mflags, roots,
  configs, and AUR endpoints are rejected.

## Commands

```text
aur-gate gate                gate pending AUR updates
aur-gate check <pkg> ...     check named package candidates
aur-gate audit <pkg>         whole-candidate audit for explicit install
aur-gate scan                report suspicious installed hook surfaces
aur-gate explain [pkg]       advisory LLM analysis of stashed evidence
aur-gate accept              promote freshly installed staged refs
aur-gate rules               list deterministic rules
aur-gate wrapper             print the Bash/Zsh wrapper
aur-gate selftest            run embedded deterministic assertions
```

Exit codes: `0` clean/complete, `1` blocked or audit-unavailable, `2` review,
`3` usage/configuration error.

## Configuration

Non-secret settings use environment > config file > default. The default config
file is `~/.config/aur-gate/config`.

| Variable | Default |
|---|---|
| `AUR_GATE_YAY_CACHE` | `~/.cache/yay` |
| `AUR_GATE_PARU_CACHE` | `~/.cache/paru/clone` |
| `AUR_GATE_STATE_DIR` | `~/.cache/aur-gate` |
| `AUR_GATE_BRANCH` | `master` |
| `AUR_GATE_AUR_URL` | `https://aur.archlinux.org` |
| `AUR_GATE_LLM_BACKEND` | `openrouter` |
| `AUR_GATE_MODEL` | `z-ai/glm-5.2` |
| `AUR_GATE_LLM_TIMEOUT_SECONDS` | `120` |
| `AUR_GATE_EXPLAIN_MAXLINES` | `1000` |
| `AUR_GATE_LLM_AUTO_BORING` | `0` |

Supported LLM backends are OpenAI, Anthropic, Ollama, DeepSeek, and OpenRouter.
API keys are environment-only. `AUR_GATE_LLM_AUTO_BORING=1` is opt-in and does
not expand LLM authority beyond deterministic boring-edge candidates.

`AUR_GATE_ALLOW_REVIEW=1` permits reviewed candidates to proceed in
non-interactive wrapper runs. It cannot consent past an audit failure or hard
block.

## Verification

```sh
cargo fmt --check
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo run --quiet -- selftest
bash -n assets/wrapper.sh
zsh -n assets/wrapper.sh
```

Current coverage includes production startup/curl/RPC boundaries, missing-cache
HTTP flows, explicit and split-package command flows, complete yay/paru wrapper
transactions, helper/build/install failures, exact-SHA window commits, and fresh
pacman evidence.

## Security status

The durable finding catalog is [`docs/findings/README.md`](docs/findings/README.md).
Open work is tracked in GitHub issues. Availability limits for exceptionally
large hostile repositories remain tracked as issue #17; limits must fail closed
and may never classify truncated input as safe.

Licensed under the MIT License.
