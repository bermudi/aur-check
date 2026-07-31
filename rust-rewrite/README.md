# aur-safe (Rust rewrite)

A Rust port of the deterministic AUR update gate. The trust model is unchanged:
`accepted/<pkgbase>` advances only after the exact staged commit was audited,
the generated wrapper guarded the helper checkout at the makepkg seam, and
pacman's root-owned local database confirms a fresh install.

**Validation status:** 83 Rust unit/integration tests and 59 embedded self-test
assertions pass; the live missing-cache path has also been exercised. The root
Bash oracle still has broader coverage (324 assertions) and passes in full. This
is not yet a one-for-one parity certification, so treat the root implementation
as the release version until the remaining command-flow scenarios are covered.

The LLM is **not** part of the deterministic gate. It is used only for:

- `aur-safe explain` (advisory second opinion), and
- the opt-in strict verifier for deterministic `boring_edge` results.

It cannot clear hard, review, or audit-unavailable classifications.

## Build and verify

```sh
cargo build --release
cargo test --all-targets
cargo run -- selftest
```

The wrapper is required for the complete gate → helper → accept transaction:

```sh
cargo run -- wrapper > ~/.config/aur-safe-wrapper.sh
# source that file from the shell(s) where yay/paru are used
```

## LLM configuration

The implementation uses [`llm`](https://docs.rs/llm/latest/llm/) directly; it
does not execute or depend on `pi`.

```sh
export AUR_SAFE_LLM_BACKEND=openrouter
export AUR_SAFE_MODEL=z-ai/glm-5.2
export OPENROUTER_API_KEY=...
```

Compiled backends are `openai`, `anthropic`, `ollama`, `deepseek`, and
`openrouter`. Provider keys use their normal environment variables
(`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`,
`OPENROUTER_API_KEY`, or optional `OLLAMA_API_KEY`).
`AUR_SAFE_LLM_API_KEY` is a provider-neutral override. Secrets are never read
from aur-safe's plain-text config file.

For local Ollama:

```sh
export AUR_SAFE_LLM_BACKEND=ollama
export AUR_SAFE_MODEL=qwen3:8b
# optional; defaults to http://localhost:11434
export AUR_SAFE_LLM_BASE_URL=http://127.0.0.1:11434
```

The makepkg seam rejects **all untracked files** in the helper checkout. This is
intentional: an audited PKGBUILD can execute an arbitrary-name cached file before
makepkg verifies sources. If the guard reports untracked files, clean that helper
checkout and retry; aur-safe will not delete cache data on your behalf.

Set `AUR_SAFE_LLM_AUTO_BORING=1` only if the strict boring-edge verifier is
desired. Provider construction, credentials, transport, malformed output, and
any verdict other than the exact first line `VERDICT: BORING_EDGE_OK` all fail
closed to human review.
