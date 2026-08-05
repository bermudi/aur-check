# GH #28 — Repo-local `http.*` git config escapes the safety check (proxy/CA MITM)

**Source:** adversarial review (shared M2/H1; Review 2 H1), GitHub issue #28
**Status:** fixed (2026-08-04; structural reset superseded the prefix fix 2026-08-05)
**Severity:** high
**Lines:** current Rust boundary is `src/git.rs` `reset_local_config()` and
its fail-closed exact generated-config contract.

## What happens

`src/git.rs` `UNSAFE_KEY_PREFIXES` did not include `"http."`, and
`UNSAFE_CORE_KEYS` did not include `http.sslCAInfo` or `http.proxy`.
`local_config_is_safe()` therefore passed `.git/config` entries like:

```ini
[http]
    proxy = http://attacker:8080
    sslCAInfo = /tmp/evil-ca.pem
```

`SAFE_PRE` sets `http.sslVerify=true` via `-c`, but command-line `-c` does
**not** reliably override repo-local `http.*` because URL-scoped sections
(`[http "https://aur.archlinux.org"]`) take precedence over the global `-c`
value. A malicious `build()` that writes to the cached clone's `.git/config`
could therefore route the next `git fetch` through an attacker-controlled
proxy presenting an attacker-controlled CA bundle, defeating clone/fetch
integrity and letting an attacker serve a commit that passes the gate's
deterministic rules.

## Fix

The durable fix is stronger than adding another prefix: cached and fresh
checkouts now have `.git/config` atomically regenerated from the validated
HTTP(S) origin and branch refspec before Git reads it. The fixed generated
key/value contract contains no `http.*` namespace, while the fallback validator
rejects any changed, duplicate, or future key if an untrusted build rewrites
the file later. Each Rust Git child uses a private metadata view containing
the validated config, so it does not reopen the
mutable repository-local file. Fetches still use explicit validated HTTP(S)
URL/refspec arguments.

## Verification

- `cargo test --all-targets` — `reset_local_config_discards_unknown_keys`
  proves that `http.*`/include-style state is discarded, while
  `unknown_repo_local_config_is_rejected` proves an unknown future namespace
  fails closed if it appears after refresh.
- `cargo clippy --all-targets -- -D warnings` clean.
- `cargo run --quiet -- selftest` passes.

## Lesson

`-c` overrides are not a complete defence against repo-local config. Any
config namespace that admits URL-scoped subsections (`http.<url>.*`,
`url.<base>.insteadOf`, etc.) can override a global `-c` value. Regenerating the
small config namespace closes that class for known and future keys alike; the
private command view closes the validation-to-execution race; `-c` remains
defence in depth for rendering and transport defaults.
