# Finding H — `bunx`, `pnpm exec`, `yarn dlx` escape JS package-manager hard rules

**Source:** glm-5.1 red-team review, session `019f0517-d737-732f-b8d6-6ae4c3208309`  
**Status:** open  
**Severity:** high  
**Lines:** `add_rule pnpm` at aur-safe:135, `add_rule bun` at aur-safe:136, `add_rule yarn` at aur-safe:137

## What happens

Three JS package-manager exec-equivalents are missing from the hard-fail rules:

- **`bunx`** — Bun's `npx` equivalent. The `bun` rule at line 136 requires
  whitespace between `bun` and `(x|install|add)`, so `bunx evil-pkg` doesn't
  match. `bunx` has been the documented Wave 2 campaign exec-equivalent since
  June 12.
- **`pnpm exec`** — The pnpm alt list is `install|i|add|ci|run`. `exec` is
  missing.
- **`yarn dlx`** — yarn's `npx` equivalent since yarn berry. The yarn alt list
  is `add|install`. `dlx` is missing.

These three commands each fetch and execute JS packages from npm registry
without `npm install` being part of the visible diff — exactly the campaign
payload delivery mechanism. If placed in `build()` (not a `.install` hook), they
evade both the `install-hook-*` rule AND the JS package-manager rule.

Selftest covers `bun add`, `bun install`, `bun --cwd add` but not `bunx`.

## Fix

- Add `bunx` rule (mirror `npx` at line 134):
  `'bunx[[:space:]]+[[:alnum:]_@./-]'`
- Add `exec` to pnpm alt list (line 135)
- Add `dlx` to yarn alt list (line 137)

## Test gap

Add selftest cases for `bunx evil`, `pnpm exec evil`, and `yarn dlx evil`
matching hard-fail.
