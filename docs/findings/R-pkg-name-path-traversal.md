# Finding R — Package name regex allows `.`, `..`, `.git`

**Source:** kimi-k2.6 red-team review, session `019f0517-d73a-78d5-929f-c514eed1880d`  
**Status:** open  
**Severity:** medium  
**Lines:** `check_pkg()` at aur-safe:985, `cmd_audit()` at aur-safe:1444

## What happens

The package name validation regex `^[a-z0-9@._+-]+$` allows `.`, `..`, and names
starting with `.` (like `.git`). A user manually running `aur-safe check ..` or
`aur-safe audit .git` passes validation:

- `find_pkg_dir "."` fast-path checks `"$base/./.git"` which resolves to the
  current directory. If CWD is a git repo, `check_pkg` would diff it, fetch from
  its origin, and potentially stage its HEAD under the name `.`.
- `cmd_audit .git` would attempt to clone `AUR_URL/.git.git`.

While `cmd_gate` gets names from `yay -Qua` (which won't emit `.` or `..`),
`check` and `audit` are user-facing entry points. Accepting path-like names
violates the boundary validation principle: "Package names go into git URLs and
flag-file paths; they're regex-validated at entry points."

## Fix

Reject names matching `^\.`, `^\.\.$`, `^\.git$` in the validation regex.
Simplest: add a separate guard `[[ "$pkg" == . || "$pkg" == .. || "$pkg" == .git ]] && return 3`.

## Test gap

No selftest rejects `.`, `..`, `.git` as package names.
