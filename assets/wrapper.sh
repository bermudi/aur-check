# --- aur-gate wrapper (cross-shell: bash + zsh) ----------------------------
# Gates `yay -Syu` / `paru -Syu` before they reach pacman, and gates new installs
# (`-S <pkg>`). Everything else (-Q, -R, repo -S) passes through.
# Written POSIX-ish so it loads under both bash and zsh (no bash-only array
# slicing). Place in a file sourced by both shells, e.g. ~/.shrc.
#
# Rust owns interactive review in both Bash and Zsh. Non-interactive review
# blocks unless AUR_GATE_ALLOW_REVIEW=1 was explicitly set.

if command -v aur-gate >/dev/null 2>&1; then
  # Resolve external helper executables even when an older sourced wrapper
  # already shadows their names with functions. This keeps wrapper updates
  # idempotent and ensures later dispatch cannot re-enter a function or honor a
  # changed PATH.
  if [ -n "${ZSH_VERSION:-}" ]; then
    _AUR_GATE_YAY_BIN=$(whence -p -- yay 2>/dev/null || true)
    _AUR_GATE_PARU_BIN=$(whence -p -- paru 2>/dev/null || true)
  else
    _AUR_GATE_YAY_BIN=$(type -P -- yay 2>/dev/null || true)
    _AUR_GATE_PARU_BIN=$(type -P -- paru 2>/dev/null || true)
  fi
  case "$_AUR_GATE_YAY_BIN" in */*) ;; *) _AUR_GATE_YAY_BIN= ;; esac
  case "$_AUR_GATE_PARU_BIN" in */*) ;; *) _AUR_GATE_PARU_BIN= ;; esac

  # Run the real helper with Git's executable/config redirection namespace
  # scrubbed. Fixed command-scope config overrides local/global hooks, proxies,
  # and executable transports during helper fetch/checkout operations.
  _aur_gate_run_helper() {
    env \
      -u GIT_EXEC_PATH -u GIT_CONFIG -u GIT_CONFIG_PARAMETERS \
      -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE -u GIT_COMMON_DIR \
      -u GIT_OBJECT_DIRECTORY -u GIT_ALTERNATE_OBJECT_DIRECTORIES \
      -u GIT_NAMESPACE -u GIT_SHALLOW_FILE -u GIT_REPLACE_REF_BASE \
      -u GIT_ATTR_SOURCE -u GIT_EXTERNAL_DIFF -u GIT_SSH -u GIT_SSH_COMMAND \
      -u GIT_PROXY_COMMAND -u GIT_ASKPASS \
      GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
      GIT_ASKPASS=/bin/true GIT_TERMINAL_PROMPT=0 \
      GIT_CONFIG_COUNT=8 \
      GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null \
      GIT_CONFIG_KEY_1=core.fsmonitor GIT_CONFIG_VALUE_1=false \
      GIT_CONFIG_KEY_2=core.sshCommand GIT_CONFIG_VALUE_2=/bin/false \
      GIT_CONFIG_KEY_3=core.gitProxy GIT_CONFIG_VALUE_3= \
      GIT_CONFIG_KEY_4=protocol.allow GIT_CONFIG_VALUE_4=never \
      GIT_CONFIG_KEY_5=protocol.http.allow GIT_CONFIG_VALUE_5=always \
      GIT_CONFIG_KEY_6=protocol.https.allow GIT_CONFIG_VALUE_6=always \
      GIT_CONFIG_KEY_7=protocol.ext.allow GIT_CONFIG_VALUE_7=never \
      "$@"
  }

  # Classify an arg list. Emits explicit sync targets plus a final `gate` for
  # sync+sysupgrade, or bare sysupgrade (helpers default it to sync). Flag
  # clusters are arbitrary: -Syu/-Su/-Sua gate; query -Qu and refresh-only -Sy
  # do not.
  _aur_gate_classify() {
    local _a _sync=0 _upgrade=0 _other_op=0 _expect_pkg=0 _skip_arg=0
    [ $# -eq 0 ] && { echo AUR_GATE_GATE; return 0; }
    for _a; do
      if [ "$_skip_arg" = 1 ]; then
        _skip_arg=0
        continue
      fi
      case "$_a" in
        # Options whose following operand is not a package target. Context-
        # changing options are rejected by dispatch below; these are safe to
        # preserve without feeding their values to `aur-gate audit`.
        --assume-installed|--ignore|--ignoregroup|--overwrite|--ask|\
        --cachedir|--hookdir|--gpgdir|--logfile|--print-format|--color|\
        --answerclean|--answerdiff|--answeredit|--answerupgrade|\
        --builddir|--clonedir|--sortby|--searchby|--editor|--editorflags|\
        --bat|--batflags|--fm|--fmflags|--requestsplitn|\
        --completioninterval|--limit|--develsuffixes)
          _skip_arg=1 ;;
        --sysupgrade) _upgrade=1 ;;
        --refresh) ;;
        --sync) _sync=1; _expect_pkg=1 ;;
        --query|--remove|--database|--files|--deptest|--upgrade) _other_op=1 ;;
        --) ;;
        # Short clusters can combine or split operation flags.
        -[!-]*)
          case "$_a" in *u*) _upgrade=1 ;; esac
          case "$_a" in *S*) _sync=1; _expect_pkg=1 ;; esac
          case "$_a" in *[QRDFTU]*) _other_op=1 ;; esac
          ;;
        -*) ;;
        *)
          if [ "$_expect_pkg" = 1 ]; then
            case "$_a" in
              .*|*[!a-zA-Z0-9@._+-]*) echo INVALID_TARGET ;;
              *) printf 'PKG:%s\n' "$_a" ;;
            esac
          fi
          ;;
      esac
    done
    if [ "$_upgrade" = 1 ] && { [ "$_sync" = 1 ] || [ "$_other_op" = 0 ]; }; then
      echo AUR_GATE_GATE
    fi
    return 0
  }

  _aur_gate_dispatch() {
    local _helper=$1 _line _gate=0 _out _rc _aur_gate_bin _rebuild_opt
    local _context_opt1 _context_opt2 _review_opt1 _review_opt2
    shift
    case "${_helper##*/}" in
      yay)
        _rebuild_opt=--rebuildall
        _context_opt1=--nomakepkgconf
        _context_opt2=
        _review_opt1=--diffmenu=false
        _review_opt2=--editmenu=false
        ;;
      paru)
        _rebuild_opt=--rebuild=all
        _context_opt1=--nochroot
        _context_opt2=--nolocalrepo
        _review_opt1=--skipreview
        _review_opt2=--nosavechanges
        ;;
      *) printf 'aur-gate: unsupported helper path: %s\n' "$_helper" >&2; return 1 ;;
    esac
    for _line in "$@"; do
      case "$_line" in
        --makepkg|--makepkg=*|--mflags|--mflags=*|\
        --makepkgconf|--makepkgconf=*|\
        --rebuild|--rebuild=*|--rebuildall|--rebuildtree|\
        --norebuild|--norebuild=*|--no-rebuild|--no-rebuild=*|\
        --chroot|--chroot=*|--nochroot|--no-chroot|\
        --localrepo|--localrepo=*|--nolocalrepo|--no-localrepo|\
        --config|--config=*|--root|--root=*|--dbpath|--dbpath=*|\
        --hookdir|--hookdir=*|--cachedir|--cachedir=*|\
        --gpgdir|--gpgdir=*|--logfile|--logfile=*|\
        --sysroot|--sysroot=*|--arch|--arch=*|-r|-r*|-b|-b*|-[!-]*[rb]*|\
        --aururl|--aururl=*|--aurrpcur|--aurrpcur=*|\
        --aurrpcurl|--aurrpcurl=*|--mode|--mode=*|\
        --pacman|--pacman=*|--git|--git=*|--gitflags|--gitflags=*|\
        --gpg|--gpg=*|--gpgflags|--gpgflags=*|\
        --sudo|--sudo=*|--sudoflags|--sudoflags=*|--pkgctl|--pkgctl=*)
          printf 'aur-gate: custom helper/build trust context is unsupported; aborting\n' >&2
          return 1
          ;;
      esac
    done
    _aur_gate_bin=$(command -v aur-gate) || return 1
    _out=$(_aur_gate_classify "$@")
    # First pass only determines the mode; do not audit outside the transaction
    # lock or another gate can overwrite its staged state before install.
    while IFS= read -r _line; do
      [ "$_line" = AUR_GATE_GATE ] && _gate=1
    done <<< "$_out"
    if [ "$_gate" = 1 ] || [ -n "$_out" ]; then
      local _sd
      # Resolve environment/config/default through the same typed Rust config
      # used by gate and accept; shell-side defaults can select the wrong lock.
      _sd=$("$_aur_gate_bin" state-dir) || return 1
      [ -n "$_sd" ] || return 1
      export AUR_GATE_STATE_DIR="$_sd"
      # Rust validates ownership, mode, and symlink hygiene before shell
      # redirection opens the transaction lock.
      "$_aur_gate_bin" init-state || return 1
      command -v flock >/dev/null 2>&1 || {
        printf 'aur-gate: flock is required for state locking\n' >&2
        return 1
      }
      # Hold one lock across audit/gate → helper build/install → accept.
      (
        flock 9 || exit 1
        export AUR_GATE_LOCK_HELD=1
        if [ "$_gate" = 1 ]; then
          _aur_gate_gate || exit $?
        else
          "$_aur_gate_bin" begin || exit $?
        fi
        # A combined `-Syu explicit-target` must audit both the pending update
        # set and explicit new AUR targets in this same locked manifest.
        export AUR_GATE_STAGING=1
        while IFS= read -r _line; do
          [ -z "$_line" ] && continue
          [ "$_line" = AUR_GATE_GATE ] && continue
          case "$_line" in
            PKG:*) _line=${_line#PKG:} ;;
            *) printf 'aur-gate: invalid classifier record\n' >&2; exit 1 ;;
          esac
          # Repository packages are outside the AUR trust path.
          if pacman -Si -- "$_line" >/dev/null 2>&1; then
            continue
          fi
          aur-gate audit "$_line" || exit $?
        done <<< "$_out"
        # Keep the transaction lock in this wrapper process, but do not expose
        # its capability fd/env to untrusted PKGBUILD code run by the helper.
        (
          exec 9>&-
          unset AUR_GATE_LOCK_HELD AUR_GATE_STAGING
          export AUR_GATE_AS_MAKEPKG=1 AUR_GATE_TRANSACTION_ACTIVE=1
          _aur_gate_run_helper "$_helper" --makepkg "$_aur_gate_bin" \
            --mflags '--cleanbuild --force' "$_rebuild_opt" "$_context_opt1" \
            ${_context_opt2:+"$_context_opt2"} "$_review_opt1" "$_review_opt2" \
            --pacman /usr/bin/pacman --git /usr/bin/git --gitflags '' \
            --gpg /usr/bin/gpg --gpgflags '' --sudo /usr/bin/sudo --sudoflags '' "$@"
        )
        _rc=$?
        if [ "$_rc" -eq 0 ]; then
          # Promotion failure must be visible even though the helper's exit code
          # remains the wrapper's public result.
          "$_aur_gate_bin" accept \
            || printf 'aur-gate: accept failed; trust anchor unchanged\n' >&2
        else
          # A failed helper/guard transaction can never promote, even if an
          # unrelated same-version install appears concurrently.
          "$_aur_gate_bin" abort \
            || printf 'aur-gate: failed transaction manifest could not be cleared\n' >&2
        fi
        exit "$_rc"
      ) 9>"$_sd/run.lock"
      return $?
    fi
    AUR_GATE_AS_MAKEPKG=1 AUR_GATE_TRANSACTION_ACTIVE=0 \
      _aur_gate_run_helper "$_helper" --makepkg "$_aur_gate_bin" \
        --mflags '--cleanbuild --force' "$_rebuild_opt" "$_context_opt1" \
        ${_context_opt2:+"$_context_opt2"} "$_review_opt1" "$_review_opt2" \
        --pacman /usr/bin/pacman --git /usr/bin/git --gitflags '' \
        --gpg /usr/bin/gpg --gpgflags '' --sudo /usr/bin/sudo --sudoflags '' "$@"
  }

  _aur_gate_gate() {
    # Rust owns review interaction for both Bash and Zsh. A returned review code
    # means non-interactive consent was unavailable, so the wrapper blocks.
    "$_aur_gate_bin" gate
    local _rc=$?
    case $_rc in
      0) return 0 ;;
      2) printf 'aur-gate: review required; helper not run\n' >&2; return 1 ;;
      *) printf 'aur-gate: gate stopped before helper ran. run: aur-gate explain\n' >&2; return 1 ;;
    esac
  }

  if [ -n "$_AUR_GATE_YAY_BIN" ]; then
    yay() { _aur_gate_dispatch "$_AUR_GATE_YAY_BIN" "$@"; }
  fi
  if [ -n "$_AUR_GATE_PARU_BIN" ]; then
    paru() { _aur_gate_dispatch "$_AUR_GATE_PARU_BIN" "$@"; }
  fi
fi
