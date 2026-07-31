# --- aur-safe wrapper (cross-shell: bash + zsh) ----------------------------
# Gates `yay -Syu` / `paru -Syu` before they reach pacman, and gates new installs
# (`-S <pkg>`). Everything else (-Q, -R, repo -S) passes through.
# Written POSIX-ish so it loads under both bash and zsh (no bash-only array
# slicing). Place in a file sourced by both shells, e.g. ~/.shrc.
#
# Exit 2 = review needed: interactive prompt offers [v]iew diff, [e]xplain,
# [y]es continue, or [N]o abort. Honors AUR_SAFE_ALLOW_REVIEW=1 when
# non-interactive.

if command -v aur-safe >/dev/null 2>&1; then
  # Resolve helper executables before defining the shadowing shell functions;
  # later dispatch must not re-enter a function or honor a changed PATH.
  _AUR_SAFE_YAY_BIN=$(command -v yay 2>/dev/null || true)
  _AUR_SAFE_PARU_BIN=$(command -v paru 2>/dev/null || true)
  case "$_AUR_SAFE_YAY_BIN" in */*) ;; *) _AUR_SAFE_YAY_BIN= ;; esac
  case "$_AUR_SAFE_PARU_BIN" in */*) ;; *) _AUR_SAFE_PARU_BIN= ;; esac

  # Run the real helper with Git's executable/config redirection namespace
  # scrubbed. Fixed command-scope config overrides local/global hooks, proxies,
  # and executable transports during helper fetch/checkout operations.
  _aur_safe_run_helper() {
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
  _aur_safe_classify() {
    local _a _sync=0 _upgrade=0 _other_op=0 _expect_pkg=0 _skip_arg=0
    [ $# -eq 0 ] && { echo AUR_SAFE_GATE; return 0; }
    for _a; do
      if [ "$_skip_arg" = 1 ]; then
        _skip_arg=0
        continue
      fi
      case "$_a" in
        # Options whose following operand is not a package target. Context-
        # changing options are rejected by dispatch below; these are safe to
        # preserve without feeding their values to `aur-safe audit`.
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
      echo AUR_SAFE_GATE
    fi
    return 0
  }

  _aur_safe_dispatch() {
    local _helper=$1 _line _gate=0 _out _rc _aur_safe_bin _rebuild_opt
    local _context_opt1 _context_opt2 _review_opt1 _review_opt2
    shift
    case "${_helper##*/}" in
      yay)
        _rebuild_opt=--rebuildall
        _context_opt1=--nomakepkgconf
        _context_opt2=
        _review_opt1=--nodiffmenu
        _review_opt2=--noeditmenu
        ;;
      paru)
        _rebuild_opt=--rebuild=all
        _context_opt1=--nochroot
        _context_opt2=--nolocalrepo
        _review_opt1=--skipreview
        _review_opt2=--nosavechanges
        ;;
      *) printf 'aur-safe: unsupported helper path: %s\n' "$_helper" >&2; return 1 ;;
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
        --sysroot|--sysroot=*|--arch|--arch=*|-r|-r*|-b|-b*|-[!-]*[rb]*|\
        --aururl|--aururl=*|--aurrpcur|--aurrpcur=*|\
        --aurrpcurl|--aurrpcurl=*|--mode|--mode=*|\
        --pacman|--pacman=*|--git|--git=*|--gitflags|--gitflags=*|\
        --gpg|--gpg=*|--gpgflags|--gpgflags=*|\
        --sudo|--sudo=*|--sudoflags|--sudoflags=*|--pkgctl|--pkgctl=*)
          printf 'aur-safe: custom helper/build trust context is unsupported; aborting\n' >&2
          return 1
          ;;
      esac
    done
    _aur_safe_bin=$(command -v aur-safe) || return 1
    _out=$(_aur_safe_classify "$@")
    # First pass only determines the mode; do not audit outside the transaction
    # lock or another gate can overwrite its staged state before install.
    while IFS= read -r _line; do
      [ "$_line" = AUR_SAFE_GATE ] && _gate=1
    done <<< "$_out"
    if [ "$_gate" = 1 ] || [ -n "$_out" ]; then
      local _sd
      _sd="${AUR_SAFE_STATE_DIR:-$HOME/.cache/aur-safe}"
      mkdir -p "$_sd" || return 1
      command -v flock >/dev/null 2>&1 || {
        printf 'aur-safe: flock is required for state locking\n' >&2
        return 1
      }
      # Hold one lock across audit/gate → helper build/install → accept.
      (
        flock 9 || exit 1
        export AUR_SAFE_LOCK_HELD=1
        if [ "$_gate" = 1 ]; then
          _aur_safe_gate || exit $?
        else
          : >"$_sd/last-gate" || exit 1
        fi
        # A combined `-Syu explicit-target` must audit both the pending update
        # set and explicit new AUR targets in this same locked manifest.
        export AUR_SAFE_STAGING=1
        while IFS= read -r _line; do
          [ -z "$_line" ] && continue
          [ "$_line" = AUR_SAFE_GATE ] && continue
          case "$_line" in
            PKG:*) _line=${_line#PKG:} ;;
            *) printf 'aur-safe: invalid classifier record\n' >&2; exit 1 ;;
          esac
          # Repository packages are outside the AUR trust path.
          if pacman -Si -- "$_line" >/dev/null 2>&1; then
            continue
          fi
          aur-safe audit "$_line" || exit $?
        done <<< "$_out"
        # Keep the transaction lock in this wrapper process, but do not expose
        # its capability fd/env to untrusted PKGBUILD code run by the helper.
        (
          exec 9>&-
          unset AUR_SAFE_LOCK_HELD AUR_SAFE_STAGING
          export AUR_SAFE_AS_MAKEPKG=1 AUR_SAFE_TRANSACTION_ACTIVE=1
          _aur_safe_run_helper "$_helper" --makepkg "$_aur_safe_bin" \
            --mflags '--cleanbuild --force' "$_rebuild_opt" "$_context_opt1" \
            ${_context_opt2:+"$_context_opt2"} "$_review_opt1" "$_review_opt2" \
            --pacman /usr/bin/pacman --git /usr/bin/git --gitflags '' \
            --gpg /usr/bin/gpg --gpgflags '' --sudo /usr/bin/sudo --sudoflags '' "$@"
        )
        _rc=$?
        # Promotion failure must be visible even though the helper's exit code
        # remains the wrapper's public result.
        aur-safe accept \
          || printf 'aur-safe: accept failed; trust anchor unchanged\n' >&2
        exit "$_rc"
      ) 9>"$_sd/run.lock"
      return $?
    fi
    AUR_SAFE_AS_MAKEPKG=1 AUR_SAFE_TRANSACTION_ACTIVE=0 \
      _aur_safe_run_helper "$_helper" --makepkg "$_aur_safe_bin" \
        --mflags '--cleanbuild --force' "$_rebuild_opt" "$_context_opt1" \
        ${_context_opt2:+"$_context_opt2"} "$_review_opt1" "$_review_opt2" \
        --pacman /usr/bin/pacman --git /usr/bin/git --gitflags '' \
        --gpg /usr/bin/gpg --gpgflags '' --sudo /usr/bin/sudo --sudoflags '' "$@"
  }

  _AUR_SAFE_MENU_INPUT=""
  _aur_safe_read_menu_input() {
    local _first _rest
    _AUR_SAFE_MENU_INPUT=""
    IFS= read -r -n 1 _first || return 1
    case "$_first" in
      $'\e') return 2 ;;
      ''|$'\n'|$'\r') return 0 ;;
    esac
    IFS= read -r _rest || return 1
    _AUR_SAFE_MENU_INPUT="$_first$_rest"
  }

  _aur_safe_gate() {
    aur-safe gate
    local _rc=$?
    case $_rc in
      0) return 0 ;;
      2) if [ "${AUR_SAFE_ALLOW_REVIEW:-}" = 1 ]; then
           return 0
         elif [ -t 0 ]; then
           local _ans _sd _pkg _diff
           _sd="${AUR_SAFE_STATE_DIR:-$HOME/.cache/aur-safe}"
           while :; do
             printf 'aur-safe: review needed — [v]iew diff / [e]xplain / [y]es continue / [N]/Esc abort: ' >&2
             _aur_safe_read_menu_input
             local _input_rc=$?
             [ "$_input_rc" -eq 2 ] && return 1
             [ "$_input_rc" -eq 0 ] || return 1
             _ans="$_AUR_SAFE_MENU_INPUT"
             case "$_ans" in
               y|Y) return 0 ;;
               n|N|'') return 1 ;;
               v|V)
                 _pkg=$(cat "$_sd/last-flag.pkg" 2>/dev/null || true)
                 _diff="$_sd/flag.${_pkg}.diff"
                 if [ -n "$_pkg" ] && [ -r "$_diff" ]; then
                   ${PAGER:-less} "$_diff"
                 else
                   printf 'aur-safe: no stashed diff found\n' >&2
                 fi
                 ;;
               e|E)
                 if aur-safe explain; then
                   :
                 else
                   printf 'aur-safe: explain failed (no stashed diff, credentials, or LLM backend)\n' >&2
                 fi
                 ;;
               *) printf 'aur-safe: enter v, e, y, or N\n' >&2 ;;
             esac
           done
         else
           printf 'aur-safe: review needed; no blocking rule fired (non-interactive; set AUR_SAFE_ALLOW_REVIEW=1 to continue after review)\n' >&2
           return 1
         fi ;;
      *) printf 'aur-safe: gate stopped before helper ran. run: aur-safe explain\n' >&2; return 1 ;;
    esac
  }

  if [ -n "$_AUR_SAFE_YAY_BIN" ]; then
    yay() { _aur_safe_dispatch "$_AUR_SAFE_YAY_BIN" "$@"; }
  fi
  if [ -n "$_AUR_SAFE_PARU_BIN" ]; then
    paru() { _aur_safe_dispatch "$_AUR_SAFE_PARU_BIN" "$@"; }
  fi
fi
