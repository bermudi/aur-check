/// Generated shell wrapper. It shadows yay/paru and holds the transaction lock
/// across gate → helper → accept.
pub const WRAPPER: &str = include_str!("../assets/wrapper.sh");

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::process::Command;

    fn executable(path: &Path) {
        fs::write(path, "#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).unwrap();
    }

    fn classify(args: &[&str]) -> String {
        let temp = tempfile::tempdir().unwrap();
        for binary in ["aur-gate", "yay", "paru"] {
            executable(&temp.path().join(binary));
        }
        let path = format!(
            "{}:{}",
            temp.path().display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let wrapper = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/wrapper.sh");
        let output = Command::new("bash")
            .env("PATH", path)
            .arg("-c")
            .arg("source \"$1\"; shift; _aur_gate_classify \"$@\"")
            .arg("wrapper-test")
            .arg(wrapper)
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "wrapper classifier failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    #[test]
    fn wrapper_classification_matches_bash_oracle() {
        let cases: &[(&[&str], &str)] = &[
            (&[], "AUR_GATE_GATE\n"),
            (&["-Syu"], "AUR_GATE_GATE\n"),
            (&["-Sua"], "AUR_GATE_GATE\n"),
            (&["-Syyu"], "AUR_GATE_GATE\n"),
            (&["-Syua"], "AUR_GATE_GATE\n"),
            (&["-Su"], "AUR_GATE_GATE\n"),
            (&["--sysupgrade"], "AUR_GATE_GATE\n"),
            (&["-S", "-u"], "AUR_GATE_GATE\n"),
            (&["-Sua", "--noconfirm"], "AUR_GATE_GATE\n"),
            (&["-Syu", "explicit"], "PKG:explicit\nAUR_GATE_GATE\n"),
            (&["-S", "foo"], "PKG:foo\n"),
            (&["-S", "UpperCase-Pkg"], "PKG:UpperCase-Pkg\n"),
            (&["-S", "foo", "bar"], "PKG:foo\nPKG:bar\n"),
            (&["-S", "foo", "--needed", "bar"], "PKG:foo\nPKG:bar\n"),
            (&["-S", "--assume-installed", "fake=1", "foo"], "PKG:foo\n"),
            (&["-S", "--color", "always", "foo"], "PKG:foo\n"),
            (&["-S", "gate"], "PKG:gate\n"),
            (&["-S", "../bad"], "INVALID_TARGET\n"),
            (&["-Sy"], ""),
            (&["--refresh"], ""),
            (&["-Q"], ""),
            (&["-Qu"], ""),
            (&["-Q", "cursor-bin"], ""),
            (&["-R", "foo"], ""),
        ];
        for (args, expected) in cases {
            assert_eq!(classify(args), *expected, "args: {args:?}");
        }
    }

    #[test]
    fn wrapper_pins_transaction_and_helper_security_contract() {
        for fragment in [
            "flock 9",
            "AUR_GATE_LOCK_HELD=1",
            "exec 9>&-",
            "unset AUR_GATE_LOCK_HELD AUR_GATE_STAGING",
            "AUR_GATE_TRANSACTION_ACTIVE=1",
            "AUR_GATE_TRANSACTION_ACTIVE=0",
            "--rebuildall",
            "--rebuild=all",
            "--nomakepkgconf",
            "--nochroot",
            "--nolocalrepo",
            "--cleanbuild --force",
            "--norebuild",
            "--pacman /usr/bin/pacman",
            "--git /usr/bin/git --gitflags ''",
            "--gpg /usr/bin/gpg --gpgflags ''",
            "--sudo /usr/bin/sudo --sudoflags ''",
            "--hookdir|--hookdir=*",
            "--cachedir|--cachedir=*",
            "--gpgdir|--gpgdir=*",
            "--logfile|--logfile=*",
            "GIT_CONFIG_COUNT=9",
            "GIT_CONFIG_KEY_0=core.hooksPath",
            "GIT_CONFIG_KEY_4=protocol.allow",
            "GIT_CONFIG_KEY_8=core.commitGraph",
            "-u GIT_EXEC_PATH",
            "-u GIT_CONFIG_PARAMETERS",
        ] {
            assert!(
                WRAPPER.contains(fragment),
                "missing wrapper contract: {fragment}"
            );
        }
    }

    #[test]
    fn wrapper_parses_in_bash_and_zsh() {
        let wrapper = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/wrapper.sh");
        for shell in ["bash", "zsh"] {
            let status = Command::new(shell)
                .arg("-n")
                .arg(&wrapper)
                .status()
                .unwrap();
            assert!(status.success(), "{shell} rejected wrapper syntax");
        }
    }
}
