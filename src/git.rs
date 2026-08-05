//! Hardened git wrapper (Finding J + H1 / issue #5, #27).
//!
//! Every git call goes through `safe_git`. It strips caller-injected env,
//! forces diff/show options that defeat diff.external / textconv / word-diff /
//! color / noprefix games, disables `git replace` and grafted history,
//! and fails closed on repo-local `.git/config` keys that can alter output,
//! redirect fetches, or execute code.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Global `-c` overrides. Order matters: appended AFTER any caller options so
/// the last value wins. Mirrors `safe_pre` in the script.
const SAFE_PRE: &[&str] = &[
    "-c",
    "core.pager=cat",
    "-c",
    "pager.diff=cat",
    "-c",
    "pager.show=cat",
    "-c",
    "core.quotepath=false",
    "-c",
    "core.attributesFile=",
    "-c",
    "core.excludesFile=",
    "-c",
    "core.hooksPath=",
    "-c",
    "color.ui=false",
    "-c",
    "color.diff=false",
    "-c",
    "diff.wordDiff=none",
    "-c",
    "diff.colorWords=false",
    "-c",
    "diff.mnemonicPrefix=false",
    "-c",
    "diff.noprefix=false",
    "-c",
    "diff.colorMoved=false",
    "-c",
    "http.sslVerify=true",
    // No repository may select an executable transport. AUR traffic is HTTP(S)
    // only; command-line config has higher priority than local config.
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.http.allow=always",
    "-c",
    "protocol.https.allow=always",
    "-c",
    "protocol.ext.allow=never",
];

/// Subcommand guards for diff/show (the commands that render diffs).
fn safe_mid(subcommand: &str) -> &'static [&'static str] {
    match subcommand {
        "diff" | "show" => &[
            "--no-ext-diff",
            "--no-textconv",
            "--word-diff=none",
            "--text",
        ],
        _ => &[],
    }
}

/// Run git with safe global options. `repo` is the optional `-C` dir.
/// `args` must begin with the subcommand (e.g. &["diff", "--name-only", ...]).
pub fn safe_git(repo: Option<&Path>, args: &[&str]) -> Result<Output> {
    Ok(safe_git_command(repo, args)?.output()?)
}

/// Build a hardened git command for callers that need streaming stdin/stdout
/// (notably `cat-file --batch`). The same config and environment checks as
/// `safe_git` are applied before the caller can spawn it.
pub(crate) fn safe_git_command(repo: Option<&Path>, args: &[&str]) -> Result<Command> {
    let subcommand = args.first().copied().unwrap_or("");
    if subcommand.is_empty() {
        bail!("git_safe: no subcommand");
    }

    let mut cmd = Command::new("/usr/bin/git");
    cmd.arg("--no-pager");
    // Issue #27: never honour `git replace` refs for any object resolution.
    cmd.arg("--no-replace-objects");
    if let Some(dir) = repo {
        cmd.arg("-C").arg(dir);
    }
    cmd.args(SAFE_PRE);
    cmd.arg(subcommand);
    cmd.args(safe_mid(subcommand));
    cmd.args(&args[1..]);

    isolate_git_env(&mut cmd);

    // Fail closed on unsafe repo-local config (skip init/clone: no config yet).
    if subcommand != "init" && subcommand != "clone" {
        let dir = match repo {
            Some(path) => path.to_path_buf(),
            None => std::env::current_dir().context("resolve current directory for git")?,
        };
        if !local_config_is_safe(&dir)? {
            bail!("git_safe: unsafe repo config in {}", dir.display());
        }
    }

    Ok(cmd)
}

const CRITICAL_GIT_ENV: &[&str] = &[
    "GIT_EXEC_PATH",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_SHALLOW_FILE",
    "GIT_REPLACE_REF_BASE",
    "GIT_ATTR_SOURCE",
    "GIT_EXTERNAL_DIFF",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_PROXY_COMMAND",
    "GIT_ASKPASS",
];

fn isolate_git_env(cmd: &mut Command) {
    // Git has many redirection/execution variables, including GIT_EXEC_PATH,
    // GIT_CONFIG_PARAMETERS, GIT_COMMON_DIR, and the obvious GIT_DIR family.
    // A denylist ages badly; this process needs none of the caller's GIT_*
    // state, so remove the namespace wholesale and add back only fixed values.
    for variable in CRITICAL_GIT_ENV {
        cmd.env_remove(variable);
    }
    for (key, _) in std::env::vars_os() {
        if key.as_encoded_bytes().starts_with(b"GIT_") {
            cmd.env_remove(key);
        }
    }
    for var in ["PAGER", "VISUAL", "EDITOR"] {
        cmd.env_remove(var);
    }
    cmd.env("GIT_PROXY_COMMAND", "");
    cmd.env("GIT_ASKPASS", "/bin/true");
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    // Issue #27: disable replacement refs even if a `--no-replace-objects`
    // command-line flag is somehow stripped by a caller. Grafts have no
    // command-line equivalent, so redirect their deprecated file explicitly.
    cmd.env("GIT_NO_REPLACE_OBJECTS", "1");
    cmd.env("GIT_GRAFT_FILE", "/dev/null");
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
    cmd.env("GIT_CONFIG_SYSTEM", "/dev/null");
}

/// Denylist of `.git/config` keys that can alter output / redirect / exec.
///
/// `http.` is blocked wholesale (issue #28): a repo-local `[http]` or
/// URL-scoped `[http "https://aur.archlinux.org"]` section can route fetches
/// through an attacker-controlled proxy and/or pin an attacker-controlled
/// `sslCAInfo`, defeating `http.sslVerify=true` set via `-c`. URL-scoped
/// sections override command-line `-c`, so blocking in
/// `local_config_is_safe()` is the only robust kill switch.
///
/// `includeIf.` is blocked wholesale (extends #5/#28): `[includeIf "..."]`
/// subsections do not start with `include.`, so the `include.` prefix alone
/// would let a repo-local `includeIf.<condition>.path` pull in an
/// attacker-controlled config file (which could itself set `http.*`, `url.*`,
/// `alias.*`, etc., bypassing every other prefix check). The includeIf
/// directive is the canonical config-injection vector and must be denied at
/// the prefix level.
const UNSAFE_KEY_PREFIXES: &[&str] = &[
    "diff.",
    "url.",
    "filter.",
    "alias.",
    "include.",
    "includeif.",
    "credential.",
    "submodule.",
    "protocol.",
    "http.",
];
const UNSAFE_CORE_KEYS: &[&str] = &[
    "core.attributesfile",
    "core.hookspath",
    "core.pager",
    "core.sshcommand",
    "core.askpass",
    "core.editor",
    "core.excludesfile",
    "core.worktree",
    "core.fsmonitor",
    "core.gitproxy",
];

fn local_config_is_safe(dir: &Path) -> Result<bool> {
    let mut command = Command::new("/usr/bin/git");
    command
        .arg("-C")
        .arg(dir)
        .arg("--no-pager")
        .arg("-c")
        .arg("core.pager=cat")
        .args(["config", "--local", "--list", "--name-only"]);
    isolate_git_env(&mut command);
    let out = command.output()?;

    if !out.status.success() {
        return Ok(false); // unreadable config => fail closed
    }

    let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
    for key in text.lines() {
        if UNSAFE_KEY_PREFIXES.iter().any(|p| key.starts_with(p))
            || UNSAFE_CORE_KEYS.contains(&key)
            || (key.starts_with("remote.") && key.ends_with(".proxy"))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Locate the git directory for a normal or linked worktree checkout.
fn resolve_git_dir(repo: &Path) -> Result<Option<PathBuf>> {
    let dotgit = repo.join(".git");
    if dotgit.is_dir() {
        return Ok(Some(dotgit));
    }
    if dotgit.is_file() {
        let content = fs::read_to_string(&dotgit)
            .with_context(|| format!("cannot read {} for worktree gitdir", dotgit.display()))?;
        for line in content.lines() {
            if let Some(path) = line.strip_prefix("gitdir:") {
                let path = path.trim();
                let p = Path::new(path);
                return Ok(Some(if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    dotgit
                        .parent()
                        .expect(".git has a parent")
                        .join(p)
                        .canonicalize()
                        .with_context(|| format!("cannot resolve worktree gitdir {path}"))?
                }));
            }
        }
    }
    Ok(None)
}

/// Issue #27: remove `refs/replace/*` and `info/grafts` from a cached clone.
///
/// A malicious PKGBUILD running as the user can plant replacement refs or
/// a grafts file in the shared cache. Replacement refs can substitute the
/// object behind an audited SHA; grafts can rewrite ancestry used by history
/// walks and range selection. `safe_git` ignores both mechanisms through its
/// command/environment isolation. This purge is a second line of defence that
/// removes the persistent artifacts before a helper can reuse the cache with
/// different Git isolation.
pub(crate) fn purge_replace_artifacts(repo: &Path) -> Result<()> {
    let list = safe_git(
        Some(repo),
        &["for-each-ref", "--format=%(refname)", "refs/replace"],
    )?;
    if !list.status.success() {
        bail!("cannot list replace refs in {}", repo.display());
    }
    for refname in String::from_utf8_lossy(&list.stdout).lines() {
        if refname.is_empty() {
            continue;
        }
        let out = safe_git(Some(repo), &["update-ref", "-d", refname])?;
        if !out.status.success() {
            bail!("cannot delete replace ref {refname} in {}", repo.display());
        }
    }
    if let Some(gitdir) = resolve_git_dir(repo)? {
        let grafts = gitdir.join("info/grafts");
        match fs::symlink_metadata(&grafts) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                bail!("grafts path is a directory: {}", grafts.display());
            }
            Ok(_) => {
                fs::remove_file(&grafts)
                    .with_context(|| format!("cannot remove grafts file {}", grafts.display()))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("cannot inspect grafts file {}", grafts.display()));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn git_environment_namespace_is_removed() {
        let command = safe_git_command(None, &["status"]).unwrap();
        let env: Vec<_> = command.get_envs().collect();
        for variable in CRITICAL_GIT_ENV {
            let value = env
                .iter()
                .find_map(|(key, value)| (*key == OsStr::new(variable)).then_some(*value));
            if *variable == "GIT_PROXY_COMMAND" || *variable == "GIT_ASKPASS" {
                assert!(
                    value.flatten().is_some(),
                    "{variable} must be replaced safely"
                );
            } else {
                assert_eq!(value, Some(None), "{variable} must be removed");
            }
        }

        for (variable, expected) in [
            ("GIT_NO_REPLACE_OBJECTS", "1"),
            ("GIT_GRAFT_FILE", "/dev/null"),
        ] {
            let value = env
                .iter()
                .find_map(|(key, value)| (*key == OsStr::new(variable)).then_some(*value));
            assert_eq!(
                value.flatten().map(|s| s.to_os_string()),
                Some(std::ffi::OsString::from(expected)),
                "{variable} must be set to {expected}"
            );
        }
    }

    #[test]
    fn repo_local_protocol_override_is_rejected() {
        for (key, value) in [
            ("protocol.ext.allow", "always"),
            ("diff.external", "/tmp/evil"),
            ("url.ext::evil.insteadOf", "https://aur.archlinux.org"),
            ("filter.payload.smudge", "/tmp/evil"),
            ("core.hooksPath", "/tmp/hooks"),
            ("remote.origin.proxy", "command"),
            ("include.path", "/tmp/evil-config"),
            ("http.proxy", "http://attacker:8080"),
            ("http.sslcainfo", "/tmp/evil-ca.pem"),
            (
                "http.https://aur.archlinux.org.proxy",
                "http://attacker:8080",
            ),
            // includeIf.<condition>.path does not start with `include.` and is
            // the canonical config-injection vector (extends #5/#28).
            ("includeif.onbranch.main.path", "/tmp/evil-config"),
        ] {
            let temp = tempfile::tempdir().unwrap();
            assert!(Command::new("/usr/bin/git")
                .args(["init", "-q"])
                .arg(temp.path())
                .status()
                .unwrap()
                .success());
            assert!(Command::new("/usr/bin/git")
                .arg("-C")
                .arg(temp.path())
                .args(["config", key, value])
                .status()
                .unwrap()
                .success());
            assert!(
                safe_git(Some(temp.path()), &["status", "--short"]).is_err(),
                "unsafe local config was accepted: {key}"
            );
        }
    }

    #[test]
    fn replace_objects_are_disabled_by_git_command() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        assert!(std::process::Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .arg(repo)
            .status()
            .unwrap()
            .success());
        for (k, v) in [("user.email", "t@t"), ("user.name", "t")] {
            assert!(std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["config", k, v])
                .status()
                .unwrap()
                .success());
        }

        std::fs::write(repo.join("PKGBUILD"), "original\n").unwrap();
        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["add", "PKGBUILD"])
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["commit", "-q", "-m", "original commit"])
            .status()
            .unwrap()
            .success());
        let original = String::from_utf8(
            std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();

        std::fs::write(repo.join("PKGBUILD"), "replaced\n").unwrap();
        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["commit", "-q", "-am", "replace commit"])
            .status()
            .unwrap()
            .success());
        let replacement = String::from_utf8(
            std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();

        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["replace", &original, &replacement])
            .status()
            .unwrap()
            .success());

        // A plain git call resolves the replacement.
        let raw = std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["show", "--no-patch", "--format=%s", &original])
            .output()
            .unwrap()
            .stdout;
        assert_eq!(
            String::from_utf8_lossy(&raw).trim(),
            "replace commit",
            "fixture: plain git should honour the replace ref"
        );

        // safe_git must see the original object.
        let safe = safe_git(
            Some(repo),
            &["show", "--no-patch", "--format=%s", &original],
        )
        .unwrap();
        assert!(safe.status.success());
        assert_eq!(
            String::from_utf8_lossy(&safe.stdout).trim(),
            "original commit"
        );
    }

    #[test]
    fn grafts_are_disabled_by_safe_git() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        assert!(std::process::Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .arg(repo)
            .status()
            .unwrap()
            .success());
        for (k, v) in [("user.email", "t@t"), ("user.name", "t")] {
            assert!(std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["config", k, v])
                .status()
                .unwrap()
                .success());
        }

        for (name, content) in [("one", "one\n"), ("two", "two\n"), ("three", "three\n")] {
            std::fs::write(repo.join("PKGBUILD"), content).unwrap();
            assert!(std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["add", "PKGBUILD"])
                .status()
                .unwrap()
                .success());
            assert!(std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["commit", "-q", "-m", name])
                .status()
                .unwrap()
                .success());
        }
        let first = String::from_utf8(
            std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["rev-list", "--max-count=1", "--reverse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        let second = String::from_utf8(
            std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["rev-parse", "HEAD~1"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        let tip = String::from_utf8(
            std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();

        // Grafts rewrite only ancestry: make the tip appear rooted at the
        // first commit instead of its real second-commit parent.
        let grafts = repo.join(".git/info/grafts");
        std::fs::create_dir_all(grafts.parent().unwrap()).unwrap();
        std::fs::write(&grafts, format!("{tip} {first}\n")).unwrap();

        let raw = std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["show", "-s", "--format=%P", &tip])
            .env("GIT_GRAFT_FILE", &grafts)
            .output()
            .unwrap();
        assert!(raw.status.success());
        assert_eq!(
            String::from_utf8_lossy(&raw.stdout).trim(),
            first,
            "fixture: plain git should honour the grafted parent"
        );

        let safe = safe_git(Some(repo), &["show", "-s", "--format=%P", &tip]).unwrap();
        assert!(safe.status.success());
        assert_eq!(
            String::from_utf8_lossy(&safe.stdout).trim(),
            second,
            "safe_git must use the committed parent, not info/grafts"
        );
    }

    #[test]
    fn replace_artifacts_are_purged_from_cache() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        assert!(std::process::Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .arg(repo)
            .status()
            .unwrap()
            .success());
        for (k, v) in [("user.email", "t@t"), ("user.name", "t")] {
            assert!(std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["config", k, v])
                .status()
                .unwrap()
                .success());
        }

        std::fs::write(repo.join("PKGBUILD"), "original\n").unwrap();
        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["add", "PKGBUILD"])
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["commit", "-q", "-m", "original commit"])
            .status()
            .unwrap()
            .success());
        let original = String::from_utf8(
            std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();

        std::fs::write(repo.join("PKGBUILD"), "replaced\n").unwrap();
        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["commit", "-q", "-am", "replace commit"])
            .status()
            .unwrap()
            .success());
        let replacement = String::from_utf8(
            std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();

        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["replace", &original, &replacement])
            .status()
            .unwrap()
            .success());

        // Plant a grafts file (same effect as a replace ref on parent history).
        let grafts = repo.join(".git/info/grafts");
        std::fs::create_dir_all(grafts.parent().unwrap()).unwrap();
        std::fs::write(
            &grafts,
            "0000000000000000000000000000000000000000 0000000000000000000000000000000000000001\n",
        )
        .unwrap();

        purge_replace_artifacts(repo).unwrap();

        let list = std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["for-each-ref", "--format=%(refname)", "refs/replace"])
            .output()
            .unwrap()
            .stdout;
        assert!(list.is_empty(), "replace ref was not purged");
        assert!(!grafts.exists(), "grafts file was not removed");
    }
}
