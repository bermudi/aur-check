//! Hardened git wrapper (Finding J + H1 / issue #5).
//!
//! Every git call goes through `safe_git`. It strips caller-injected env,
//! forces diff/show options that defeat diff.external / textconv / word-diff /
//! color / noprefix games, and fails closed on repo-local `.git/config` keys
//! that can alter output, redirect fetches, or execute code.

use anyhow::{bail, Context, Result};
use std::path::Path;
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
const UNSAFE_KEY_PREFIXES: &[&str] = &[
    "diff.",
    "url.",
    "filter.",
    "alias.",
    "include.",
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
}
