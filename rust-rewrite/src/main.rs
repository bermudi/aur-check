use std::path::PathBuf;
use std::process::ExitCode;

use aur_safe::cli::dispatch;
use aur_safe::config::Config;
use aur_safe::engine::App;
use aur_safe::llm_client::NativeLlm;
use aur_safe::rpc::CurlRpc;
use aur_safe::srcinfo::SystemPacman;
use aur_safe::state::Paths;
use aur_safe::ui::StderrReporter;

fn main() -> ExitCode {
    isolate_process_environment();
    let code = match run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            3
        }
    };
    ExitCode::from(code as u8)
}

fn run() -> anyhow::Result<i32> {
    let config = Config::load()?;
    let paths = Paths::new(config.state_dir.clone());
    paths.ensure_dirs()?;

    let pacman = SystemPacman;
    let rpc = CurlRpc {
        aur_url: config.aur_url.clone(),
    };
    let mut reporter = StderrReporter::new();
    let mut llm = NativeLlm::from_config(&config).map_err(anyhow::Error::msg)?;
    let llm_description = llm.description();
    let mut app = App {
        paths,
        pacman: &pacman,
        reporter: &mut reporter,
        llm: &mut llm,
        rpc: &rpc,
        branch: config.branch.clone(),
        aur_url: config.aur_url.clone(),
        yay_cache: config.yay_cache.clone(),
        paru_cache: config.paru_cache.clone(),
        makepkg_path: PathBuf::from("/usr/bin/makepkg"),
        staging: std::env::var("AUR_SAFE_STAGING").as_deref() == Ok("1"),
        llm_auto_boring: config.llm_auto_boring,
        explain_maxlines: config.explain_maxlines,
        explain_model: llm_description,
        hard: aur_safe::rules::hard_rules(),
        review: aur_safe::rules::review_rules(),
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    Ok(dispatch(&mut app, &args))
}

fn isolate_process_environment() {
    // Finding J/H1: do this before configuration or any git operation. Git's
    // execution/redirection environment is broad (GIT_EXEC_PATH,
    // GIT_CONFIG_PARAMETERS, GIT_COMMON_DIR, ...), so a prefix allowlist is
    // safer than trying to remember every dangerous variable. Per-call
    // isolation in `git::safe_git` remains the second line of defense.
    let injected: Vec<std::ffi::OsString> = std::env::vars_os()
        .filter_map(|(key, _)| {
            (key.as_encoded_bytes().starts_with(b"GIT_")
                || matches!(key.to_str(), Some("PAGER" | "VISUAL" | "EDITOR")))
            .then_some(key)
        })
        .collect();
    for key in injected {
        std::env::remove_var(key);
    }
    std::env::set_var("GIT_CONFIG_GLOBAL", "/dev/null");
    std::env::set_var("GIT_CONFIG_SYSTEM", "/dev/null");
    std::env::set_var("LC_ALL", "C");
    std::env::set_var("LANG", "C");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static STARTUP_ENV_GUARD: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        previous: Vec<(String, Option<String>)>,
    }

    impl EnvGuard {
        fn set(vars: &[(&str, &str)]) -> Self {
            let mut previous = Vec::with_capacity(vars.len());
            for (key, value) in vars {
                previous.push(((*key).to_string(), std::env::var(key).ok()));
                std::env::set_var(key, value);
            }
            Self { previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, old) in self.previous.drain(..) {
                match old {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    #[test]
    fn isolate_process_environment_removes_git_and_editor_env() {
        let _guard = STARTUP_ENV_GUARD.lock().unwrap();
        let _startup_vars = EnvGuard::set(&[
            ("GIT_DIR", "/tmp/example.git"),
            ("GIT_WORK_TREE", "/tmp/work"),
            ("PAGER", "less"),
            ("VISUAL", "vim"),
            ("EDITOR", "nano"),
            ("LC_ALL", "en_US.UTF-8"),
            ("LANG", "en_US.UTF-8"),
            ("GIT_CONFIG_GLOBAL", "/tmp/other"),
            ("GIT_CONFIG_SYSTEM", "/tmp/system"),
        ]);
        isolate_process_environment();
        assert!(
            std::env::var("GIT_DIR").is_err(),
            "GIT_DIR must be scrubbed"
        );
        assert!(
            std::env::var("GIT_WORK_TREE").is_err(),
            "GIT_WORK_TREE must be scrubbed"
        );
        assert!(
            std::env::var("PAGER").is_err(),
            "PAGER must be scrubbed by process isolation"
        );
        assert!(
            std::env::var("VISUAL").is_err(),
            "VISUAL must be scrubbed by process isolation"
        );
        assert!(
            std::env::var("EDITOR").is_err(),
            "EDITOR must be scrubbed by process isolation"
        );
        assert_eq!(
            std::env::var("GIT_CONFIG_GLOBAL").ok(),
            Some("/dev/null".into())
        );
        assert_eq!(
            std::env::var("GIT_CONFIG_SYSTEM").ok(),
            Some("/dev/null".into())
        );
        assert_eq!(std::env::var("LC_ALL").ok(), Some("C".into()));
        assert_eq!(std::env::var("LANG").ok(), Some("C".into()));
    }
}
