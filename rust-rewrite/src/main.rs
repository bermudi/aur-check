use std::process::ExitCode;

use aur_safe::commands;
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
        staging: std::env::var("AUR_SAFE_STAGING").as_deref() == Ok("1"),
        llm_auto_boring: config.llm_auto_boring,
        explain_maxlines: config.explain_maxlines,
        explain_model: llm_description,
        hard: aur_safe::rules::hard_rules(),
        review: aur_safe::rules::review_rules(),
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    if std::env::var("AUR_SAFE_AS_MAKEPKG").as_deref() == Ok("1") {
        return Ok(commands::cmd_makepkg(&mut app, &args));
    }
    let Some((command, rest)) = args.split_first() else {
        print_usage();
        return Ok(3);
    };

    let rc = match command.as_str() {
        "gate" if rest.is_empty() => commands::cmd_gate(&mut app),
        "check" => commands::cmd_check(&mut app, rest),
        "audit" if rest.len() == 1 => commands::cmd_audit(&mut app, &rest[0]),
        "scan" if rest.is_empty() => commands::cmd_scan(&mut app),
        "explain" if rest.len() <= 1 => {
            commands::cmd_explain(&mut app, rest.first().map(String::as_str))
        }
        "accept" if rest.is_empty() => commands::cmd_accept(&mut app),
        "rules" if rest.is_empty() => {
            print_rules();
            0
        }
        "wrapper" if rest.is_empty() => {
            print!("{}", aur_safe::wrapper::WRAPPER);
            0
        }
        "selftest" if rest.is_empty() => aur_safe::selftest::run(),
        "-h" | "--help" | "help" if rest.is_empty() => {
            print_usage();
            0
        }
        known
            if matches!(
                known,
                "gate" | "audit" | "scan" | "explain" | "accept" | "rules" | "wrapper" | "selftest"
            ) =>
        {
            eprintln!("error: invalid arguments for '{known}' (try: aur-safe --help)");
            3
        }
        other => {
            eprintln!("error: unknown command '{other}' (try: aur-safe --help)");
            3
        }
    };
    Ok(rc)
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

fn print_rules() {
    println!("hard-fail rules (block)");
    for rule in aur_safe::rules::HARD_RULES {
        println!("  {:22} {}", rule.name, rule.pattern);
    }
    println!("\nreview rules (warn)");
    for rule in aur_safe::rules::REVIEW_RULES {
        println!("  {:22} {}", rule.name, rule.pattern);
    }
}

fn print_usage() {
    println!(
        r#"aur-safe — deterministic gate for AUR updates

usage:
  aur-safe gate                gate all pending AUR updates
  aur-safe check <pkg> ...     gate specific cached package(s)
  aur-safe audit <pkg>         gate an uncached/new package
  aur-safe scan                scan installed pkgs for payload patterns
  aur-safe explain [pkg]       advisory LLM second-opinion on a flagged diff
  aur-safe accept              promote staged refs (called by the wrapper)
  aur-safe rules               list active rules
  aur-safe wrapper             print the shell wrapper (not installed)
  aur-safe selftest            run embedded deterministic smoke tests

env:
  AUR_SAFE_YAY_CACHE           yay cache dir (default: ~/.cache/yay)
  AUR_SAFE_PARU_CACHE          paru cache dir (default: ~/.cache/paru/clone)
  AUR_SAFE_STATE_DIR           state dir (default: ~/.cache/aur-safe)
  AUR_SAFE_BRANCH              remote branch (default: master)
  AUR_SAFE_AUR_URL             AUR base URL (default: https://aur.archlinux.org)
  AUR_SAFE_CONFIG              config file (default: ~/.config/aur-safe/config)
  AUR_SAFE_LLM_BACKEND         openai|anthropic|ollama|deepseek|openrouter
  AUR_SAFE_MODEL               provider model ID (default: z-ai/glm-5.2)
  AUR_SAFE_LLM_BASE_URL        optional provider API base URL
  AUR_SAFE_LLM_API_KEY         provider-neutral API-key override (env only)
  AUR_SAFE_LLM_TIMEOUT_SECONDS request timeout (default: 120)
  AUR_SAFE_EXPLAIN_MAXLINES    diff truncation (default: 1000)
  AUR_SAFE_LLM_AUTO_BORING     1 enables the strict boring-edge verifier

The generated wrapper is required for the full gate → build → accept TOCTOU guarantee.
The LLM is advisory and can never clear hard, review, or audit-unavailable results."#
    );
}
