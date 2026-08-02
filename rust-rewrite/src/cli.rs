//! Shared CLI dispatch used by the production binary and the subprocess test
//! harness. The `AUR_SAFE_AS_MAKEPKG=1` guard is checked first; it must not be
//! reachable through the normal command table.

use crate::commands;
use crate::engine::App;

/// Route `args` to the appropriate command. Returns the stable exit code:
/// 0 clean, 1 blocked / audit-unavailable, 2 review, 3 usage/unknown.
pub fn dispatch(app: &mut App, args: &[String]) -> i32 {
    if std::env::var("AUR_SAFE_AS_MAKEPKG").as_deref() == Ok("1") {
        return commands::cmd_makepkg(app, args);
    }

    let Some((command, rest)) = args.split_first() else {
        print_usage();
        return 3;
    };

    match command.as_str() {
        "gate" if rest.is_empty() => commands::cmd_gate(app),
        "check" => commands::cmd_check(app, rest),
        "audit" if rest.len() == 1 => commands::cmd_audit(app, &rest[0]),
        "scan" if rest.is_empty() => commands::cmd_scan(app),
        "explain" if rest.len() <= 1 => {
            commands::cmd_explain(app, rest.first().map(String::as_str))
        }
        "accept" if rest.is_empty() => commands::cmd_accept(app),
        "rules" if rest.is_empty() => {
            print_rules();
            0
        }
        "wrapper" if rest.is_empty() => {
            print!("{}", crate::wrapper::WRAPPER);
            0
        }
        "selftest" if rest.is_empty() => crate::selftest::run(),
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
    }
}

fn print_rules() {
    println!("hard-fail rules (block)");
    for rule in crate::rules::HARD_RULES {
        println!("  {:22} {}", rule.name, rule.pattern);
    }
    println!("\nreview rules (warn)");
    for rule in crate::rules::REVIEW_RULES {
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
