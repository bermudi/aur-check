//! Configuration loading for the Rust implementation.
//!
//! Non-secret settings use `environment > config file > default`. API keys are
//! intentionally environment-only and are read by `llm_client`: silently
//! loading long-lived credentials from this plain-text config would be a bad
//! default for a supply-chain security tool.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone)]
pub struct Config {
    pub branch: String,
    pub aur_url: String,
    pub yay_cache: PathBuf,
    pub paru_cache: PathBuf,
    pub state_dir: PathBuf,
    pub llm_auto_boring: bool,
    pub llm_backend: String,
    pub llm_base_url: Option<String>,
    pub explain_model: String,
    pub explain_maxlines: usize,
    pub llm_timeout_seconds: u64,
    pub config_file: PathBuf,
}

impl Config {
    pub fn load() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .context("HOME is not set; refusing to place trust state in a shared fallback")?;
        let config_file = std::env::var_os("AUR_SAFE_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config/aur-safe/config"));
        let file = parse_config_file(&config_file)?;

        let branch = get("AUR_SAFE_BRANCH", &file, "master");
        validate_branch(&branch)?;
        let aur_url = get("AUR_SAFE_AUR_URL", &file, "https://aur.archlinux.org");
        validate_aur_url(&aur_url)?;

        let yay_cache = path_setting("AUR_SAFE_YAY_CACHE", &file, home.join(".cache/yay"));
        let paru_cache = path_setting("AUR_SAFE_PARU_CACHE", &file, home.join(".cache/paru/clone"));
        let state_dir = path_setting("AUR_SAFE_STATE_DIR", &file, home.join(".cache/aur-safe"));

        let llm_auto_boring = matches!(get("AUR_SAFE_LLM_AUTO_BORING", &file, "0").as_str(), "1");
        let llm_backend = get("AUR_SAFE_LLM_BACKEND", &file, "openrouter");
        if !matches!(
            llm_backend.as_str(),
            "openai" | "anthropic" | "ollama" | "deepseek" | "openrouter"
        ) {
            bail!(
                "unsupported AUR_SAFE_LLM_BACKEND {llm_backend:?}; expected openai, anthropic, ollama, deepseek, or openrouter"
            );
        }
        let llm_base_url = optional("AUR_SAFE_LLM_BASE_URL", &file);
        let explain_model = get("AUR_SAFE_MODEL", &file, "z-ai/glm-5.2");
        if explain_model.is_empty() || explain_model.bytes().any(|b| b.is_ascii_control()) {
            bail!("AUR_SAFE_MODEL must be a non-empty, single-line model identifier");
        }
        let explain_maxlines = parse_positive::<usize>(
            "AUR_SAFE_EXPLAIN_MAXLINES",
            &get("AUR_SAFE_EXPLAIN_MAXLINES", &file, "1000"),
        )?;
        let llm_timeout_seconds = parse_positive::<u64>(
            "AUR_SAFE_LLM_TIMEOUT_SECONDS",
            &get("AUR_SAFE_LLM_TIMEOUT_SECONDS", &file, "120"),
        )?;

        Ok(Self {
            branch,
            aur_url,
            yay_cache,
            paru_cache,
            state_dir,
            llm_auto_boring,
            llm_backend,
            llm_base_url,
            explain_model,
            explain_maxlines,
            llm_timeout_seconds,
            config_file,
        })
    }
}

fn get_with(
    key: &str,
    file: &HashMap<String, String>,
    default: &str,
    env: impl Fn(&str) -> Option<String>,
) -> String {
    env(key)
        .or_else(|| file.get(key).cloned())
        .unwrap_or_else(|| default.to_owned())
}

fn get(key: &str, file: &HashMap<String, String>, default: &str) -> String {
    get_with(key, file, default, |name| std::env::var(name).ok())
}

fn optional(key: &str, file: &HashMap<String, String>) -> Option<String> {
    std::env::var(key)
        .ok()
        .or_else(|| file.get(key).cloned())
        .filter(|value| !value.is_empty())
}

fn path_setting(key: &str, file: &HashMap<String, String>, default: PathBuf) -> PathBuf {
    optional(key, file).map(PathBuf::from).unwrap_or(default)
}

fn parse_positive<T>(key: &str, value: &str) -> Result<T>
where
    T: std::str::FromStr + PartialEq + Default,
    T::Err: std::fmt::Display,
{
    let parsed = value.parse::<T>().map_err(|error| {
        anyhow::anyhow!("{key} must be a positive integer, got {value:?}: {error}")
    })?;
    if parsed == T::default() {
        bail!("{key} must be greater than zero");
    }
    Ok(parsed)
}

fn validate_aur_url(url: &str) -> Result<()> {
    if !(url.starts_with("https://") || url.starts_with("http://"))
        || url
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || url.ends_with('/')
    {
        bail!("AUR_SAFE_AUR_URL must be a single-line http(s) base URL without a trailing slash");
    }
    Ok(())
}

fn validate_branch(branch: &str) -> Result<()> {
    let bytes_ok = branch
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-'));
    if branch.is_empty()
        || branch.starts_with('-')
        || branch.starts_with('.')
        || branch.ends_with('.')
        || branch.ends_with('/')
        || branch.contains("..")
        || branch.contains("//")
        || branch.contains("@{")
        || !bytes_ok
    {
        bail!("AUR_SAFE_BRANCH is not a safe git branch name: {branch:?}");
    }
    Ok(())
}

fn parse_config_file(path: &Path) -> Result<HashMap<String, String>> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("read config {}", path.display()));
        }
    };
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        map.entry(key.trim().to_owned())
            .or_insert_with(|| value.trim().to_owned());
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_option_like_branch() {
        assert!(validate_branch("--upload-pack=evil").is_err());
        assert!(validate_branch("feature/rust").is_ok());
    }

    #[test]
    fn aur_url_is_an_http_base_not_a_curl_option() {
        assert!(validate_aur_url("https://aur.archlinux.org").is_ok());
        assert!(validate_aur_url("http://127.0.0.1:8080").is_ok());
        assert!(validate_aur_url("--output=/tmp/owned").is_err());
        assert!(validate_aur_url("https://aur.archlinux.org/").is_err());
        assert!(validate_aur_url("https://aur.archlinux.org/a b").is_err());
    }

    #[test]
    fn config_parser_uses_first_matching_key_like_bash() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), "# comment\n K = first\nK=second\n").unwrap();
        let parsed = parse_config_file(tmp.path()).unwrap();
        assert_eq!(parsed.get("K").map(String::as_str), Some("first"));
    }

    #[test]
    fn llm_auto_boring_precedence_and_fail_closed_values() {
        let file = HashMap::from([("AUR_SAFE_LLM_AUTO_BORING".to_owned(), "1".to_owned())]);
        let from_file = get_with("AUR_SAFE_LLM_AUTO_BORING", &file, "0", |_| None);
        assert_eq!(from_file, "1", "config file should enable the opt-in");

        let from_env = get_with("AUR_SAFE_LLM_AUTO_BORING", &file, "0", |_| Some("0".into()));
        assert_eq!(from_env, "0", "environment must override the file");

        let invalid = get_with("AUR_SAFE_LLM_AUTO_BORING", &file, "0", |_| {
            Some("bogus".into())
        });
        assert!(
            !matches!(invalid.as_str(), "1"),
            "invalid values fail closed"
        );
    }
}
