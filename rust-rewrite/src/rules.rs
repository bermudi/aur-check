//! Hard-fail and review-only rule tables. This is the heart of the tool.
//!
//! Patterns are POSIX-ERE-ish, compiled with `unicode(false)` so that
//! `[[:space:]]` / `[[:alnum:]]` etc. are ASCII-only — the exact equivalent
//! of the script's `export LC_ALL=C`. Case-insensitivity matches `grep -i`.

use regex::bytes::Regex;
use regex::bytes::RegexBuilder;

pub struct Rule {
    pub name: &'static str,
    pub pattern: &'static str,
}

/// Hard-fail rules: a match on an ADDED diff line blocks the update.
pub const HARD_RULES: &[Rule] = &[
    Rule {
        name: "install-hook-ref",
        // makepkg sources whatever value `install` resolves to; restricting the
        // suffix would miss dynamic or nested script paths.
        pattern: r"(^|[[:space:]])install[[:space:]]*=",
    },
    Rule {
        name: "install-hook-func",
        pattern: r"(function[[:space:]]+)?(post|pre)_(install|upgrade|remove)([[:space:]]*\(\))?[[:space:]]*\{",
    },
    Rule {
        name: "npm",
        pattern: r"npm([[:space:]]+-[^[:space:]]+([[:space:]]+[^-[:space:]][^[:space:]]*)?)*[[:space:]]+(install|i|ci|add|run|exec)([[:space:];|&]|$)",
    },
    Rule {
        name: "npx",
        pattern: r"npx([[:space:]]+-[^[:space:]]+([[:space:]]+[^-[:space:]][^[:space:]]*)?)*[[:space:]]+[[:alnum:]_@./-]",
    },
    Rule {
        name: "bunx",
        pattern: r"bunx([[:space:]]+-[^[:space:]]+([[:space:]]+[^-[:space:]][^[:space:]]*)?)*[[:space:]]+[[:alnum:]_@./-]",
    },
    Rule {
        name: "pnpm",
        pattern: r"pnpm([[:space:]]+-[^[:space:]]+([[:space:]]+[^-[:space:]][^[:space:]]*)?)*[[:space:]]+(install|i|add|ci|run|exec|dlx)([[:space:];|&]|$)",
    },
    Rule {
        name: "bun",
        pattern: r"bun([[:space:]]+-[^[:space:]]+([[:space:]]+[^-[:space:]][^[:space:]]*)?)*[[:space:]]+(add|x|install)([[:space:];|&]|$)",
    },
    Rule {
        name: "yarn",
        pattern: r"yarn([[:space:]]+-[^[:space:]]+([[:space:]]+[^-[:space:]][^[:space:]]*)?)*[[:space:]]+(add|install|exec|dlx)([[:space:];|&]|$)",
    },
    Rule {
        name: "pipe-to-interpreter",
        pattern: r"(curl|wget|fetch)[^|;&]*\|[[:space:]]*(sudo[[:space:]]+)?(sh|bash|zsh|fish|python[0-9.]*|node|ruby|perl[0-9.]*)",
    },
    Rule {
        name: "interp-c-net",
        pattern: r"(sh|bash|zsh|fish)([[:space:]]+-[^[:space:]]+([[:space:]]+[^-[:space:]][^[:space:]]*)?)*[[:space:]]+-[[:alpha:]]*c[[:alpha:]]*[[:space:]].*[$(`][[:space:]]*(curl|wget|fetch)",
    },
    Rule {
        name: "fetch-file-exec",
        pattern: r"(curl|wget|fetch)[^;|&]*(--output(=|[[:space:]]+)|-[oO][[:space:]]*|>[[:space:]]*)[^;|&]*(;|&&|\|\|)[[:space:]]*(sudo[[:space:]]+)?(sh|bash|zsh|fish|python[0-9.]*|node|ruby|perl[0-9.]*)",
    },
    Rule {
        name: "proc-subst-net",
        pattern: r"<[[:space:]]*\([[:space:]]*(curl|wget|fetch)",
    },
    Rule {
        name: "eval-subst",
        pattern: r#"eval[[:space:]]+['"]?[$(`]"#,
    },
    Rule {
        name: "backtick-net",
        pattern: r"`[[:space:]]*(curl|wget|fetch)",
    },
    Rule {
        name: "base64-decode",
        pattern: r"base64([[:space:]]+-[^[:space:]]+([[:space:]]+[^-[:space:]][^[:space:]]*)?)*[[:space:]]+(-d|--decode)([[:space:];|&]|$)|openssl[[:space:]]+enc[^;&|]*[[:space:]](-d[^;&|]*[[:space:]](-a|-base64)|(-a|-base64)[^;&|]*[[:space:]]-d)",
    },
    Rule {
        name: "hex-decode",
        pattern: r"xxd([[:space:]]+-[^[:space:]]+)*[[:space:]]+-r([[:space:];|&]|$)",
    },
    Rule {
        name: "hex-escape-run",
        pattern: r"(\\x[0-9a-fA-F]{2}){2,}",
    },
    Rule {
        name: "octal-escape-run",
        pattern: r"(\\[0-7]{3}){2,}",
    },
];

/// Review-only rules: warn, do not block.
pub const REVIEW_RULES: &[Rule] = &[
    Rule {
        name: "checksum-skip-added",
        pattern: r"(md5|sha[0-9]+|b2)sums[^#]*SKIP",
    },
    Rule {
        name: "hex-escape",
        pattern: r"\\x[0-9a-fA-F]{2}",
    },
    Rule {
        name: "octal-escape",
        pattern: r"\\[0-7]{3}",
    },
    Rule {
        name: "pip",
        pattern: r"(pip[0-9.]*|python[0-9.]*[[:space:]]+-m[[:space:]]+pip)([[:space:]]+-[^[:space:]]+)*[[:space:]]+(install|download)([[:space:];|&]|$)",
    },
    Rule {
        name: "gem",
        pattern: r"gem[[:space:]]+install",
    },
    Rule {
        name: "cargo-install",
        pattern: r"cargo[[:space:]]+install",
    },
    Rule {
        name: "go-install",
        pattern: r"go[[:space:]]+install",
    },
    Rule {
        name: "python-inline",
        pattern: r"python[0-9.]*([[:space:]]+-[^[:space:]]+)*[[:space:]]+-c([[:space:]]|$)",
    },
    Rule {
        name: "perl-inline-net",
        pattern: r"perl[[:space:]]+(-e|-M)[[:space:]]*(HTTP::|LWP|Net::)",
    },
];

#[derive(Clone)]
pub struct CompiledRule {
    pub name: &'static str,
    pub re: Regex,
}

/// Compile a table. `unicode(false)` == C-locale ASCII classes;
/// `case_insensitive(true)` == `grep -i`. Operates on bytes so NUL /
/// non-UTF8 content cannot be silently mangled by a String round-trip.
fn compile(table: &[Rule]) -> Vec<CompiledRule> {
    table
        .iter()
        .map(|r| {
            let re = RegexBuilder::new(r.pattern)
                .case_insensitive(true)
                .unicode(false)
                .build()
                .unwrap_or_else(|e| panic!("rule {} failed to compile: {e}", r.name));
            CompiledRule { name: r.name, re }
        })
        .collect()
}

pub fn hard_rules() -> Vec<CompiledRule> {
    compile(HARD_RULES)
}
pub fn review_rules() -> Vec<CompiledRule> {
    compile(REVIEW_RULES)
}

/// First matching rule name for a single added line (bytes).
pub fn match_hard<'a>(rules: &'a [CompiledRule], line: &[u8]) -> Option<&'a str> {
    rules.iter().find(|r| r.re.is_match(line)).map(|r| r.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_compiles() {
        assert_eq!(hard_rules().len(), HARD_RULES.len());
        assert_eq!(review_rules().len(), REVIEW_RULES.len());
    }
}
