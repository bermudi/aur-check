//! PKGBUILD lexical analysis. PKGBUILD is *executable Bash*, so raw-line
//! allowlists are never enough: an unchanged opening quote/heredoc/backslash
//! can turn an apparently inert added comment into executable text. Every
//! classification here first proves the added line's lexical position in the
//! COMPLETE candidate, via a conservative (fail-closed) scanner that understands
//! per-line quote/comment escapes only well enough to detect cross-line
//! constructs. Heredocs are rejected outright.
//!
//! All scanners are byte-oriented (`regex::bytes`, `unicode(false)`) to match
//! the script's LC_ALL=C semantics.

use std::path::Path;
use std::sync::OnceLock;

use anyhow::{bail, Result};
use regex::bytes::{Regex, RegexBuilder};

use crate::git;
use crate::srcinfo::LineClass;
use crate::srcinfo::{source_line_values_are_safe, trusted_dependency_spec, Pacman};

/// Build a case-sensitive, ASCII-only (`unicode(false)`) byte regex.
macro_rules! bre {
    ($name:ident, $pat:expr) => {
        fn $name() -> &'static Regex {
            static RE: OnceLock<Regex> = OnceLock::new();
            RE.get_or_init(|| RegexBuilder::new($pat).unicode(false).build().unwrap())
        }
    };
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Ordinary one-line shell context.
    Plain,
    /// Additionally require every byte-identical occurrence to be inside the
    /// named multiline array.
    Array,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LiteralKind {
    /// license=/arch=/groups=/noextract=( … ) — literal words/quotes only.
    Literal,
    /// source[_arch]=( … ) — also permits simple $name / ${name} expansion.
    Source,
}

// --- the conservative cross-line scanner -----------------------------------

bre!(heredoc_re, r"(^|[^<])<<-?[[:space:]]*[^<]");

/// Detect constructs that span lines (unterminated quote/backtick, trailing
/// line-continuation backslash) or heredocs. A `<<<` herestring is NOT flagged
/// (the heredoc regex requires a non-`<` after `<<`). This is a lexical screen,
/// not a Bash evaluator.
pub fn is_ambiguous(s: &[u8]) -> bool {
    if heredoc_re().is_match(s) {
        return true;
    }
    let n = s.len();
    let mut state = 0u8; // 0=normal 1=single-quote 2=double-quote 3=backtick
    let mut i = 0usize;
    while i < n {
        let c = s[i];
        let prev = if i > 0 { s[i - 1] } else { 0 };
        let mut advance = 1usize;
        match state {
            0 => {
                if c == b'#' && (i == 0 || prev.is_ascii_whitespace()) {
                    break; // comment to EOL
                }
                if c == b'\\' {
                    if i + 1 >= n {
                        return true; // trailing backslash = line continuation
                    }
                    advance = 2;
                } else if c == b'\'' {
                    state = 1;
                } else if c == b'"' {
                    state = 2;
                } else if c == b'`' {
                    state = 3;
                }
            }
            1 => {
                if c == b'\'' {
                    state = 0;
                }
            }
            2 => {
                if c == b'\\' {
                    if i + 1 >= n {
                        return true;
                    }
                    advance = 2;
                } else if c == b'"' {
                    state = 0;
                } else if c == b'`' {
                    return true; // backtick inside double quotes
                }
            }
            3 => {
                if c == b'\\' {
                    if i + 1 >= n {
                        return true;
                    }
                    advance = 2;
                } else if c == b'`' {
                    state = 0;
                }
            }
            _ => {}
        }
        i += advance;
    }
    state != 0
}

/// Does this line contain an unquoted `)` that closes an array? Tracks
/// quotes/backticks/comments/escapes; does NOT treat trailing backslash or
/// backtick-in-double-quote as special (unlike `is_ambiguous`) — it only needs
/// to find the real closer.
pub fn closes_array(s: &[u8]) -> bool {
    let n = s.len();
    let mut state = 0u8;
    let mut i = 0usize;
    while i < n {
        let c = s[i];
        let prev = if i > 0 { s[i - 1] } else { 0 };
        let mut advance = 1usize;
        match state {
            0 => {
                if c == b'#' && (i == 0 || prev.is_ascii_whitespace()) {
                    break;
                }
                if c == b'\\' {
                    advance = 2;
                } else if c == b'\'' {
                    state = 1;
                } else if c == b'"' {
                    state = 2;
                } else if c == b'`' {
                    state = 3;
                } else if c == b')' {
                    return true;
                }
            }
            1 => {
                if c == b'\'' {
                    state = 0;
                }
            }
            2 => {
                if c == b'\\' {
                    advance = 2;
                } else if c == b'"' {
                    state = 0;
                }
            }
            3 => {
                if c == b'\\' {
                    advance = 2;
                } else if c == b'`' {
                    state = 0;
                }
            }
            _ => {}
        }
        i += advance;
    }
    false
}

/// Prove an added line's lexical position in the complete candidate PKGBUILD.
///
/// Ordering is load-bearing and mirrors the awk exactly:
///   1. `is_ambiguous` runs first → sticky `unsafe` (a self-ambiguous wanted
///      line is therefore unsafe-found, never plain-context);
///   2. the array opener is matched → `in_array` set before the wanted check
///      (an opener line that is itself the wanted line counts as in-array);
///   3. the wanted line is matched and classified;
///   4. `closes_array` runs last → a final member carrying the real `)` is
///      recorded as a member before the array closes on that same line.
pub fn candidate_line_context(
    pkgbuild: &[u8],
    wanted: &[u8],
    opener: Option<&Regex>,
    mode: Mode,
) -> bool {
    let mut unsafe_context = false;
    let mut in_array = false;
    let mut found = false;
    let mut unsafe_found = false;
    let mut outside = false;

    for line in pkgbuild.split(|&b| b == b'\n') {
        if is_ambiguous(line) {
            unsafe_context = true;
        }
        if mode == Mode::Array {
            if let Some(re) = opener {
                if re.is_match(line) {
                    in_array = true;
                }
            }
        }
        if line == wanted {
            match mode {
                Mode::Plain => {
                    found = true;
                    if unsafe_context {
                        unsafe_found = true;
                    }
                }
                Mode::Array => {
                    if in_array {
                        found = true;
                        if unsafe_context {
                            unsafe_found = true;
                        }
                    } else {
                        outside = true;
                    }
                }
            }
        }
        if mode == Mode::Array && in_array && closes_array(line) {
            in_array = false;
        }
    }

    match mode {
        Mode::Plain => found && !unsafe_found,
        Mode::Array => found && !outside && !unsafe_found,
    }
}

/// mode=plain convenience: ordinary one-line context.
pub fn line_has_plain_context(pkgbuild: &[u8], wanted: &[u8]) -> bool {
    candidate_line_context(pkgbuild, wanted, None, Mode::Plain)
}

/// mode=array convenience: every byte-identical occurrence inside `opener`.
pub fn array_member_added_line(pkgbuild: &[u8], wanted: &[u8], opener: &Regex) -> bool {
    candidate_line_context(pkgbuild, wanted, Some(opener), Mode::Array)
}

// --- git-backed readers -----------------------------------------------------

/// Read the complete candidate PKGBUILD at an immutable candidate ref.
pub fn candidate_pkgbuild_at(dir: &Path, candidate_ref: &str) -> Result<Vec<u8>> {
    let rev = format!("{candidate_ref}:PKGBUILD");
    let out = git::safe_git(Some(dir), &["show", &rev])?;
    if !out.status.success() {
        bail!("cannot read candidate PKGBUILD at {rev}");
    }
    Ok(out.stdout)
}

/// Read the candidate .SRCINFO at origin/<branch> (the generated mirror used as
/// a second structural check for PKGBUILD dependencies).
pub fn candidate_srcinfo_at(dir: &Path, candidate_ref: &str) -> Result<String> {
    let rev = format!("{candidate_ref}:.SRCINFO");
    let out = git::safe_git(Some(dir), &["show", &rev])?;
    if !out.status.success() {
        bail!("cannot read candidate .SRCINFO at {rev}");
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

// --- positive array-literal grammar ----------------------------------------

bre!(
    literal_opener_re,
    r"^[[:space:]]*(license|arch|groups|noextract)=\("
);
bre!(
    source_opener_inline_re,
    r"^[[:space:]]*source(_[[:alnum:]_]+)?=\("
);

/// Length (bytes) of a simple expansion at the start of `tail`, or 0. Only
/// `$name` and `${name}` — expands data, cannot run a command. Anything else
/// (`${x@P}`, `${x:=…}`, `$(…)`, arithmetic) is rejected by returning 0.
fn simple_expansion(tail: &[u8], kind: LiteralKind) -> usize {
    if kind != LiteralKind::Source {
        return 0;
    }
    static BRACED: OnceLock<Regex> = OnceLock::new();
    static BARE: OnceLock<Regex> = OnceLock::new();
    let braced = BRACED.get_or_init(|| Regex::new(r"^\$\{[A-Za-z_][A-Za-z0-9_]*\}").unwrap());
    let bare = BARE.get_or_init(|| Regex::new(r"^\$[A-Za-z_][A-Za-z0-9_]*").unwrap());
    if let Some(m) = braced.find(tail) {
        return m.end();
    }
    if let Some(m) = bare.find(tail) {
        return m.end();
    }
    0
}

bre!(tail_ws_re, r"^[[:space:]]*$");
bre!(tail_comment_re, r"^[[:space:]]+#.*$");

/// Validate the RHS of a one-line array assignment (everything from `(`).
/// Returns true only for a balanced array of literal words/quotes (plus simple
/// expansion for `source`), closed by a real unquoted `)` with nothing but
/// whitespace/comment after it.
fn array_literal_rhs_ok(rhs: &[u8], kind: LiteralKind) -> bool {
    let n = rhs.len();
    if n == 0 || rhs[0] != b'(' {
        return false;
    }
    let mut state = 0u8; // 0=normal 1=single-quote 2=double-quote
    let mut closed: Option<usize> = None;
    let mut i = 1usize;
    while i < n {
        let c = rhs[i];
        match state {
            0 => {
                if c == b'\'' {
                    state = 1;
                    i += 1;
                } else if c == b'"' {
                    state = 2;
                    i += 1;
                } else if c == b')' {
                    closed = Some(i);
                    break;
                } else if c == b'$' {
                    let used = simple_expansion(&rhs[i..], kind);
                    if used == 0 {
                        return false;
                    }
                    i += used;
                } else if matches!(
                    c,
                    b'`' | b'\\'
                        | b';'
                        | b'&'
                        | b'|'
                        | b'<'
                        | b'>'
                        | b'('
                        | b')'
                        | b'['
                        | b']'
                        | b'#'
                ) {
                    return false;
                } else {
                    i += 1;
                }
            }
            1 => {
                if c == b'\'' {
                    state = 0;
                }
                i += 1;
            }
            2 => {
                if c == b'"' {
                    state = 0;
                    i += 1;
                } else if c == b'$' {
                    let used = simple_expansion(&rhs[i..], kind);
                    if used == 0 {
                        return false;
                    }
                    i += used;
                } else if c == b'`' || c == b'\\' {
                    return false;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
    let Some(closed) = closed else {
        return false;
    };
    if state != 0 {
        return false;
    }
    let tail = &rhs[closed + 1..];
    tail_ws_re().is_match(tail) || tail_comment_re().is_match(tail)
}

/// Validate a complete one-line PKGBUILD array assignment by positive grammar.
/// For `source`, the lexical proof is necessary but not sufficient: the values
/// must also pass the fail-closed URI policy.
pub fn safe_array_literal_line(line: &str, kind: LiteralKind) -> bool {
    let bytes = line.as_bytes();
    let ok = match kind {
        LiteralKind::Literal => literal_opener_re().is_match(bytes),
        LiteralKind::Source => source_opener_inline_re().is_match(bytes),
    };
    if !ok {
        return false;
    }
    // RHS = everything after the first '='.
    let Some(eq) = line.find('=') else {
        return false;
    };
    let rhs = &line[eq + 1..];
    if !array_literal_rhs_ok(rhs.as_bytes(), kind) {
        return false;
    }
    if kind == LiteralKind::Source && !source_line_values_are_safe(line) {
        return false;
    }
    true
}

// --- single-line checksum literal ------------------------------------------

/// `(md5|shaN|b2)sums[_arch]=( <literal atoms> )` on one line.
pub fn checksum_literal_line(line: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        let value = r"(SKIP|[A-Fa-f0-9]{16,})";
        let atom = format!(r#"({value}|'{value}'|"{value}")"#);
        let pat = format!(
            r"^[[:space:]]*(md5|sha[0-9]+|b2)sums(_[[:alnum:]_]+)?=\([[:space:]]*({atom}[[:space:]]*)*\)[[:space:]]*([[:space:]]+#.*)?$"
        );
        RegexBuilder::new(&pat).unicode(false).build().unwrap()
    });
    re.is_match(line.as_bytes())
}

// --- boring classification --------------------------------------------------

bre!(comment_re, r"^[[:space:]]*#");

fn pkgver_rule() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let t = r"[0-9A-Za-z.+_~:-]+";
        let pat = format!(
            r#"^[[:space:]]*(pkgver|pkgrel|epoch)=({t}|'{t}'|"{t}")[[:space:]]*([[:space:]]+#.*)?$"#
        );
        RegexBuilder::new(&pat).unicode(false).build().unwrap()
    })
}

fn commit_var_rule() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let t = r"[0-9a-f]{7,40}";
        let pat = format!(
            r#"^[[:space:]]*_(commit|gittag|gitrev|tag|rev)(_[[:alnum:]_]*)?=[[:space:]]*({t}|'{t}'|"{t}")[[:space:]]*$"#
        );
        RegexBuilder::new(&pat).unicode(false).build().unwrap()
    })
}

fn version_var_rule() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let t = r"v?[0-9]+(\.[0-9]+)+";
        let pat =
            format!(r#"^[[:space:]]*_[[:alnum:]_]*=[[:space:]]*({t}|'{t}'|"{t}")[[:space:]]*$"#);
        RegexBuilder::new(&pat).unicode(false).build().unwrap()
    })
}

fn indexed_checksum_rule() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        RegexBuilder::new(
            r#"^[[:space:]]*(md5|sha[0-9]+|b2)sums\[[0-9]+\][[:space:]]*=[[:space:]]*(SKIP|[0-9a-fA-F]{16,}|'(SKIP|[0-9a-fA-F]{16,})'|"(SKIP|[0-9a-fA-F]{16,})")[[:space:]]*$"#,
        )
        .unicode(false)
        .build()
        .unwrap()
    })
}

/// Deterministic boring classification for an added PKGBUILD line. Callers MUST
/// first prove plain candidate lexical context; the contextual array helpers
/// own boring_edge. Unknown shell syntax is Review — never LLM-overridable.
pub fn boring_pkgbuild_added_line_class(line: &str) -> LineClass {
    if line.trim().is_empty() {
        return LineClass::Boring;
    }
    let b = line.as_bytes();
    if comment_re().is_match(b) {
        return LineClass::Boring;
    }
    if pkgver_rule().is_match(b) {
        return LineClass::Boring;
    }
    if commit_var_rule().is_match(b) {
        return LineClass::Boring;
    }
    if version_var_rule().is_match(b) {
        return LineClass::Boring;
    }
    if safe_array_literal_line(line, LiteralKind::Literal) {
        return LineClass::Boring;
    }
    if safe_array_literal_line(line, LiteralKind::Source) {
        return LineClass::Boring;
    }
    if checksum_literal_line(line) {
        return LineClass::Boring;
    }
    if indexed_checksum_rule().is_match(b) {
        return LineClass::Boring;
    }
    LineClass::Review
}

// --- contextual array helpers ----------------------------------------------

bre!(single_quoted_re, r"^[[:space:]]*'[^']+'[[:space:]]*$");
bre!(
    optdepends_opener_re,
    r"^[[:space:]]*optdepends=\([[:space:]]*$"
);
bre!(
    source_opener_eol_re,
    r"^[[:space:]]*source(_[[:alnum:]_]+)?=\([[:space:]]*$"
);
bre!(
    sums_opener_eol_re,
    r"^[[:space:]]*(md5|sha[0-9]+|b2)sums(_[[:alnum:]_]+)?=\([[:space:]]*$"
);
bre!(
    dep_opener_re,
    r"^[[:space:]]*(depends|makedepends|checkdepends)(_[[:alnum:]_]+)?=\([[:space:]]*$"
);
bre!(standalone_closer_re, r"^[[:space:]]*\)[[:space:]]*(#.*)?$");

fn checksum_name() -> &'static str {
    r"(md5|sha[0-9]+|b2)sums(_[[:alnum:]_]+)?"
}
fn checksum_atom() -> String {
    let value = r"(SKIP|[A-Fa-f0-9]{16,})";
    format!(r#"({value}|'{value}'|"{value}")"#)
}

/// Opener for the checksum array tracker: `sums=(` at EOL OR exactly one inline
/// literal first token (`sums=('hex'`). Deliberately NOT the shared/source
/// opener — arbitrary inline content would re-open array-state leakage into
/// validpgpkeys.
fn checksum_array_opener() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let atom = checksum_atom();
        let name = checksum_name();
        let pat = format!(r"^[[:space:]]*{name}=\([[:space:]]*({atom}[[:space:]]*)?$");
        RegexBuilder::new(&pat).unicode(false).build().unwrap()
    })
}

fn checksum_inline_opener() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let atom = checksum_atom();
        let name = checksum_name();
        let pat = format!(r"^[[:space:]]*{name}=\([[:space:]]*{atom}[[:space:]]*$");
        RegexBuilder::new(&pat).unicode(false).build().unwrap()
    })
}

fn checksum_standalone_member() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let atom = checksum_atom();
        let pat = format!(r"^[[:space:]]*{atom}[[:space:]]*(\)[[:space:]]*(#.*)?)?$");
        RegexBuilder::new(&pat).unicode(false).build().unwrap()
    })
}

/// optdepends: only literal single-quoted entries are metadata-safe; unquoted/
/// double-quoted entries can perform expansion.
pub fn optdepends_added_line(pkgbuild: &[u8], wanted: &str) -> bool {
    if !single_quoted_re().is_match(wanted.as_bytes()) {
        return false;
    }
    array_member_added_line(pkgbuild, wanted.as_bytes(), optdepends_opener_re())
}

/// A literal checksum token belonging to a checksum array. Eligible added
/// shapes: inline literal opener, standalone member, literal final member +
/// closer, or a standalone closer — each proven against the checksum-specific
/// opener in the complete candidate.
pub fn checksum_array_line(pkgbuild: &[u8], wanted: &str) -> bool {
    let b = wanted.as_bytes();
    let eligible = checksum_inline_opener().is_match(b)
        || checksum_standalone_member().is_match(b)
        || standalone_closer_re().is_match(b);
    if !eligible {
        return false;
    }
    array_member_added_line(pkgbuild, b, checksum_array_opener())
}

/// Multiline source/checksum openers and closers. A bare `)` is safe only when
/// every byte-identical occurrence closes the same proven source/checksum array.
/// Returns true ⇒ boring_edge.
pub fn metadata_array_syntax_added_line(pkgbuild: &[u8], wanted: &str) -> bool {
    let b = wanted.as_bytes();
    if source_opener_eol_re().is_match(b) {
        return array_member_added_line(pkgbuild, b, source_opener_eol_re());
    }
    if sums_opener_eol_re().is_match(b) {
        return array_member_added_line(pkgbuild, b, sums_opener_eol_re());
    }
    if !standalone_closer_re().is_match(b) {
        return false;
    }
    if array_member_added_line(pkgbuild, b, source_opener_eol_re()) {
        return true;
    }
    array_member_added_line(pkgbuild, b, sums_opener_eol_re())
}

/// A source continuation member: boring-edge only after BOTH a positive
/// one-word source grammar (on a synthetic single-line wrap, which also runs
/// the URI policy) AND complete-candidate array context are proven.
pub fn source_array_added_line(pkgbuild: &[u8], wanted: &str) -> bool {
    let member = wanted.trim();
    if member.is_empty() {
        return false;
    }
    if !safe_array_literal_line(&format!("source=({member})"), LiteralKind::Source) {
        return false;
    }
    array_member_added_line(pkgbuild, wanted.as_bytes(), source_opener_eol_re())
}

/// Does the .SRCINFO mirror declare `spec` as a dependency? awk default-FS:
/// ($1 in deps) && $2=="=" && $3==spec.
fn srcinfo_declares_dep(srcinfo: &str, spec: &str) -> bool {
    for line in srcinfo.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 3
            && matches!(f[0], "depends" | "makedepends" | "checkdepends")
            && f[1] == "="
            && f[2] == spec
        {
            return true;
        }
    }
    false
}

/// PKGBUILD dependency: restrict to a literal single-quoted array member,
/// require the generated .SRCINFO mirror as a second structural check, then
/// apply the installed/sync-db/intra-pkgbase trust policy.
pub fn repo_dep_added_line<P: Pacman + ?Sized>(
    pacman: &P,
    pkgbuild: &[u8],
    srcinfo: &str,
    wanted: &str,
) -> bool {
    if !single_quoted_re().is_match(wanted.as_bytes()) {
        return false;
    }
    // spec = the text inside the single quotes.
    static EXTRACT: OnceLock<Regex> = OnceLock::new();
    let extract =
        EXTRACT.get_or_init(|| Regex::new(r"^[[:space:]]*'([^']+)'[[:space:]]*$").unwrap());
    let Some(caps) = extract.captures(wanted.as_bytes()) else {
        return false;
    };
    let spec = String::from_utf8_lossy(caps.get(1).unwrap().as_bytes()).into_owned();

    if !srcinfo_declares_dep(srcinfo, &spec) {
        return false;
    }
    if !trusted_dependency_spec(pacman, srcinfo, &spec) {
        return false;
    }
    array_member_added_line(pkgbuild, wanted.as_bytes(), dep_opener_re())
}

// --- review-detail text classification (UX) ---------------------------------

bre!(
    build_func_header_re,
    r"^[[:space:]]*(prepare|build|check|package|install)[[:space:]]*\(\)[[:space:]]*\{?[[:space:]]*$"
);
bre!(
    build_body_re,
    r"^[[:space:]]*(install|cp|mv|rm|ln|mkdir|cmake|make|ninja|cargo|go|npm|yarn|pnpm|bun|pip|python|sh |bash |\./)"
);

/// Content-based (NOT git-hunk-annotation-based) detection of build logic: a
/// shell statement that runs at build/install time. Used only for summary-text
/// selection — a missed keyword falls through to the generic summary (fail-safe).
pub fn detail_is_build_logic(text: &str) -> bool {
    let b = text.as_bytes();
    build_func_header_re().is_match(b) || build_body_re().is_match(b)
}

bre!(
    numeric_var_re,
    r"^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=[0-9]+[[:space:]]*$"
);

pub fn review_added_line_summary(text: &str) -> String {
    if detail_is_build_logic(text) {
        return "package build instructions changed".to_string();
    }
    if let Some(caps) = numeric_var_re().captures(text.as_bytes()) {
        let name = String::from_utf8_lossy(caps.get(1).unwrap().as_bytes());
        return format!("PKGBUILD variable '{name}' changed; numeric value needs review");
    }
    "build file changed in a way aur-gate cannot auto-clear".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_plain(pkgbuild: &str, wanted: &str) -> bool {
        line_has_plain_context(pkgbuild.as_bytes(), wanted.as_bytes())
    }

    #[test]
    fn plain_context_balanced_line() {
        let pkg = "pkgname=x\npkgver=1.0\nsource=(\"https://example.com/x.tar\")\n";
        assert!(ctx_plain(pkg, "pkgver=1.0"));
        // a line not present in the candidate is not plain-context
        assert!(!ctx_plain(pkg, "pkgver=2.0"));
    }

    #[test]
    fn multiline_quote_poisons_added_comment() {
        // The added line looks like a comment but sits inside an unchanged open
        // double quote; command substitution would run. Sticky-unsafe ⇒ not plain.
        let pkg = "pkgname=x\n_desc=\"\n#$(printf MARKER >&2)\nold text\n\"\n";
        assert!(!ctx_plain(pkg, "#$(printf MARKER >&2)"));
    }

    #[test]
    fn herestring_does_not_poison() {
        // `<<<` is a herestring, not a heredoc; the line is balanced.
        let pkg = "pkgname=x\n_note=$(cat <<< \"trusted\")\npkgver=2.0\n";
        assert!(ctx_plain(pkg, "pkgver=2.0"));
        assert!(!is_ambiguous(b"_note=$(cat <<< \"trusted\")"));
        assert!(is_ambiguous(b"cat <<EOF"));
        assert!(is_ambiguous(b"cat <<- EOF"));
    }

    #[test]
    fn trailing_backslash_is_ambiguous() {
        assert!(is_ambiguous(b"source=(foo \\"));
        assert!(is_ambiguous(b"echo \"unterminated"));
        assert!(!is_ambiguous(b"echo \"terminated\""));
    }

    #[test]
    fn array_membership_and_removed_opener_latch() {
        // A stray quoted token after a closed/empty array is OUTSIDE ⇒ array
        // mode must not clear it (removed-opener-cannot-latch).
        let pkg = "pkgname=x\nmakedepends=()\n'alsa-lib'\nsource=(\"u\")\n";
        let dep_opener = dep_opener_re();
        assert!(!array_member_added_line(
            pkg.as_bytes(),
            b"'alsa-lib'",
            dep_opener
        ));

        // A real member inside an open array clears.
        let pkg2 = "pkgname=x\ndepends=(\n'alsa-lib'\n)\n";
        assert!(array_member_added_line(
            pkg2.as_bytes(),
            b"'alsa-lib'",
            dep_opener
        ));
    }

    #[test]
    fn final_member_with_closer_is_in_array() {
        // `'hex')` is the wanted line AND carries the closer; membership is
        // recorded before the array closes on that line.
        let pkg = "pkgname=x\nsha256sums=(\n'aaaa1111aaaa1111aaaa1111aaaa1111')\n";
        let opener = checksum_array_opener();
        assert!(array_member_added_line(
            pkg.as_bytes(),
            b"'aaaa1111aaaa1111aaaa1111aaaa1111')",
            opener
        ));
    }

    #[test]
    fn safe_array_literal_source_expansion() {
        assert!(safe_array_literal_line(
            "source=(\"https://example.com/${pkgver}/x.tar\")",
            LiteralKind::Source
        ));
        // command substitution is rejected
        assert!(!safe_array_literal_line(
            "source=($(evil))",
            LiteralKind::Source
        ));
        // process substitution rejected
        assert!(!safe_array_literal_line(
            "source=(<(printf x))",
            LiteralKind::Source
        ));
        // early close + trailing command rejected
        assert!(!safe_array_literal_line(
            "sha256sums=(aaaa1111aaaa1111aaaa1111aaaa1111)evil",
            LiteralKind::Literal
        ));
        // license literal array ok
        assert!(safe_array_literal_line(
            "license=(MIT LGPL-2.0-or-later)",
            LiteralKind::Literal
        ));
        // source URI policy still enforced
        assert!(!safe_array_literal_line(
            "source=(\"http://example.com/x.tar\")",
            LiteralKind::Source
        ));
    }

    #[test]
    fn boring_classification() {
        use LineClass::*;
        assert_eq!(
            boring_pkgbuild_added_line_class("pkgver=r1234.abc1234"),
            Boring
        );
        assert_eq!(boring_pkgbuild_added_line_class("pkgver=1.0+dfsg1"), Boring);
        assert_eq!(
            boring_pkgbuild_added_line_class("_commit=042b3c1a4c53f2c3808067f519fbfc67b72cad8b"),
            Boring
        );
        assert_eq!(
            boring_pkgbuild_added_line_class("_nwjs_ffmpeg_version=0.113.0"),
            Boring
        );
        assert_eq!(
            boring_pkgbuild_added_line_class("_electron_version=v25.3.0"),
            Boring
        );
        assert_eq!(
            boring_pkgbuild_added_line_class("sha256sums=('aaaa1111aaaa1111aaaa1111aaaa1111')"),
            Boring
        );
        assert_eq!(
            boring_pkgbuild_added_line_class("sha512sums[0]=SKIP"),
            Boring
        );
        // command substitution in a version var is NOT boring
        assert_eq!(
            boring_pkgbuild_added_line_class("_version=$(echo 1.2.3)"),
            Review
        );
        // arbitrary _var with a hex fingerprint is NOT boring (not _commit/_tag…)
        assert_eq!(
            boring_pkgbuild_added_line_class("_evil=0123456789abcdef0123456789abcdef01234567"),
            Review
        );
        // operator chaining after pkgver is NOT boring (EOL-anchored rule)
        assert_eq!(
            boring_pkgbuild_added_line_class("pkgver=2.0; evil_cmd"),
            Review
        );
        // unknown shell is review
        assert_eq!(
            boring_pkgbuild_added_line_class("build() { make; }"),
            Review
        );

        for line in [
            "_commit='042b3c1a4c53f2c3808067f519fbfc67b72cad8b'",
            "_tag=\"v1.2.3\"",
            "_version=1.2.3",
            "_version='v1.2.3'",
            "pkgver='1.2.3' # upstream",
            "license=(MIT Apache-2.0)",
            "arch=('x86_64')",
            "noextract=('archive.zip')",
        ] {
            assert_eq!(boring_pkgbuild_added_line_class(line), Boring, "{line}");
        }
        for line in [
            "_commit=$(curl https://evil)",
            "_commit=\"$(date)\"",
            "pkgver=$(date)",
            "pkgrel=$((1+1))",
            "pkgver=2.0 | sh",
            "sha256sums=($(date))",
            "license=($(evil))",
            "sha512sums[0]=$(date)",
            "'https://example.com/stray.tar'",
            "package() { cp payload \"$pkgdir\"; }",
        ] {
            assert_eq!(boring_pkgbuild_added_line_class(line), Review, "{line}");
        }
    }

    #[test]
    fn checksum_literal_line_shapes() {
        assert!(checksum_literal_line(
            "sha256sums=(aaaa1111aaaa1111aaaa1111aaaa1111)"
        ));
        assert!(checksum_literal_line(
            "sha256sums=('aaaa1111aaaa1111aaaa1111aaaa1111' 'bbbb2222bbbb2222bbbb2222bbbb2222')"
        ));
        assert!(checksum_literal_line("sha256sums=(SKIP) # vendored"));
        assert!(!checksum_literal_line("sha256sums=($(evil))"));
    }

    #[test]
    fn build_logic_and_summary() {
        assert!(detail_is_build_logic("build() {"));
        assert!(detail_is_build_logic(
            "  install -Dm755 ./x \"${pkgdir}/usr/bin/x\""
        ));
        assert!(detail_is_build_logic("make"));
        assert!(!detail_is_build_logic("license=(MIT)"));
        assert_eq!(
            review_added_line_summary("  install -Dm755 ./bwrap \"${pkgdir}/usr/lib/x/bwrap\""),
            "package build instructions changed"
        );
        assert_eq!(
            review_added_line_summary("_build=4510119262814208"),
            "PKGBUILD variable '_build' changed; numeric value needs review"
        );
        assert_eq!(
            review_added_line_summary("weird shell thing"),
            "build file changed in a way aur-gate cannot auto-clear"
        );
    }
}
