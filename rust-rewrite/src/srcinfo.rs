//! .SRCINFO parsing, install-confirmation, baseline recovery, and the
//! fail-closed source-URI policy (Finding gh3). Also the domain-drift
//! extractors (maintainer / source hosts).
//!
//! Everything here is byte-oriented (regex::bytes, unicode(false)) to match the
//! script's LC_ALL=C semantics exactly. Non-ASCII bytes in source URLs are the
//! IDN-homograph signal and must survive parsing untouched.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{bail, Result};
use regex::bytes::{Regex, RegexBuilder};

use crate::state::{is_object_id, valid_pkg_name};

/// Overridable pacman seams (the script redefines these functions in selftest).
/// `local_record` returns (name, version, pkgbase, build_epoch, install_epoch).
pub trait Pacman {
    /// `pacman -Q -- <name>` → prints "<name> <ver>".
    fn query(&self, name: &str) -> Option<String>;
    /// Root-owned local DB record; binds an installed pkgname back to pkgbase.
    fn local_record(&self, name: &str) -> Option<LocalRecord>;
    /// `pacman -Si` — is this a known repository package?
    fn sync_info(&self, name: &str) -> bool;
    /// `pacman -T` — is this dep/provision already satisfied?
    fn dep_satisfied(&self, spec: &str) -> bool;
}

#[derive(Clone, Debug)]
pub struct LocalRecord {
    pub name: String,
    pub version: String,
    pub pkgbase: String,
    pub build_epoch: u64,
    pub install_epoch: u64,
}

/// Real pacman-backed implementation.
pub struct SystemPacman;

impl Pacman for SystemPacman {
    fn query(&self, name: &str) -> Option<String> {
        let out = Command::new("/usr/bin/pacman")
            .args(["-Q", "--", name])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn local_record(&self, name: &str) -> Option<LocalRecord> {
        // pacman-conf DBPath, then scan <dbpath>/local/<name>-*/desc.
        let out = Command::new("/usr/bin/pacman-conf")
            .arg("DBPath")
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let dbpath = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if dbpath.is_empty() {
            return None;
        }
        let local = Path::new(&dbpath).join("local");
        let entries = std::fs::read_dir(&local).ok()?;
        for e in entries.flatten() {
            let fname = e.file_name().to_string_lossy().to_string();
            if !(fname.starts_with(&format!("{name}-"))) {
                continue;
            }
            let desc = e.path().join("desc");
            let content = std::fs::read_to_string(&desc).ok()?;
            if let Some(rec) = parse_desc(&content, name) {
                return Some(rec);
            }
        }
        None
    }

    fn sync_info(&self, name: &str) -> bool {
        Command::new("/usr/bin/pacman")
            .args(["-Si", "--", name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn dep_satisfied(&self, spec: &str) -> bool {
        Command::new("/usr/bin/pacman")
            .args(["-T", "--", spec])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

/// Parse a pacman local-db `desc` file. `%NAME%`/`%VERSION%`/`%BASE%`/
/// `%BUILDDATE%`/`%INSTALLDATE%` each precede their value on the next line.
fn parse_desc(content: &str, wanted: &str) -> Option<LocalRecord> {
    let mut name = None;
    let mut version = None;
    let mut base = None;
    let mut built = None;
    let mut installed = None;
    let mut lines = content.lines();
    while let Some(line) = lines.next() {
        match line {
            "%NAME%" => name = lines.next().map(str::to_string),
            "%VERSION%" => version = lines.next().map(str::to_string),
            "%BASE%" => base = lines.next().map(str::to_string),
            "%BUILDDATE%" => built = lines.next().and_then(|v| v.parse().ok()),
            "%INSTALLDATE%" => installed = lines.next().and_then(|v| v.parse().ok()),
            _ => {}
        }
    }
    let name = name?;
    let version = version?;
    if name != wanted || version.is_empty() {
        return None;
    }
    Some(LocalRecord {
        pkgbase: base.unwrap_or_else(|| name.clone()),
        name,
        version,
        build_epoch: built.unwrap_or(0),
        install_epoch: installed.unwrap_or(0),
    })
}

// --- .SRCINFO field extraction ---------------------------------------------

/// awk -F' = ' helpers. Leading-whitespace tolerant for attributes (some
/// packages ship space-indented .SRCINFO, e.g. opera-developer); pkgbase/pkgname
/// are section headers at column 0.
fn srcinfo_field(content: &str, key: &str, column0: bool) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim_start();
        let matches = if column0 {
            line.starts_with(&format!("{key} ="))
        } else {
            trimmed.starts_with(&format!("{key} ="))
        };
        if matches {
            // split on " = " and take the value
            if let Some(idx) = trimmed.find(" = ") {
                return Some(trimmed[idx + 3..].trim().to_string());
            }
        }
    }
    None
}

/// All `pkgname =` section headers (column 0), in order.
fn srcinfo_pkgnames(content: &str) -> Vec<String> {
    content
        .lines()
        .filter(|l| l.starts_with("pkgname ="))
        .filter_map(|l| l.find(" = ").map(|i| l[i + 3..].trim().to_string()))
        .collect()
}

/// find_pkg_dir's .SRCINFO membership check: pkgbase==base AND pkgname==pkg.
/// awk default-FS: $1=key, $3=value.
pub fn srcinfo_declares(content: &str, pkg: &str, base: &str) -> bool {
    let mut base_ok = false;
    let mut name_ok = false;
    for line in content.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 3 {
            if f[0] == "pkgbase" && f[2] == base {
                base_ok = true;
            }
            if f[0] == "pkgname" && f[2] == pkg {
                name_ok = true;
            }
        }
    }
    base_ok && name_ok
}

// --- install confirmation (Finding F) ---------------------------------------

/// Return true if a package built from commit `sha` is currently installed at
/// exactly that commit's version, bound back to `expected_base`. `not_before`
/// is the earliest acceptable install timestamp (staged-file mtime from accept).
pub fn installed_matches<P: Pacman + ?Sized>(
    pacman: &P,
    srcinfo_at_sha: &str,
    expected_base: &str,
    not_before: u64,
) -> bool {
    // Declared pkgbase must match the trust-anchor key.
    let declared_base = srcinfo_field(srcinfo_at_sha, "pkgbase", true).unwrap_or_default();
    if declared_base != expected_base {
        return false;
    }
    let pkgver = srcinfo_field(srcinfo_at_sha, "pkgver", false).unwrap_or_default();
    let pkgrel = srcinfo_field(srcinfo_at_sha, "pkgrel", false).unwrap_or_default();
    let epoch = srcinfo_field(srcinfo_at_sha, "epoch", false).unwrap_or_default();
    if pkgver.is_empty() || pkgrel.is_empty() {
        return false;
    }
    let mut want = format!("{pkgver}-{pkgrel}");
    if !epoch.is_empty() && epoch != "0" {
        want = format!("{epoch}:{want}");
    }
    // pkgname= section headers at column 0; deliberately NO pkgbase fallback.
    let names = srcinfo_pkgnames(srcinfo_at_sha);
    if names.is_empty() {
        return false;
    }
    for pkgname in names {
        if !valid_pkg_name(&pkgname) {
            continue;
        }
        let Some(rec) = pacman.local_record(&pkgname) else {
            continue;
        };
        if rec.name != pkgname || rec.pkgbase != expected_base {
            continue;
        }
        if rec.version != want {
            continue;
        }
        if rec.build_epoch < not_before || rec.install_epoch < not_before {
            continue;
        }
        return true;
    }
    false
}

// --- baseline recovery (cat-file --batch block-index parser) -----------------

/// Walk origin/<branch> history and return the OLDEST commit whose .SRCINFO
/// matches version `want` ("epoch:pkgver-pkgrel", epoch optional).
///
/// cat-file --batch echoes the BLOB's sha in its header, not the commit's, so
/// the commit↔.SRCINFO association is restored by block index: the Nth object
/// block corresponds to the Nth commit in the oldest-first list. A `missing`
/// object (or a tree/commit/tag header) advances the index without a version.
pub fn find_baseline_commit(dir: &Path, want: &str, branch: &str) -> Result<Option<String>> {
    let out = crate::git::safe_git(
        Some(dir),
        &["rev-list", "--reverse", &format!("origin/{branch}")],
    )?;
    if !out.status.success() {
        bail!("rev-list failed");
    }
    let commits: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    if commits.is_empty() {
        return Ok(None);
    }
    if commits.iter().any(|commit| !is_object_id(commit)) {
        bail!("rev-list returned an invalid object id");
    }

    // Feed "<sha>:.SRCINFO\n" for each commit into cat-file --batch.
    let mut command = crate::git::safe_git_command(Some(dir), &["cat-file", "--batch"])?;
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    {
        let Some(stdin) = child.stdin.as_mut() else {
            bail!("cat-file stdin was not piped");
        };
        for commit in &commits {
            stdin.write_all(format!("{commit}:.SRCINFO\n").as_bytes())?;
        }
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        bail!("cat-file --batch failed");
    }

    parse_baseline_batch(&output.stdout, &commits, want)
}

/// Parse the size-framed `cat-file --batch` stream. Blob content is never
/// interpreted as a header: an attacker-controlled `.SRCINFO` line can look
/// exactly like one, so line-oriented parsing would desynchronize commit↔blob
/// association and potentially choose the wrong baseline.
fn parse_baseline_batch(stream: &[u8], commits: &[String], want: &str) -> Result<Option<String>> {
    let header_re =
        Regex::new(r"^[0-9a-f]{40}([0-9a-f]{24})? (blob|tree|commit|tag) ([0-9]+)$").unwrap();
    let mut cursor = 0usize;

    for commit in commits {
        let relative = &stream[cursor..];
        let Some(line_end) = relative.iter().position(|byte| *byte == b'\n') else {
            bail!("truncated cat-file header");
        };
        let header = &relative[..line_end];
        cursor += line_end + 1;

        let missing = format!("{commit}:.SRCINFO missing");
        if header == missing.as_bytes() {
            continue;
        }
        let Some(captures) = header_re.captures(header) else {
            bail!("malformed cat-file header");
        };
        let kind = captures.get(2).unwrap().as_bytes();
        let size_text = std::str::from_utf8(captures.get(3).unwrap().as_bytes())?;
        let size = size_text.parse::<usize>()?;
        let end = cursor
            .checked_add(size)
            .ok_or_else(|| anyhow::anyhow!("cat-file blob size overflow"))?;
        if end >= stream.len() || stream[end] != b'\n' {
            bail!("truncated cat-file blob");
        }
        let object = &stream[cursor..end];
        cursor = end + 1;

        if kind == b"blob" {
            let blob = std::str::from_utf8(object)?;
            if srcinfo_version(blob).as_deref() == Some(want) {
                return Ok(Some(commit.clone()));
            }
        }
    }
    if cursor != stream.len() {
        bail!("unexpected trailing cat-file output");
    }
    Ok(None)
}

fn srcinfo_version(content: &str) -> Option<String> {
    let pkgver = srcinfo_field(content, "pkgver", false)?;
    let pkgrel = srcinfo_field(content, "pkgrel", false)?;
    let epoch = srcinfo_field(content, "epoch", false).unwrap_or_default();
    if epoch.is_empty() || epoch == "0" {
        Some(format!("{pkgver}-{pkgrel}"))
    } else {
        Some(format!("{epoch}:{pkgver}-{pkgrel}"))
    }
}

// --- .SRCINFO added-line classification --------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LineClass {
    Boring,
    Review,
}

/// Detect a line that differs from a removed .SRCINFO line only by leading
/// whitespace (a reflow, not a value change). Operates on the .SRCINFO diff.
pub fn srcinfo_leading_ws_only_added_line(diff: &str, wanted: &str) -> bool {
    fn norm(s: &str) -> &str {
        s.trim_start()
    }
    let mut removed: std::collections::HashMap<String, String> = Default::default();
    for line in diff.lines() {
        if line.starts_with("+++") || line.starts_with("---") {
            continue;
        }
        if let Some(raw) = line.strip_prefix('-') {
            removed.insert(norm(raw).to_string(), raw.to_string());
            continue;
        }
        if let Some(text) = line.strip_prefix('+') {
            if text == wanted {
                if let Some(prev) = removed.get(norm(text)) {
                    if !prev.is_empty() && prev != text {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// Fail-closed source-URI policy for a single source line or array member
/// (Finding gh3). Safe only if every value is an https:// URL (or filename::
/// https alias) with a dotted, non-IPv4 host, no userinfo/port/IPv6/query/
/// fragment, and no VCS/alt scheme.
pub fn source_line_values_are_safe(line: &str) -> bool {
    let prefix_re =
        RegexBuilder::new(r"^[[:space:]]*source(_[[:alnum:]_]+)?[[:space:]]*=[[:space:]]*(\()?")
            .unicode(false)
            .build()
            .unwrap();
    let suffix_re = RegexBuilder::new(r"\)[[:space:]]*(#.*)?$")
        .unicode(false)
        .build()
        .unwrap();

    let s = prefix_re.replace(line.as_bytes(), &b""[..]).into_owned();
    let s = suffix_re.replace(&s, &b""[..]).into_owned();
    let s = String::from_utf8_lossy(&s);

    // Tokenize respecting single/double quotes; check each token.
    let mut state = 0u8;
    let mut token = String::new();
    for c in s.chars() {
        match state {
            0 => {
                if c == ' ' || c == '\t' {
                    if !token.is_empty() && token != ")" && !source_value_safe(&token) {
                        return false;
                    }
                    token.clear();
                } else if c == '\'' {
                    state = 1;
                    token.push(c);
                } else if c == '"' {
                    state = 2;
                    token.push(c);
                } else {
                    token.push(c);
                }
            }
            1 => {
                token.push(c);
                if c == '\'' {
                    if !source_value_safe(&token) {
                        return false;
                    }
                    state = 0;
                    token.clear();
                }
            }
            _ => {
                token.push(c);
                if c == '"' {
                    if !source_value_safe(&token) {
                        return false;
                    }
                    state = 0;
                    token.clear();
                }
            }
        }
    }
    if !token.is_empty() && token != ")" {
        return source_value_safe(&token);
    }
    true
}

/// The `safe(v)` awk function.
fn source_value_safe(v: &str) -> bool {
    let mut v = v;
    // Strip surrounding matching quotes.
    let bytes = v.as_bytes();
    if bytes.len() >= 2 {
        let (a, b) = (bytes[0], bytes[bytes.len() - 1]);
        if (a == b'"' && b == b'"') || (a == b'\'' && b == b'\'') {
            v = &v[1..v.len() - 1];
        }
    }
    if v.is_empty() {
        return true;
    }
    // Extract URL from a filename::URL alias: the last "::" before "://".
    let url: &str = if let Some(p) = v.find("://") {
        if p > 0 {
            let before = &v[..p];
            match before.rfind("::") {
                Some(q) => &v[q + 2..],
                None => v,
            }
        } else {
            v
        }
    } else {
        v
    };

    // Authority/transport anomalies are not safe.
    if url.contains(['[', ']', '@', '?', '#']) {
        return false;
    }
    // Only https is trusted.
    if !url.starts_with("https://") {
        return false;
    }
    // Dotted hostname, then a path or end-of-string.
    static HOST_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let host_re = HOST_RE.get_or_init(|| {
        RegexBuilder::new(
            r"^https://([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(/|$)",
        )
        .unicode(false)
        .build()
        .unwrap()
    });
    if !host_re.is_match(url.as_bytes()) {
        return false;
    }
    // Reject all-numeric dotted hosts (IPv4 literals).
    let h = &url["https://".len()..];
    let host = match h.find('/') {
        Some(p) => &h[..p],
        None => h,
    };
    static IPV4_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    if IPV4_RE
        .get_or_init(|| Regex::new(r"^[0-9.]+$").unwrap())
        .is_match(host.as_bytes())
    {
        return false;
    }
    true
}

/// .SRCINFO dependency line → trusted spec check (installed / sync-db /
/// intra-pkgbase). `members` is the candidate .SRCINFO text for intra-pkgbase
/// resolution.
pub fn srcinfo_repo_dep_added_line<P: Pacman + ?Sized>(
    pacman: &P,
    members_srcinfo: &str,
    line: &str,
) -> bool {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        RegexBuilder::new(
            r"^[[:space:]]*(depends|makedepends|checkdepends)[[:space:]]+=[[:space:]]+.+",
        )
        .unicode(false)
        .build()
        .unwrap()
    });
    if !re.is_match(line.as_bytes()) {
        return false;
    }
    // spec = strip the "key = " prefix, then cut at the first space.
    let stripped = RegexBuilder::new(
        r"^[[:space:]]*(depends|makedepends|checkdepends)[[:space:]]+=[[:space:]]+",
    )
    .unicode(false)
    .build()
    .unwrap()
    .replace(line.as_bytes(), &b""[..]);
    let stripped = String::from_utf8_lossy(&stripped);
    let spec = stripped.split_whitespace().next().unwrap_or("").to_string();
    trusted_dependency_spec(pacman, members_srcinfo, &spec)
}

/// Trust policy for a dependency spec: name grammar, then installed OR in the
/// sync db OR an intra-pkgbase member (pkgbase itself or a sibling pkgname).
pub fn trusted_dependency_spec<P: Pacman + ?Sized>(
    pacman: &P,
    members_srcinfo: &str,
    spec: &str,
) -> bool {
    let dep = spec.split(['<', '>', '=']).next().unwrap_or("").to_string();
    static NAME_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    if !NAME_RE
        .get_or_init(|| Regex::new(r"^[A-Za-z0-9@._+-]+$").unwrap())
        .is_match(dep.as_bytes())
    {
        return false;
    }
    if pacman.dep_satisfied(spec) {
        return true;
    }
    if pacman.sync_info(&dep) {
        return true;
    }
    // Intra-pkgbase: the name is this pkgbase or a declared sibling pkgname.
    let mut is_member = false;
    for line in members_srcinfo.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 3 && (f[0] == "pkgbase" || f[0] == "pkgname") && f[2] == dep {
            is_member = true;
            break;
        }
    }
    is_member
}

/// Boring classification for an added .SRCINFO line. Data-file shapes only —
/// applying these to PKGBUILD was a code-execution bypass.
pub fn boring_srcinfo_added_line_class(line: &str) -> LineClass {
    if line.trim().is_empty() {
        return LineClass::Boring;
    }
    static COMMENT: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    if COMMENT
        .get_or_init(|| {
            RegexBuilder::new(r"^[[:space:]]*#")
                .unicode(false)
                .build()
                .unwrap()
        })
        .is_match(line.as_bytes())
    {
        return LineClass::Boring;
    }
    static VERREL: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    if VERREL
        .get_or_init(|| {
            RegexBuilder::new(
                r"^[[:space:]]*(pkgver|pkgrel|epoch|source(_[[:alnum:]_]+)?|[[:alnum:]]+sums(_[[:alnum:]_]+)?)[[:space:]]+=[[:space:]]+",
            )
            .unicode(false).build().unwrap()
        })
        .is_match(line.as_bytes())
    {
        // Source values are attacker-authored → fail-closed URI policy.
        static SRC: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        if SRC
            .get_or_init(|| {
                RegexBuilder::new(r"^[[:space:]]*source(_[[:alnum:]_]+)?[[:space:]]+=[[:space:]]+")
                    .unicode(false).build().unwrap()
            })
            .is_match(line.as_bytes())
            && !source_line_values_are_safe(line)
        {
            return LineClass::Review;
        }
        return LineClass::Boring;
    }
    static META: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    if META
        .get_or_init(|| {
            RegexBuilder::new(
                r"^[[:space:]]*(pkgdesc|url|arch|license|groups|optdepends|noextract)[[:space:]]+=[[:space:]]+.+",
            )
            .unicode(false).build().unwrap()
        })
        .is_match(line.as_bytes())
    {
        return LineClass::Boring;
    }
    LineClass::Review
}

// --- domain-drift extractors -------------------------------------------------

/// Maintainer/Contributor email domains at a given PKGBUILD text (lowercased,
/// unique). Bracket-agnostic email regex.
pub fn maintainer_domains_from(pkgbuild: &str) -> BTreeSet<String> {
    static LINE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static EMAIL: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let line_re = LINE.get_or_init(|| {
        RegexBuilder::new(r"^[[:space:]]*#[[:space:]]*(Maintainer|Contributor):")
            .case_insensitive(true)
            .unicode(false)
            .build()
            .unwrap()
    });
    let email_re = EMAIL
        .get_or_init(|| Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap());
    let mut out = BTreeSet::new();
    for line in pkgbuild.lines() {
        if !line_re.is_match(line.as_bytes()) {
            continue;
        }
        for m in email_re.find_iter(line.as_bytes()) {
            let email = String::from_utf8_lossy(m.as_bytes()).to_lowercase();
            if let Some(domain) = email.rsplit('@').next() {
                out.insert(domain.to_string());
            }
        }
    }
    out
}

/// Update shell-array parenthesis depth while ignoring quoted/escaped text and
/// comments. In particular, a literal `)` inside a quoted URL must not end a
/// multiline source array before later hosts are inspected.
fn array_depth_after_line(line: &str, mut depth: usize) -> usize {
    let bytes = line.as_bytes();
    let mut quote = None;
    let mut i = 0;
    while i < bytes.len() {
        let byte = bytes[i];
        match quote {
            Some(b'\'') => {
                if byte == b'\'' {
                    quote = None;
                }
            }
            Some(b'"') => {
                if byte == b'\\' {
                    i += 1;
                } else if byte == b'"' {
                    quote = None;
                }
            }
            None => match byte {
                b'#' => break,
                b'\'' | b'"' => quote = Some(byte),
                b'\\' => i += 1,
                b'(' => depth = depth.saturating_add(1),
                b')' => depth = depth.saturating_sub(1),
                _ => {}
            },
            _ => unreachable!(),
        }
        i += 1;
    }
    depth
}

/// Hosts in source=() / source_*() arrays, including multi-line continuation
/// lines (the host-swap attack surface). Strips userinfo; handles bracketed
/// IPv6 literals (Finding gh3). Lowercased, unique.
pub fn source_domains_from(pkgbuild: &str) -> BTreeSet<String> {
    static OPENER: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    static HOST: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let opener = OPENER.get_or_init(|| {
        RegexBuilder::new(r"^[[:space:]]*source(_[[:alnum:]_]+)?[+]?=\(")
            .unicode(false)
            .build()
            .unwrap()
    });
    // Capture the host, dropping scheme + optional userinfo.
    let host = HOST
        .get_or_init(|| Regex::new(r"://(?:[^@]+@)?(\[[0-9A-Fa-f:]+\]|[a-zA-Z0-9._-]+)").unwrap());

    let mut out = BTreeSet::new();
    let mut in_src = false;
    let mut depth = 0usize;
    for line in pkgbuild.lines() {
        if opener.is_match(line.as_bytes()) {
            in_src = true;
            depth = 0;
        }
        if in_src {
            for m in host.captures_iter(line.as_bytes()) {
                if let Some(h) = m.get(1) {
                    out.insert(String::from_utf8_lossy(h.as_bytes()).to_lowercase());
                }
            }
            depth = array_depth_after_line(line, depth);
            if depth == 0 {
                in_src = false;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srcinfo_declares_membership() {
        let si = "pkgbase = true-base\n\tpkgver = 1\npkgname = target-member\n";
        assert!(srcinfo_declares(si, "target-member", "true-base"));
        assert!(!srcinfo_declares(si, "target-member", "evil-base"));
        assert!(!srcinfo_declares(si, "other", "true-base"));
    }

    #[test]
    fn source_policy_fail_closed() {
        // safe shapes
        assert!(source_line_values_are_safe(
            r#"source=("https://example.com/x.tar")"#
        ));
        assert!(source_line_values_are_safe(
            r#"source=("foo-1.0.tar.gz::https://example.com/foo-1.0.tar.gz")"#
        ));
        assert!(source_line_values_are_safe(
            "source = https://example.com/x.tar"
        ));
        // PoC classes from Finding gh3 → review
        assert!(!source_line_values_are_safe(
            r#"source=("https://example.com@evil.example/x")"#
        ));
        assert!(!source_line_values_are_safe(
            r#"source=("http://example.com/x")"#
        ));
        assert!(!source_line_values_are_safe(
            r#"source=("https://[::1]/x.tar")"#
        ));
        assert!(!source_line_values_are_safe(
            r#"source=("git+https://example.com/x.git#commit=dead")"#
        ));
        assert!(!source_line_values_are_safe(
            r#"source=("https://example.com:8443/x")"#
        ));
        assert!(!source_line_values_are_safe(
            r#"source=("https://127.0.0.1/x")"#
        ));
        assert!(!source_line_values_are_safe(r#"source=(/dev/null)"#));
        assert!(!source_line_values_are_safe(
            r#"source=('git@evil.example:repo.git')"#
        ));
        assert!(!source_line_values_are_safe(
            r#"source=("https://${host}/payload")"#
        ));
        assert!(!source_line_values_are_safe(
            r#"source=($'https://example.com/payload')"#
        ));
        assert!(!source_line_values_are_safe(r#"source=('payload.tar')"#));
        assert!(source_line_values_are_safe(
            r#"source=('payload.tar::https://example.com/payload.tar')"#
        ));
    }

    fn blob_block(content: &str) -> Vec<u8> {
        format!("{} blob {}\n{}\n", "a".repeat(40), content.len(), content).into_bytes()
    }

    #[test]
    fn baseline_batch_block_index() {
        let commits = vec!["1".repeat(40), "2".repeat(40), "3".repeat(40)];
        let one = "pkgbase = p\n\tpkgver = 1.0\n\tpkgrel = 1\npkgname = p\n";
        let three = "pkgbase = p\n\tpkgver = 3.0\n\tpkgrel = 1\npkgname = p\n";
        let mut stream = blob_block(one);
        stream.extend_from_slice(format!("{}:.SRCINFO missing\n", commits[1]).as_bytes());
        stream.extend_from_slice(&blob_block(three));
        assert_eq!(
            parse_baseline_batch(&stream, &commits, "3.0-1").unwrap(),
            Some(commits[2].clone())
        );
        assert_eq!(
            parse_baseline_batch(&stream, &commits, "1.0-1").unwrap(),
            Some(commits[0].clone())
        );
        assert_eq!(
            parse_baseline_batch(&stream, &commits, "9.9-9").unwrap(),
            None
        );
    }

    #[test]
    fn baseline_blob_content_cannot_desync_framing() {
        let commits = vec!["1".repeat(40), "2".repeat(40)];
        let header_lookalike = format!(
            "{} blob 999\n# arm64 binary is missing\npkgbase = p\n\tpkgver = 2.0\n\tpkgrel = 1\n",
            "b".repeat(40)
        );
        let second = "pkgbase = p\n\tpkgver = 3.0\n\tpkgrel = 1\n";
        let mut stream = blob_block(&header_lookalike);
        stream.extend_from_slice(&blob_block(second));
        assert_eq!(
            parse_baseline_batch(&stream, &commits, "2.0-1").unwrap(),
            Some(commits[0].clone())
        );
        assert_eq!(
            parse_baseline_batch(&stream, &commits, "3.0-1").unwrap(),
            Some(commits[1].clone())
        );
    }

    #[test]
    fn baseline_non_blob_object_advances_without_desynchronizing() {
        let commits = vec!["1".repeat(40), "2".repeat(40)];
        let tree_body = b"100644 blob deadbeef\tchild\0";
        let mut stream = format!("{} tree {}\n", "a".repeat(40), tree_body.len()).into_bytes();
        stream.extend_from_slice(tree_body);
        stream.push(b'\n');
        stream.extend_from_slice(&blob_block("pkgbase = p\n\tpkgver = 2\n\tpkgrel = 1\n"));
        assert_eq!(
            parse_baseline_batch(&stream, &commits, "2-1").unwrap(),
            Some(commits[1].clone())
        );
    }

    #[test]
    fn baseline_batch_rejects_truncation() {
        let commits = vec!["1".repeat(40)];
        let stream = format!("{} blob 20\nshort\n", "a".repeat(40));
        assert!(parse_baseline_batch(stream.as_bytes(), &commits, "1-1").is_err());
    }

    #[test]
    fn baseline_recovery_uses_oldest_matching_real_commit() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();
        assert!(std::process::Command::new("/usr/bin/git")
            .args(["-c", "init.defaultBranch=master", "init", "-q"])
            .arg(dir)
            .status()
            .unwrap()
            .success());
        let git = |args: &[&str]| {
            let output = std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(dir)
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        };
        let mut commits = Vec::new();
        for (message, version) in [("one", "1"), ("two", "2"), ("one-again", "1")] {
            std::fs::write(
                dir.join(".SRCINFO"),
                format!("pkgbase = p\n\tpkgver = {version}\n\tpkgrel = 1\npkgname = p\n"),
            )
            .unwrap();
            std::fs::write(
                dir.join("PKGBUILD"),
                format!("pkgname=p\npkgver={version}\npkgrel=1\n"),
            )
            .unwrap();
            git(&["add", "PKGBUILD", ".SRCINFO"]);
            git(&[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                message,
            ]);
            commits.push(git(&["rev-parse", "HEAD"]));
        }
        git(&[
            "update-ref",
            "refs/remotes/origin/master",
            commits.last().unwrap(),
        ]);
        assert_eq!(
            find_baseline_commit(dir, "1-1", "master").unwrap(),
            Some(commits[0].clone())
        );
        assert_eq!(find_baseline_commit(dir, "9-1", "master").unwrap(), None);
    }

    #[test]
    fn installed_matches_epoch_and_split() {
        struct Mock;
        impl Pacman for Mock {
            fn query(&self, _: &str) -> Option<String> {
                None
            }
            fn local_record(&self, name: &str) -> Option<LocalRecord> {
                if name == "test-split-tools" {
                    Some(LocalRecord {
                        name: name.into(),
                        version: "7-1".into(),
                        pkgbase: "test-split".into(),
                        build_epoch: 4_102_444_800,
                        install_epoch: 4_102_444_800,
                    })
                } else {
                    None
                }
            }
            fn sync_info(&self, _: &str) -> bool {
                false
            }
            fn dep_satisfied(&self, _: &str) -> bool {
                false
            }
        }
        let si = "pkgbase = test-split\n\tpkgver = 7\n\tpkgrel = 1\npkgname = test-split-core\npkgname = test-split-tools\n";
        assert!(installed_matches(&Mock, si, "test-split", 0));
        // pkgbase name is not an installed split member
        assert!(!installed_matches(&Mock, si, "other-base", 0));
    }

    #[test]
    fn installed_confirmation_matrix_binds_identity_version_epoch_and_freshness() {
        use std::collections::HashMap;

        struct Records(HashMap<String, LocalRecord>);
        impl Pacman for Records {
            fn query(&self, _: &str) -> Option<String> {
                None
            }
            fn local_record(&self, name: &str) -> Option<LocalRecord> {
                self.0.get(name).cloned()
            }
            fn sync_info(&self, _: &str) -> bool {
                false
            }
            fn dep_satisfied(&self, _: &str) -> bool {
                false
            }
        }
        fn record(
            name: &str,
            version: &str,
            base: &str,
            built: u64,
            installed: u64,
        ) -> LocalRecord {
            LocalRecord {
                name: name.into(),
                version: version.into(),
                pkgbase: base.into(),
                build_epoch: built,
                install_epoch: installed,
            }
        }

        let ordinary = "pkgbase = fixture\n\tpkgver = 2\n\tpkgrel = 3\npkgname = fixture\n";
        let fresh = Records(HashMap::from([(
            "fixture".into(),
            record("fixture", "2-3", "fixture", 200, 201),
        )]));
        assert!(installed_matches(&fresh, ordinary, "fixture", 100));
        assert!(!installed_matches(&fresh, ordinary, "other", 100));
        assert!(!installed_matches(&fresh, ordinary, "fixture", 202));

        let old_build = Records(HashMap::from([(
            "fixture".into(),
            record("fixture", "2-3", "fixture", 99, 201),
        )]));
        assert!(!installed_matches(&old_build, ordinary, "fixture", 100));
        let old_install = Records(HashMap::from([(
            "fixture".into(),
            record("fixture", "2-3", "fixture", 201, 99),
        )]));
        assert!(!installed_matches(&old_install, ordinary, "fixture", 100));
        let wrong_version = Records(HashMap::from([(
            "fixture".into(),
            record("fixture", "2-2", "fixture", 200, 201),
        )]));
        assert!(!installed_matches(&wrong_version, ordinary, "fixture", 100));
        assert!(!installed_matches(
            &Records(HashMap::new()),
            ordinary,
            "fixture",
            0
        ));
        assert!(!installed_matches(
            &fresh,
            "pkgbase = fixture\n\tpkgver = 2\n\tpkgrel = 3\n",
            "fixture",
            0
        ));

        let epoch =
            "pkgbase = fixture\n\tepoch = 4\n\tpkgver = 2\n\tpkgrel = 3\npkgname = fixture\n";
        let epoch_match = Records(HashMap::from([(
            "fixture".into(),
            record("fixture", "4:2-3", "fixture", 200, 201),
        )]));
        assert!(installed_matches(&epoch_match, epoch, "fixture", 100));
        assert!(!installed_matches(&fresh, epoch, "fixture", 100));

        let split = "pkgbase = suite\n\tpkgver = 7\n\tpkgrel = 1\npkgname = suite-core\npkgname = suite-docs\npkgname = suite-tools\n";
        let third_member = Records(HashMap::from([(
            "suite-tools".into(),
            record("suite-tools", "7-1", "suite", 200, 201),
        )]));
        assert!(installed_matches(&third_member, split, "suite", 100));
        let fake_base_pkg = Records(HashMap::from([(
            "suite".into(),
            record("suite", "7-1", "suite", 200, 201),
        )]));
        assert!(!installed_matches(&fake_base_pkg, split, "suite", 100));
        let foreign = Records(HashMap::from([(
            "suite-tools".into(),
            record("suite-tools", "7-1", "evil-base", 200, 201),
        )]));
        assert!(!installed_matches(&foreign, split, "suite", 100));
    }

    #[test]
    fn source_domains_multiline_and_userinfo() {
        let pkg =
            "source=(\n\"https://example.com@evil.example/p.tar\"\n\"https://good.org/q.tar\"\n)\n";
        let d = source_domains_from(pkg);
        assert!(d.contains("evil.example")); // userinfo stripped
        assert!(d.contains("good.org"));
        assert!(!d.contains("example.com"));
    }

    #[test]
    fn source_domain_scan_ignores_parentheses_inside_quoted_urls() {
        let pkg = "source=(\n  'https://example.com/release(foo).tar'\n  'https://evil.example/payload.tar'\n)\n";
        let domains = source_domains_from(pkg);
        assert!(domains.contains("example.com"));
        assert!(domains.contains("evil.example"));
    }

    #[test]
    fn maintainer_domain_scan_accepts_indented_comments() {
        let domains = maintainer_domains_from("  # Maintainer: Real <real@evil.example>\n");
        assert!(domains.contains("evil.example"));
    }
}
