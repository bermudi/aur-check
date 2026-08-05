//! Trust-anchor state: accepted/staged refs, the run manifest, flock-based
//! transaction locking, atomic record writes, evidence stashing, and GC.
//!
//! Mirrors the script's state helpers. All writes that establish or advance a
//! trust anchor are atomic (temp file in the destination dir + rename) so a
//! partial write can never masquerade as a confirmed anchor.

/// Render a reviewable diff to `dest`, fail-closed. Rejects an empty/failed
/// diff, NUL-bearing output (a hostile .gitattributes can force binary through
/// a text diff; Bash/LLM can't carry it byte-faithfully), and opaque patch/diff
/// files (`--numstat` reports `-/-` for binary). No suffix pathspecs: extension
/// is attacker-controlled (Finding T).
pub fn review_diff_to_file(dir: &Path, old: &str, new: &str, dest: &Path) -> Result<()> {
    let out = git::safe_git(Some(dir), &["diff", old, new])?;
    if !out.status.success() || out.stdout.is_empty() {
        bail!("diff empty or failed");
    }
    if out.stdout.contains(&0u8) {
        bail!("diff contains NUL");
    }
    let numstat = git::safe_git(
        Some(dir),
        &["diff", "--numstat", old, new, "--", "*.patch", "*.diff"],
    )?;
    if !numstat.status.success() {
        bail!("numstat failed");
    }
    for line in String::from_utf8_lossy(&numstat.stdout).lines() {
        let mut f = line.split_whitespace();
        if let (Some(a), Some(b)) = (f.next(), f.next()) {
            if a == "-" && b == "-" {
                bail!("opaque patch/diff in evidence");
            }
        }
    }
    fs::write(dest, &out.stdout).context("write review diff")?;
    Ok(())
}

/// Persist the offending diff atomically so `view`/`explain` can never show a
/// stale prior diff while the gate stages a newer commit.
pub fn stash_flag(
    paths: &Paths,
    pkg: &str,
    dir: &Path,
    base: &str,
    candidate_ref: &str,
    context: &str,
) -> Result<()> {
    let flagfile = paths.flag_diff(pkg);
    let tmp = paths
        .state_dir
        .join(format!("flag.{pkg}.diff.tmp.{}", std::process::id()));
    let result = (|| -> Result<()> {
        review_diff_to_file(dir, base, candidate_ref, &tmp)?;
        fs::rename(&tmp, &flagfile).context("persist flag diff")?;
        atomic_write_record(&paths.flag_context(pkg), context)?;
        symlink_flag(paths, pkg)?;
        atomic_write_record(&paths.state_dir.join("last-flag.pkg"), pkg)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
        let _ = fs::remove_file(&flagfile);
        let _ = fs::remove_file(paths.flag_context(pkg));
        let _ = fs::remove_file(paths.state_dir.join("last-flag.diff"));
    }
    result
}

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use nix::fcntl::{Flock, FlockArg};
use regex::Regex;

use crate::git;

/// 40-hex (SHA-1) or 64-hex (SHA-256) git object id. The script widened this
/// from {40} to {40}([0-9a-f]{24})? for SHA-256 repos (gh21).
pub fn is_object_id(s: &str) -> bool {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[0-9a-f]{40}([0-9a-f]{24})?$").unwrap())
        .is_match(s)
}

/// AUR package-name grammar, tightened for path use (Finding R + gh22).
/// Uppercase allowed; '.', '..', '.git' and hidden shapes rejected.
pub fn valid_pkg_name(name: &str) -> bool {
    static RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let ok = RE
        .get_or_init(|| Regex::new(r"^[A-Za-z0-9@._+-]+$").unwrap())
        .is_match(name);
    ok && !name.starts_with('.')
}

/// All state locations, derived from AUR_GATE_STATE_DIR.
#[derive(Clone, Debug)]
pub struct Paths {
    pub state_dir: PathBuf,
    pub accepted_dir: PathBuf,
    pub staged_dir: PathBuf,
    pub manifest_file: PathBuf,
}

impl Paths {
    pub fn new(state_dir: PathBuf) -> Self {
        Paths {
            accepted_dir: state_dir.join("accepted"),
            staged_dir: state_dir.join("staged"),
            manifest_file: state_dir.join("last-gate"),
            state_dir,
        }
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        secure_private_dir(&self.state_dir)?;
        secure_private_dir(&self.accepted_dir)?;
        secure_private_dir(&self.staged_dir)?;
        for file in [&self.manifest_file, &self.state_dir.join("run.lock")] {
            reject_unsafe_existing_file(file)?;
        }
        Ok(())
    }

    pub fn accepted_file(&self, pkgbase: &str) -> PathBuf {
        self.accepted_dir.join(pkgbase)
    }
    pub fn staged_file(&self, pkgbase: &str) -> PathBuf {
        self.staged_dir.join(pkgbase)
    }
    pub fn flag_diff(&self, pkg: &str) -> PathBuf {
        self.state_dir.join(format!("flag.{pkg}.diff"))
    }
    pub fn flag_context(&self, pkg: &str) -> PathBuf {
        self.state_dir.join(format!("flag.{pkg}.context"))
    }

    pub fn reset_manifest(&self) -> Result<()> {
        reject_unsafe_existing_file(&self.manifest_file)?;
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&self.manifest_file)
            .context("reset transaction manifest")?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != unsafe { nix::libc::geteuid() } {
            bail!("transaction manifest is not a current-user regular file");
        }
        Ok(())
    }
}

fn secure_private_dir(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!("state path is not a real directory: {}", path.display());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .with_context(|| format!("create state directory {}", path.display()))?;
        }
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    let effective_uid = unsafe { nix::libc::geteuid() };
    if metadata.uid() != effective_uid {
        bail!(
            "state directory is not owned by the current user: {}",
            path.display()
        );
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn reject_unsafe_existing_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != unsafe { nix::libc::geteuid() }
            {
                bail!("unsafe state file: {}", path.display());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// Replace a one-line state record atomically in its destination directory.
/// `mktemp <dest>.tmp.XXXXXX` + `printf '%s\n'` + `mv -f`. Failure must block,
/// never silently lose an audited commit identity.
pub fn atomic_write_record(dest: &Path, record: &str) -> Result<()> {
    let dir = dest.parent().context("record dest has no parent dir")?;
    let stem = dest
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("record");
    let mut tmp = tempfile::Builder::new()
        .prefix(&format!("{stem}.tmp."))
        .tempfile_in(dir)
        .context("mktemp for atomic record")?;
    tmp.write_all(record.as_bytes())?;
    tmp.write_all(b"\n")?;
    tmp.flush()?;
    // rename(2) within the same directory — atomic on POSIX.
    tmp.persist(dest)
        .with_context(|| format!("persist atomic record to {}", dest.display()))?;
    Ok(())
}

// --- UTC timestamp (date -u +%Y-%m-%dT%H:%M:%SZ) ---------------------------

/// Civil date from days-since-epoch (Howard Hinnant's algorithm). Avoids a
/// chrono dependency for a single deterministic format.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn iso_utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

// --- transaction lock (Finding L) ------------------------------------------

/// Serialize gate → helper → accept. The generated wrapper holds this across
/// all three phases and passes the locked fd 9 through exec; direct gate/accept
/// calls acquire it themselves.
pub enum StateLock {
    /// The shell wrapper owns fd 9 and must keep it locked after this process
    /// exits so the helper and `accept` remain in one transaction.
    Inherited,
    /// Direct commands own their lock for the command's full duration.
    Owned(Flock<File>),
}

impl Paths {
    pub fn acquire_lock(&self) -> Result<StateLock> {
        if std::env::var("AUR_GATE_LOCK_HELD").as_deref() == Ok("1") {
            // Do not trust the env claim alone: the wrapper passes the actual
            // locked fd 9 through exec. Verify fd 9 is the real lock file
            // (same device/inode), then take the non-blocking lock. A spoofed
            // variable without the inherited fd must fail closed.
            let fd: RawFd = 9;
            let fd_stat =
                nix::sys::stat::fstat(fd).context("AUR_GATE_LOCK_HELD set but fd 9 is not open")?;
            let lock_path = self.state_dir.join("run.lock");
            let file_stat = nix::sys::stat::stat(&lock_path)
                .context("cannot stat run.lock for inherited-lock check")?;
            if fd_stat.st_dev != file_stat.st_dev || fd_stat.st_ino != file_stat.st_ino {
                bail!("AUR_GATE_LOCK_HELD set without inherited lock fd");
            }
            let rc = unsafe { nix::libc::flock(fd, nix::libc::LOCK_EX | nix::libc::LOCK_NB) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("inherited lock fd 9 is not held exclusively");
            }
            return Ok(StateLock::Inherited);
        }

        let lock_path = self.state_dir.join("run.lock");
        reject_unsafe_existing_file(&lock_path)?;
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&lock_path)
            .context("open run.lock")?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != unsafe { nix::libc::geteuid() } {
            bail!("run.lock is not a current-user regular file");
        }
        let locked = Flock::lock(file, FlockArg::LockExclusive)
            .map_err(|(_, errno)| errno)
            .context("flock run.lock")?;
        Ok(StateLock::Owned(locked))
    }
}

// --- trust anchors ----------------------------------------------------------

/// Resolve an existing accepted (trust-anchor) ref for a pkgbase. First contact
/// has NO implicit HEAD seed: a missing/empty file is an error, and the recorded
/// SHA must still exist as a commit in `dir`.
pub fn accepted_ref(paths: &Paths, dir: &Path, pkgbase: &str) -> Result<String> {
    let f = paths.accepted_file(pkgbase);
    let content =
        fs::read_to_string(&f).with_context(|| format!("no accepted anchor for {pkgbase}"))?;
    if content.trim().is_empty() {
        bail!("accepted anchor for {pkgbase} is empty");
    }
    let sha = content.lines().next().unwrap_or("");
    let sha = sha.split('\t').next().unwrap_or("");
    if !is_object_id(sha) {
        bail!("accepted anchor for {pkgbase} has malformed sha");
    }
    // Commit must still exist in the repo.
    let probe = format!("{sha}^{{commit}}");
    let out = git::safe_git(Some(dir), &["cat-file", "-e", &probe])?;
    if !out.status.success() {
        bail!("accepted anchor {sha} is not a commit in {}", dir.display());
    }
    Ok(sha.to_string())
}

/// Staging for the missing-cache path: write the scan-time tip (captured at
/// clone) instead of querying a cache dir. Preserves the TOCTOU guarantee —
/// the AUDITED commit is what accept promotes, not the helper's later fetch.
pub fn stage_scan_if_gating(
    paths: &Paths,
    staging: bool,
    pkgbase: &str,
    scan_sha: &str,
    scan_url: &str,
) -> Result<()> {
    if !staging {
        return Ok(());
    }
    if !valid_pkg_name(pkgbase) {
        bail!("invalid pkgbase for staging");
    }
    if !is_object_id(scan_sha) {
        bail!("scan tip is not a valid object id");
    }
    validate_record_url(scan_url)?;
    let staged = paths.staged_file(pkgbase);
    atomic_write_record(
        &staged,
        &format!("{scan_sha}\t{}\t{scan_url}", iso_utc_now()),
    )?;
    if let Err(error) = append_manifest(paths, pkgbase) {
        fs::remove_file(&staged).with_context(|| {
            format!(
                "manifest append failed ({error}); also failed to remove staged ref {}",
                staged.display()
            )
        })?;
        return Err(error);
    }
    Ok(())
}

fn validate_record_url(url: &str) -> Result<()> {
    if url.is_empty() || url.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("origin URL cannot be represented safely in a state record");
    }
    Ok(())
}

fn append_manifest(paths: &Paths, pkgbase: &str) -> Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.manifest_file)
        .context("open manifest")?;
    writeln!(f, "{pkgbase}")?;
    Ok(())
}

// --- evidence stashing ------------------------------------------------------

/// Persist complete reviewable evidence (already-rendered diff content) without
/// routing raw git output through a lossy scalar. Used by the missing-cache and
/// audit paths.
pub fn stash_content(paths: &Paths, pkg: &str, context: &str, content: &str) -> Result<()> {
    let flagfile = paths.flag_diff(pkg);
    atomic_write_record(&flagfile, content)
        .and_then(|_| atomic_write_record(&paths.flag_context(pkg), context))
        .and_then(|_| symlink_flag(paths, pkg))
        .and_then(|_| atomic_write_record(&paths.state_dir.join("last-flag.pkg"), pkg))
        .inspect_err(|_| {
            // best-effort rollback of a partial stash
            let _ = fs::remove_file(&flagfile);
            let _ = fs::remove_file(paths.flag_context(pkg));
            let _ = fs::remove_file(paths.state_dir.join("last-flag.diff"));
        })
}

fn symlink_flag(paths: &Paths, pkg: &str) -> Result<()> {
    let link = paths.state_dir.join("last-flag.diff");
    let _ = fs::remove_file(&link);
    std::os::unix::fs::symlink(format!("flag.{pkg}.diff"), &link).context("symlink last-flag.diff")
}

// --- GC ---------------------------------------------------------------------

/// Sweep old flag diffs (>30d) and orphaned staged refs (>7d). accepted/ is
/// intentionally never swept — it is the persistent trust anchor.
pub fn gc_state(paths: &Paths) {
    let now = SystemTime::now();
    sweep(
        &paths.state_dir,
        "flag.",
        ".diff",
        Duration::from_secs(30 * 86_400),
        &now,
    );
    sweep_all(&paths.staged_dir, Duration::from_secs(7 * 86_400), &now);
}

fn sweep(dir: &Path, prefix: &str, suffix: &str, max_age: Duration, now: &SystemTime) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        if !(name.starts_with(prefix) && name.ends_with(suffix)) {
            continue;
        }
        if let Ok(md) = e.metadata() {
            if let Ok(mtime) = md.modified() {
                if now
                    .duration_since(mtime)
                    .map(|a| a > max_age)
                    .unwrap_or(false)
                {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
    }
}

fn sweep_all(dir: &Path, max_age: Duration, now: &SystemTime) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        if let Ok(md) = e.metadata() {
            if !md.is_file() {
                continue;
            }
            if let Ok(mtime) = md.modified() {
                if now
                    .duration_since(mtime)
                    .map(|a| a > max_age)
                    .unwrap_or(false)
                {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_id_widths() {
        assert!(is_object_id(&"a".repeat(40)));
        assert!(is_object_id(&"f".repeat(64)));
        assert!(!is_object_id(&"a".repeat(39)));
        assert!(!is_object_id(&"a".repeat(41)));
        assert!(!is_object_id(&"g".repeat(40)));
    }

    #[test]
    fn pkg_name_grammar() {
        assert!(valid_pkg_name("cursor-bin"));
        assert!(valid_pkg_name("UpperCase-Pkg"));
        assert!(valid_pkg_name("opencl-nvidia-580xx"));
        assert!(!valid_pkg_name(".."));
        assert!(!valid_pkg_name(".git"));
        assert!(!valid_pkg_name(".hidden"));
        assert!(!valid_pkg_name("a/b"));
        assert!(!valid_pkg_name(""));
    }

    #[test]
    fn civil_date_known_values() {
        // 1970-01-01, 2000-01-01, 2026-07-31
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
        assert_eq!(civil_from_days(20_665), (2026, 7, 31));
    }

    #[test]
    fn state_dirs_are_private_and_symlinks_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::new(temp.path().join("state"));
        paths.ensure_dirs().unwrap();
        for dir in [&paths.state_dir, &paths.accepted_dir, &paths.staged_dir] {
            assert_eq!(fs::symlink_metadata(dir).unwrap().mode() & 0o777, 0o700);
        }

        let redirected = temp.path().join("redirected");
        fs::create_dir(&redirected).unwrap();
        let symlinked = Paths::new(temp.path().join("symlinked-state"));
        std::os::unix::fs::symlink(&redirected, &symlinked.state_dir).unwrap();
        assert!(symlinked.ensure_dirs().is_err());

        let paths = Paths::new(temp.path().join("state-with-link"));
        paths.ensure_dirs().unwrap();
        let target = temp.path().join("manifest-target");
        fs::write(&target, "do not truncate").unwrap();
        std::os::unix::fs::symlink(&target, &paths.manifest_file).unwrap();
        assert!(paths.ensure_dirs().is_err());
        assert!(paths.reset_manifest().is_err());
        assert_eq!(fs::read_to_string(target).unwrap(), "do not truncate");
    }

    #[test]
    fn atomic_write_is_complete_and_newline_terminated() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("rec");
        atomic_write_record(&dest, "abc\tdef").unwrap();
        assert_eq!(fs::read_to_string(&dest).unwrap(), "abc\tdef\n");
        // overwrite atomically
        atomic_write_record(&dest, "xyz").unwrap();
        assert_eq!(fs::read_to_string(&dest).unwrap(), "xyz\n");
    }

    fn committed_repo(object_format: Option<&str>) -> Option<(tempfile::TempDir, String)> {
        let temp = tempfile::tempdir().unwrap();
        let mut command = std::process::Command::new("/usr/bin/git");
        command.args(["-c", "init.defaultBranch=master", "init", "-q"]);
        if let Some(format) = object_format {
            command.arg(format!("--object-format={format}"));
        }
        command.arg(temp.path());
        if !command.status().unwrap().success() {
            return None;
        }
        fs::write(temp.path().join("PKGBUILD"), "pkgname=fixture\n").unwrap();
        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(temp.path())
            .args(["add", "PKGBUILD"])
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(temp.path())
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ])
            .status()
            .unwrap()
            .success());
        let output = std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(temp.path())
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        crate::git::reset_local_config(temp.path(), None, None).unwrap();
        Some((
            temp,
            String::from_utf8(output.stdout).unwrap().trim().to_owned(),
        ))
    }

    #[test]
    fn owned_state_lock_is_held_for_guard_lifetime() {
        use std::os::fd::AsRawFd;

        let temp = tempfile::tempdir().unwrap();
        let paths = Paths::new(temp.path().join("state"));
        paths.ensure_dirs().unwrap();
        let guard = paths.acquire_lock().unwrap();
        let contender = OpenOptions::new()
            .write(true)
            .open(paths.state_dir.join("run.lock"))
            .unwrap();
        let blocked = unsafe {
            nix::libc::flock(
                contender.as_raw_fd(),
                nix::libc::LOCK_EX | nix::libc::LOCK_NB,
            )
        };
        assert_ne!(blocked, 0, "a second transaction acquired the live lock");
        drop(guard);
        let acquired = unsafe {
            nix::libc::flock(
                contender.as_raw_fd(),
                nix::libc::LOCK_EX | nix::libc::LOCK_NB,
            )
        };
        assert_eq!(acquired, 0, "lock was not released with its owned guard");
    }

    #[test]
    fn accepted_ref_never_seeds_and_rejects_corruption() {
        let (repo, sha) = committed_repo(None).unwrap();
        let paths = Paths::new(repo.path().join("state"));
        paths.ensure_dirs().unwrap();
        assert!(accepted_ref(&paths, repo.path(), "fixture").is_err());
        assert!(!paths.accepted_file("fixture").exists());

        atomic_write_record(&paths.accepted_file("fixture"), "not-a-sha").unwrap();
        assert!(accepted_ref(&paths, repo.path(), "fixture").is_err());
        atomic_write_record(&paths.accepted_file("fixture"), &sha).unwrap();
        assert_eq!(accepted_ref(&paths, repo.path(), "fixture").unwrap(), sha);
    }

    #[test]
    fn sha256_accepted_ref_and_staging_round_trip() {
        let Some((repo, sha)) = committed_repo(Some("sha256")) else {
            eprintln!("git lacks SHA-256 object format; skipping");
            return;
        };
        assert_eq!(sha.len(), 64);
        let paths = Paths::new(repo.path().join("state"));
        paths.ensure_dirs().unwrap();
        atomic_write_record(&paths.accepted_file("fixture"), &sha).unwrap();
        assert_eq!(accepted_ref(&paths, repo.path(), "fixture").unwrap(), sha);
        stage_scan_if_gating(
            &paths,
            true,
            "fixture",
            &sha,
            "https://aur.archlinux.org/fixture.git",
        )
        .unwrap();
        assert!(fs::read_to_string(paths.staged_file("fixture"))
            .unwrap()
            .starts_with(&sha));
    }

    #[test]
    fn review_evidence_includes_patch_and_disguised_text_and_rejects_nul() {
        let (repo, base) = committed_repo(None).unwrap();
        fs::write(repo.path().join("fix.patch"), "harmless textual patch\n").unwrap();
        fs::write(
            repo.path().join("payload.png"),
            "text hidden by extension\n",
        )
        .unwrap();
        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo.path())
            .args(["add", "fix.patch", "payload.png"])
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo.path())
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                "evidence",
            ])
            .status()
            .unwrap()
            .success());
        let candidate = String::from_utf8(
            std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo.path())
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        let destination = repo.path().join("evidence.diff");
        review_diff_to_file(repo.path(), &base, candidate.trim(), &destination).unwrap();
        let evidence = fs::read_to_string(&destination).unwrap();
        assert!(evidence.contains("fix.patch"));
        assert!(evidence.contains("payload.png"));

        fs::write(repo.path().join("nul.dat"), b"visible\0hidden\n").unwrap();
        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo.path())
            .args(["add", "nul.dat"])
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo.path())
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                "nul",
            ])
            .status()
            .unwrap()
            .success());
        let nul_tip = String::from_utf8(
            std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo.path())
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        assert!(
            review_diff_to_file(repo.path(), candidate.trim(), nul_tip.trim(), &destination)
                .is_err()
        );
    }

    #[test]
    fn scan_staging_binds_sha_url_and_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths::new(dir.path().join("state"));
        paths.ensure_dirs().unwrap();
        let sha = "a".repeat(40);
        stage_scan_if_gating(
            &paths,
            true,
            "fixture",
            &sha,
            "https://aur.archlinux.org/fixture.git",
        )
        .unwrap();
        let staged = fs::read_to_string(paths.staged_file("fixture")).unwrap();
        assert!(staged.starts_with(&format!("{sha}\t")));
        assert!(staged.ends_with("\thttps://aur.archlinux.org/fixture.git\n"));
        assert_eq!(
            fs::read_to_string(&paths.manifest_file).unwrap(),
            "fixture\n"
        );

        assert!(stage_scan_if_gating(&paths, true, "../escape", &sha, "https://x/y").is_err());
        assert!(stage_scan_if_gating(&paths, true, "fixture", "bad", "https://x/y").is_err());
        assert!(stage_scan_if_gating(&paths, true, "fixture", &sha, "ext::evil\ncommand").is_err());

        let rollback = Paths::new(dir.path().join("rollback"));
        rollback.ensure_dirs().unwrap();
        fs::create_dir(&rollback.manifest_file).unwrap();
        assert!(stage_scan_if_gating(
            &rollback,
            true,
            "fixture",
            &sha,
            "https://aur.archlinux.org/fixture.git",
        )
        .is_err());
        assert!(!rollback.staged_file("fixture").exists());
    }
}
