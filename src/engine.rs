//! The gate engine: cache discovery, fresh-clone audit, whole-file scan, and
//! the two per-package pipelines (cached `check_pkg`, missing-cache two-tier).
//! The script's SCAN_* globals are explicit structs threaded by value.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use crate::classifier::{self, Ctx};
use crate::git;
use crate::rpc::{self, RpcClient};
use crate::rules::CompiledRule;
use crate::srcinfo::{self, Pacman};
use crate::state::{self, is_object_id, valid_pkg_name, Paths};

/// Result of a fresh AUR clone. The caller owns cleanup of `temp_root`.
/// `sha` is the gate-time origin/<branch> tip (the TOCTOU invariant: this is
/// what staging records, not whatever the helper fetches later).
#[derive(Clone, Debug)]
pub struct CloneResult {
    pub dir: PathBuf,       // temp_root/<pkgbase>
    pub temp_root: PathBuf, // caller owns `rm -rf`
    pub sha: String,
    pub url: String,
    pub pkgbase: String,
}

/// Whole-file absolute scan result.
#[derive(Clone, Debug, Default)]
pub struct WholeScan {
    pub hard_hits: bool,
    pub review_hits: bool,
    pub content: String, // whole candidate rendered as an empty-tree diff
}

/// Top-level application state for one gate run.
pub struct App<'a> {
    pub paths: Paths,
    pub pacman: &'a dyn Pacman,
    pub reporter: &'a mut dyn classifier::Reporter,
    pub llm: &'a mut dyn classifier::Llm,
    pub rpc: &'a dyn RpcClient,
    pub branch: String,
    pub aur_url: String,
    pub yay_cache: PathBuf,
    pub paru_cache: PathBuf,
    pub makepkg_path: PathBuf,
    pub staging: bool,
    pub llm_auto_boring: bool,
    pub explain_maxlines: usize,
    pub explain_model: String,
    pub hard: Vec<CompiledRule>,
    pub review: Vec<CompiledRule>,
}

impl<'a> App<'a> {
    /// Borrow self's seams into a classifier `Ctx` for the closure's duration.
    fn with_ctx<R>(&mut self, candidate_ref: &str, f: impl FnOnce(&mut Ctx<'_>) -> R) -> R {
        let mut ctx = Ctx {
            paths: &self.paths,
            pacman: self.pacman,
            reporter: &mut *self.reporter,
            llm: &mut *self.llm,
            candidate_ref: candidate_ref.to_owned(),
            llm_auto_boring: self.llm_auto_boring,
            explain_maxlines: self.explain_maxlines,
            hard: self.hard.clone(),
            review: self.review.clone(),
        };
        f(&mut ctx)
    }

    fn caches(&self) -> [&Path; 2] {
        [&self.yay_cache, &self.paru_cache]
    }

    // --- cache discovery (Finding N) ---------------------------------------

    /// Find a package's git clone in any configured cache. Split packages are
    /// resolved via AUR RPC, then ONLY the exact pkgbase directory is inspected
    /// — never discover the pkgname→pkgbase mapping by scanning attacker-authored
    /// cached .SRCINFO (another package could claim the pkgname and redirect).
    pub fn find_pkg_dir(&self, pkg: &str) -> Option<PathBuf> {
        // Fast path: exact dir-name match (pkgname == pkgbase).
        for base in self.caches() {
            let dir = base.join(pkg);
            if dir.join(".git").is_dir() {
                return Some(dir);
            }
        }
        // Split resolution through RPC.
        let pkgbase = rpc::resolve_pkgbase(self.rpc, pkg).ok()?;
        if pkgbase == pkg {
            return None;
        }
        for base in self.caches() {
            let dir = base.join(&pkgbase);
            if !(dir.join(".git").is_dir() && dir.join(".SRCINFO").is_file()) {
                continue;
            }
            let Ok(content) = fs::read_to_string(dir.join(".SRCINFO")) else {
                continue;
            };
            if srcinfo::srcinfo_declares(&content, pkg, &pkgbase) {
                return Some(dir);
            }
        }
        None
    }

    // --- fresh clone (TOCTOU invariant) ------------------------------------

    /// Clone <pkg> from AUR into a temp dir WITHOUT cleaning up (caller owns
    /// `rm -rf result.temp_root`). Resolves pkgbase first (split members 404
    /// otherwise), validates a PKGBUILD exists, and captures the gate-time tip.
    pub fn clone_aur(&mut self, pkg: &str) -> Result<CloneResult> {
        let pkgbase = rpc::resolve_pkgbase(self.rpc, pkg).unwrap_or_else(|_| pkg.to_string());
        if !valid_pkg_name(&pkgbase) {
            bail!("unsafe pkgbase {pkgbase:?}");
        }
        let temp_root = tempfile::tempdir()?.keep(); // caller owns cleanup
        let dir = temp_root.join(&pkgbase);
        self.reporter.dim(&format!(
            "→ cloning {pkgbase} from AUR to {}",
            dir.display()
        ));

        let url = format!("{}/{pkgbase}.git", self.aur_url);
        let dir_arg = dir
            .to_str()
            .context("temporary clone path is not valid UTF-8")?;
        let clone = git::safe_git(None, &["clone", "-q", "--", &url, dir_arg])?;
        if !clone.status.success() {
            bail!("clone failed for {pkgbase}");
        }
        // Do not inspect the clone's config: replace it with the exact values
        // this gate requested before the first repo-bound Git call.
        git::reset_local_config(&dir, Some(&url), Some(&self.branch))
            .with_context(|| format!("reset generated Git config for {pkgbase}"))?;
        let rev = format!("origin/{}", self.branch);
        let out = git::safe_git_with_origin(
            Some(&dir),
            &["rev-parse", "--verify", &rev],
            &url,
            &self.branch,
        )?;
        if !out.status.success() {
            bail!("cannot resolve {rev}");
        }
        let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !is_object_id(&sha) {
            bail!("origin tip is not a valid object id");
        }
        // No later clone operation needs the remote section. Removing it keeps
        // every ordinary safe_git caller on the static no-remote contract.
        git::reset_local_config(&dir, None, None)
            .with_context(|| format!("remove transient remote config for {pkgbase}"))?;
        let pkgbuild = git::safe_git(Some(&dir), &["ls-tree", &sha, "--", "PKGBUILD"])?;
        let pkgbuild_record = std::str::from_utf8(&pkgbuild.stdout)?.trim();
        if !pkgbuild.status.success()
            || !(pkgbuild_record.starts_with("100644 blob ")
                || pkgbuild_record.starts_with("100755 blob "))
            || !pkgbuild_record.ends_with("\tPKGBUILD")
        {
            bail!("no regular PKGBUILD blob in {pkgbase}");
        }
        Ok(CloneResult {
            dir,
            temp_root,
            sha,
            url,
            pkgbase,
        })
    }

    // --- whole-file absolute scan ------------------------------------------

    /// Absolute scan of a cloned dir against both rule sets. Deterministic
    /// regexes scan only executable surfaces (PKGBUILD + *.install + *.sh);
    /// the evidence (`content`) is the wider whole-candidate empty-tree diff.
    pub fn scan_whole_pkg(&mut self, dir: &Path, candidate: &str) -> Result<WholeScan> {
        if !is_object_id(candidate) {
            bail!("candidate is not a valid object id");
        }
        // Read committed blobs, never working-tree paths: a tracked symlink can
        // otherwise make the audit inspect one local file while makepkg later
        // sources another. AUR package surfaces must be regular blobs at the
        // repository root.
        let tree = git::safe_git(Some(dir), &["ls-tree", "-r", "-z", candidate])?;
        if !tree.status.success() {
            bail!("cannot enumerate candidate tree");
        }
        let mut surfaces = Vec::new();
        let mut additional_files = Vec::new();
        for record in tree
            .stdout
            .split(|byte| *byte == 0)
            .filter(|record| !record.is_empty())
        {
            let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
                bail!("malformed ls-tree record");
            };
            let metadata = std::str::from_utf8(&record[..tab])?;
            let path = std::str::from_utf8(&record[tab + 1..])?;
            let mut fields = metadata.split_whitespace();
            let mode = fields.next().unwrap_or("");
            let kind = fields.next().unwrap_or("");
            let object = fields.next().unwrap_or("");
            if !matches!(mode, "100644" | "100755")
                || kind != "blob"
                || !is_object_id(object)
                || fields.next().is_some()
            {
                bail!("candidate tree entry {path:?} is not a regular blob");
            }
            if !path.contains('/')
                && (path == "PKGBUILD" || path.ends_with(".install") || path.ends_with(".sh"))
            {
                surfaces.push(path.to_owned());
            } else if path != ".SRCINFO" {
                additional_files.push(path.to_owned());
            }
        }
        if !surfaces.iter().any(|path| path == "PKGBUILD") {
            bail!("candidate has no regular PKGBUILD blob");
        }

        let mut content = String::new();
        for path in &surfaces {
            let spec = format!("{candidate}:{path}");
            let blob = git::safe_git(Some(dir), &["show", &spec])?;
            if !blob.status.success() || blob.stdout.contains(&0) {
                bail!("candidate surface {path:?} is unreadable or contains NUL");
            }
            let surface = std::str::from_utf8(&blob.stdout)?;
            content.push_str(surface);
            content.push('\n');
        }
        if content.trim().is_empty() {
            bail!("empty package surfaces");
        }

        let mut scan = WholeScan::default();
        for rule in &self.hard {
            let hits = classifier::rule_hit_lines_pub(&rule.re, &content);
            if !hits.is_empty() {
                self.reporter.block_hits(rule.name, &hits, 4);
                scan.hard_hits = true;
            }
        }
        for rule in &self.review {
            let hits = classifier::rule_hit_lines_pub(&rule.re, &content);
            if !hits.is_empty() {
                self.reporter.review_hits(rule.name, &hits, 4);
                scan.review_hits = true;
            }
        }
        // Whole-candidate audit cannot prove how arbitrary package files are
        // consumed without executing PKGBUILD. Keep patch/data files out of
        // regex scanning (nested syntax false-positives), but never let a new
        // package containing them install without human review.
        if !additional_files.is_empty() {
            self.reporter
                .review_hits("additional-package-file", &additional_files, 8);
            scan.review_hits = true;
        }
        if !scan.hard_hits && !scan.review_hits {
            self.reporter.dim("clean: no hard/review-rule matches");
        }

        // Evidence: whole candidate as an empty-tree diff (Finding T: no suffix
        // exclusions; review_diff_to_file rejects NUL/opaque output).
        let empty = empty_tree_sha(dir)?;
        let evidence = tempfile::NamedTempFile::new()?;
        state::review_diff_to_file(dir, &empty, candidate, evidence.path())?;
        scan.content = fs::read_to_string(evidence.path())?;
        Ok(scan)
    }

    /// Clone + whole-file scan. Returns both results; caller cleans temp_root.
    pub fn scan_clone(&mut self, pkg: &str) -> Result<(CloneResult, WholeScan)> {
        let clone = self.clone_aur(pkg)?;
        let candidate = clone.sha.clone();
        let scan = self.scan_whole_pkg(&clone.dir, &candidate)?;
        Ok((clone, scan))
    }

    // --- cached per-package pipeline ---------------------------------------

    /// Gate one (possibly cached) package. Returns 0 clean | 1 hard/audit-
    /// unavailable | 2 review.
    pub fn check_pkg(&mut self, pkg: &str) -> i32 {
        if !valid_pkg_name(pkg) {
            self.reporter
                .review_msg(&format!("{pkg} — invalid package name from helper/input"));
            return 1;
        }
        let Some(dir) = self.find_pkg_dir(pkg) else {
            return self.missing_cache_gate(pkg);
        };
        let pkgbase = dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_string();

        // First contact: no implicit HEAD seed — route through fresh-clone audit.
        let accepted = self.paths.accepted_file(&pkgbase);
        if !accepted.is_file()
            || fs::read_to_string(&accepted)
                .map(|s| s.trim().is_empty())
                .unwrap_or(true)
        {
            self.reporter.review_msg(&format!(
                "{pkg} — no accepted anchor; first-contact audit required"
            ));
            return self.missing_cache_gate(pkg);
        }

        // The cache's config is attacker-writable state, not provenance. The
        // canonical URL comes from validated application config and the
        // refspec is generated from the validated branch; replace the whole
        // local config before Git parses it, then fetch that explicit URL and
        // refspec.
        let expected_url = format!("{}/{pkgbase}.git", self.aur_url);
        if let Err(error) = git::reset_local_config(&dir, Some(&expected_url), Some(&self.branch)) {
            self.reporter.review_msg(&format!(
                "{pkg} — cannot reset cached Git config; refusing fetch: {error}"
            ));
            return 1;
        }
        let fetch_ref = format!(
            "+refs/heads/{}:refs/remotes/origin/{}",
            self.branch, self.branch
        );
        let fetch = git::safe_git_with_origin(
            Some(&dir),
            &[
                "fetch",
                "-q",
                "--no-tags",
                "--no-recurse-submodules",
                &expected_url,
                &fetch_ref,
            ],
            &expected_url,
            &self.branch,
        );
        if fetch.map(|o| !o.status.success()).unwrap_or(true) {
            self.reporter.review_msg(&format!(
                "{pkg} — fetch failed; refusing to audit a stale candidate"
            ));
            return 1;
        }
        if let Err(error) = git::reset_local_config(&dir, None, None) {
            self.reporter.review_msg(&format!(
                "{pkg} — cannot remove transient remote config; refusing audit: {error}"
            ));
            return 1;
        }
        // Every reset purges stale replacement refs and grafts before this
        // helper-facing handoff; safe_git and the helper environment retain
        // their independent replacement/graft isolation for artifacts created
        // after the reset.
        let rev = format!("origin/{}", self.branch);
        let candidate_sha = match git::safe_git(
            Some(&dir),
            &["rev-parse", "--verify", &format!("{rev}^{{commit}}")],
        ) {
            Ok(output) if output.status.success() => {
                String::from_utf8_lossy(&output.stdout).trim().to_owned()
            }
            _ => {
                self.reporter
                    .review_msg(&format!("{pkg} — no {rev}; candidate unavailable"));
                return 1;
            }
        };
        if !is_object_id(&candidate_sha) {
            self.reporter
                .review_msg(&format!("{pkg} — candidate object id is malformed"));
            return 1;
        }
        let Ok(base_ref) = state::accepted_ref(&self.paths, &dir, &pkgbase) else {
            self.reporter
                .review_msg(&format!("{pkg} — accepted ref is invalid or unavailable"));
            return 1;
        };

        // Shared diff pipeline. Empty diffs are classified as boring but still
        // run through the normal staging path so the makepkg guard has a record
        // to bind against; this also runs candidate-surface validation, which
        // the previous early-return path used to skip.
        let rc = self.with_ctx(&candidate_sha, |ctx| {
            classifier::scan_diff_rules(ctx, pkg, &dir, &base_ref)
        });
        match rc {
            2 => {
                if let Err(error) =
                    git::reset_local_config(&dir, Some(&expected_url), Some(&self.branch))
                {
                    self.reporter.review_msg(&format!(
                        "{pkg} — cannot restore cached Git remote; refusing helper: {error}"
                    ));
                    return 1;
                }
                if self.paths.flag_diff(pkg).is_file()
                    && state::stage_scan_if_gating(
                        &self.paths,
                        self.staging,
                        &pkgbase,
                        &candidate_sha,
                        &expected_url,
                    )
                    .is_err()
                {
                    self.reporter
                        .review_msg(&format!("{pkg} — could not persist staged audit state"));
                    return 1;
                }
                2
            }
            0 => {
                if let Err(error) =
                    git::reset_local_config(&dir, Some(&expected_url), Some(&self.branch))
                {
                    self.reporter.review_msg(&format!(
                        "{pkg} — cannot restore cached Git remote; refusing helper: {error}"
                    ));
                    return 1;
                }
                if state::stage_scan_if_gating(
                    &self.paths,
                    self.staging,
                    &pkgbase,
                    &candidate_sha,
                    &expected_url,
                )
                .is_err()
                {
                    self.reporter
                        .review_msg(&format!("{pkg} — could not persist staged audit state"));
                    return 1;
                }
                self.reporter.dim(&format!("ok    {pkg}"));
                0
            }
            _ => 1,
        }
    }

    // --- missing-cache two-tier pipeline -----------------------------------

    /// Gate an update with NO cache clone. Tier 1: baseline recovery (diff
    /// installed-commit..origin/master at full precision). Tier 2: whole-file
    /// fallback (always review). Retained AUR history is attacker-controlled, so
    /// even a clean reconstructed baseline shows the whole candidate before
    /// consent and never earns silent trust (Finding G).
    pub fn missing_cache_gate(&mut self, pkg: &str) -> i32 {
        let clone = match self.clone_aur(pkg) {
            Ok(c) => c,
            Err(error) => {
                self.reporter.review_msg(&format!(
                    "{pkg} — could not clone; no candidate was audited: {error:#}"
                ));
                return 1;
            }
        };
        let pkgbase = clone.pkgbase.clone();
        let dir = clone.dir.clone();
        let scan_sha = clone.sha.clone();
        let scan_url = clone.url.clone();
        let temp_root = clone.temp_root.clone();

        // Tier 1: baseline recovery. Query by PKGNAME (what's installed).
        let want = self
            .pacman
            .query(pkg)
            .and_then(|line| line.split_whitespace().nth(1).map(str::to_string))
            .filter(|v| !v.is_empty());

        if let Some(want) = want {
            let baseline = match srcinfo::find_baseline_commit(&dir, &want, &self.branch) {
                Ok(baseline) => baseline,
                Err(error) => {
                    self.reporter.dim(&format!(
                        "(baseline recovery unavailable: {error:#} — whole-file fallback)"
                    ));
                    None
                }
            };
            if let Some(baseline) = baseline {
                let rc = self.with_ctx(&scan_sha, |ctx| {
                    classifier::scan_diff_rules(ctx, pkg, &dir, &baseline)
                });
                if rc == 1 {
                    let _ = fs::remove_dir_all(&temp_root);
                    return 1; // hard-fail: do NOT stage
                }
                // rc 0 or 2: retained history is attacker-controlled → replace the
                // delta stash with whole-candidate evidence before consent.
                let review_result = (|| -> Result<WholeScan> {
                    let scan = self.scan_whole_pkg(&dir, &scan_sha)?;
                    state::stash_content(
                        &self.paths,
                        pkg,
                        "baseline-recovery-whole-review",
                        &scan.content,
                    )?;
                    Ok(scan)
                })();
                if let Err(error) = fs::remove_dir_all(&temp_root) {
                    self.reporter.dim(&format!(
                        "(could not remove temporary clone {}: {error})",
                        temp_root.display()
                    ));
                }
                let scan = match review_result {
                    Ok(scan) => scan,
                    Err(error) => {
                        self.reporter.review_msg(&format!(
                            "{pkg} — could not persist whole-candidate review: {error:#}"
                        ));
                        return 1;
                    }
                };
                if scan.hard_hits {
                    self.reporter.review_msg(&format!(
                        "{pkg} — hard rule hit(s) in whole candidate; refusing candidate"
                    ));
                    return 1;
                }
                if state::stage_scan_if_gating(
                    &self.paths,
                    self.staging,
                    &pkgbase,
                    &scan_sha,
                    &scan_url,
                )
                .is_err()
                {
                    self.reporter
                        .review_msg(&format!("{pkg} — could not persist staged audit state"));
                    return 1;
                }
                self.reporter.review_msg(&format!(
                    "{pkg} — reconstructed history baseline; whole candidate review required"
                ));
                return 2;
            }
            self.reporter
                .dim("(installed version not found in AUR history — whole-file fallback)");
        } else {
            self.reporter
                .dim("(no cache clone — could not query installed version; whole-file fallback)");
        }

        // Tier 2: whole-file absolute scan; baseline absence itself requires review.
        let scan = match self.scan_whole_pkg(&dir, &scan_sha) {
            Ok(s) => s,
            Err(error) => {
                if let Err(cleanup_error) = fs::remove_dir_all(&temp_root) {
                    self.reporter.dim(&format!(
                        "(could not remove temporary clone {}: {cleanup_error})",
                        temp_root.display()
                    ));
                }
                self.reporter.review_msg(&format!(
                    "{pkg} — candidate has no auditable package surfaces: {error:#}"
                ));
                return 1;
            }
        };
        let _ = fs::remove_dir_all(&temp_root);
        if state::stash_content(&self.paths, pkg, "whole-file-review", &scan.content).is_err() {
            self.reporter
                .review_msg(&format!("{pkg} — could not persist the review scan"));
            return 1;
        }
        if scan.hard_hits {
            self.reporter.review_msg(&format!(
                "{pkg} — hard rule hit(s) in uncached PKGBUILD; refusing candidate"
            ));
            return 1;
        }
        if scan.review_hits {
            self.reporter.review_msg(&format!(
                "{pkg} — rule hit(s) in uncached PKGBUILD; consent required"
            ));
        } else {
            self.reporter.review_msg(&format!(
                "{pkg} — no history baseline; whole candidate review required"
            ));
        }
        self.reporter.dim(&format!(
            "scan stashed: {}/flag.{pkg}.diff  (run: aur-gate explain {pkg})",
            self.paths.state_dir.display()
        ));
        if state::stage_scan_if_gating(&self.paths, self.staging, &pkgbase, &scan_sha, &scan_url)
            .is_err()
        {
            self.reporter
                .review_msg(&format!("{pkg} — could not persist staged audit state"));
            return 1;
        }
        2
    }
}

/// `git mktree </dev/null` — the empty-tree SHA (object-format aware).
fn empty_tree_sha(dir: &Path) -> Result<String> {
    let out = git::safe_git(Some(dir), &["mktree"])?;
    if !out.status.success() {
        bail!("mktree failed");
    }
    let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if !is_object_id(&sha) {
        bail!("mktree returned an invalid object id");
    }
    Ok(sha)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::{CollectingReporter, NoLlm};
    use crate::rpc::RpcClient;
    use crate::srcinfo::{LocalRecord, Pacman};

    struct NoPacman;
    impl Pacman for NoPacman {
        fn query(&self, _: &str) -> Option<String> {
            None
        }
        fn local_record(&self, _: &str) -> Option<LocalRecord> {
            None
        }
        fn sync_info(&self, _: &str) -> bool {
            false
        }
        fn dep_satisfied(&self, _: &str) -> bool {
            false
        }
    }

    struct FixedRpc(String);
    impl RpcClient for FixedRpc {
        fn info(&self, _: &str) -> Result<String> {
            Ok(self.0.clone())
        }
    }

    fn candidate_repo(files: &[(&str, &[u8])]) -> (tempfile::TempDir, String) {
        let temp = tempfile::tempdir().unwrap();
        assert!(std::process::Command::new("/usr/bin/git")
            .args(["-c", "init.defaultBranch=master", "init", "-q"])
            .arg(temp.path())
            .status()
            .unwrap()
            .success());
        for (path, content) in files {
            let destination = temp.path().join(path);
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(destination, content).unwrap();
        }
        let git = |args: &[&str]| {
            let output = std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(temp.path())
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
        git(&["add", "-A"]);
        git(&[
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "candidate",
        ]);
        let sha = git(&["rev-parse", "HEAD"]);
        crate::git::reset_local_config(temp.path(), None, None).unwrap();
        (temp, sha)
    }

    #[test]
    fn whole_candidate_scan_covers_rules_extra_files_and_invalid_surfaces() {
        let state = tempfile::tempdir().unwrap();
        let pacman = NoPacman;
        let rpc = FixedRpc("{}".into());
        let mut reporter = CollectingReporter::default();
        let mut llm = NoLlm;
        let mut app = App {
            paths: Paths::new(state.path().join("state")),
            pacman: &pacman,
            reporter: &mut reporter,
            llm: &mut llm,
            rpc: &rpc,
            branch: "master".into(),
            aur_url: "https://aur.archlinux.org".into(),
            yay_cache: state.path().join("yay"),
            paru_cache: state.path().join("paru"),
            makepkg_path: PathBuf::from("/usr/bin/makepkg"),
            staging: false,
            llm_auto_boring: false,
            explain_maxlines: 1000,
            explain_model: "none".into(),
            hard: crate::rules::hard_rules(),
            review: crate::rules::review_rules(),
        };

        let (clean, clean_sha) = candidate_repo(&[
            ("PKGBUILD", b"pkgname=x\npkgver=1\npkgrel=1\n"),
            (
                ".SRCINFO",
                b"pkgbase = x\n\tpkgver = 1\n\tpkgrel = 1\npkgname = x\n",
            ),
        ]);
        let scan = app.scan_whole_pkg(clean.path(), &clean_sha).unwrap();
        assert!(!scan.hard_hits && !scan.review_hits);
        assert!(scan.content.contains("PKGBUILD"));

        let (extra, extra_sha) = candidate_repo(&[
            ("PKGBUILD", b"pkgname=x\npkgver=1\npkgrel=1\n"),
            (
                ".SRCINFO",
                b"pkgbase = x\n\tpkgver = 1\n\tpkgrel = 1\npkgname = x\n",
            ),
            ("patches/fix.patch", b"ordinary patch\n"),
        ]);
        let scan = app.scan_whole_pkg(extra.path(), &extra_sha).unwrap();
        assert!(scan.review_hits);
        assert!(scan.content.contains("patches/fix.patch"));

        let (empty, empty_sha) = candidate_repo(&[
            ("PKGBUILD", b""),
            (".SRCINFO", b"pkgbase = x\npkgname = x\n"),
        ]);
        assert!(app.scan_whole_pkg(empty.path(), &empty_sha).is_err());

        let (hard, hard_sha) = candidate_repo(&[
            (
                "PKGBUILD",
                b"pkgname=x\npkgver=1\npkgrel=1\ninstall=$_hook\n",
            ),
            (
                ".SRCINFO",
                b"pkgbase = x\n\tpkgver = 1\n\tpkgrel = 1\npkgname = x\n",
            ),
        ]);
        let hard_scan = app.scan_whole_pkg(hard.path(), &hard_sha).unwrap();
        assert!(hard_scan.hard_hits);
        drop(app);
        assert!(reporter
            .blocks
            .iter()
            .any(|(tag, _)| tag == "install-hook-ref"));
        assert!(!reporter
            .reviews
            .iter()
            .any(|(tag, _)| tag == "install-hook-ref"));
    }

    #[test]
    fn split_cache_resolution_trusts_rpc_not_attacker_srcinfo() {
        let temp = tempfile::tempdir().unwrap();
        let yay = temp.path().join("yay");
        let paru = temp.path().join("paru");
        fs::create_dir_all(&yay).unwrap();
        fs::create_dir_all(&paru).unwrap();
        let evil = yay.join("evil-base");
        fs::create_dir_all(evil.join(".git")).unwrap();
        fs::write(
            evil.join(".SRCINFO"),
            "pkgbase = evil-base\npkgname = target-member\n",
        )
        .unwrap();
        let rpc = FixedRpc(
            r#"{"resultcount":1,"results":[{"Name":"target-member","PackageBase":"true-base"}]}"#
                .into(),
        );
        let pacman = NoPacman;
        let mut reporter = CollectingReporter::default();
        let mut llm = NoLlm;
        let app = App {
            paths: Paths::new(temp.path().join("state")),
            pacman: &pacman,
            reporter: &mut reporter,
            llm: &mut llm,
            rpc: &rpc,
            branch: "master".into(),
            aur_url: "https://aur.archlinux.org".into(),
            yay_cache: yay.clone(),
            paru_cache: paru,
            makepkg_path: PathBuf::from("/usr/bin/makepkg"),
            staging: false,
            llm_auto_boring: false,
            explain_maxlines: 1000,
            explain_model: "none".into(),
            hard: crate::rules::hard_rules(),
            review: crate::rules::review_rules(),
        };
        assert!(app.find_pkg_dir("target-member").is_none());

        let true_base = yay.join("true-base");
        fs::create_dir_all(true_base.join(".git")).unwrap();
        fs::write(
            true_base.join(".SRCINFO"),
            "pkgbase = true-base\npkgname = target-member\n",
        )
        .unwrap();
        assert_eq!(app.find_pkg_dir("target-member"), Some(true_base));
    }
}
