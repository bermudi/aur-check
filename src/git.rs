//! Hardened git wrapper (Finding J + H1 / issue #5, #27).
//!
//! Every git call goes through `safe_git`. It strips caller-injected env,
//! forces diff/show options that defeat diff.external / textconv / word-diff /
//! color / noprefix games, disables `git` replacement and grafted history,
//! and keeps repo-local configuration to a fixed, generated shape. The
//! generated config is validated once and copied into a private command-scoped
//! Git metadata view; the mutable repository config is not read by the
//! operation itself.

use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::ops::{Deref, DerefMut};
use std::os::unix::fs as unix_fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};

/// Global `-c` overrides. Order matters: appended AFTER any caller options so
/// the last value wins. Mirrors `safe_pre` in the script.
const SAFE_PRE: &[&str] = &[
    "-c",
    "core.pager=cat",
    "-c",
    "pager.diff=cat",
    "-c",
    "pager.show=cat",
    "-c",
    "core.quotepath=false",
    "-c",
    "core.attributesFile=",
    "-c",
    "core.excludesFile=",
    "-c",
    "core.hooksPath=",
    "-c",
    "color.ui=false",
    "-c",
    "color.diff=false",
    "-c",
    "diff.wordDiff=none",
    "-c",
    "diff.colorWords=false",
    "-c",
    "diff.mnemonicPrefix=false",
    "-c",
    "diff.noprefix=false",
    "-c",
    "diff.colorMoved=false",
    "-c",
    "http.sslVerify=true",
    // No repository may select an executable transport. AUR traffic is HTTP(S)
    // only; command-line config has higher priority than local config.
    "-c",
    "protocol.allow=never",
    "-c",
    "protocol.http.allow=always",
    "-c",
    "protocol.https.allow=always",
    "-c",
    "protocol.ext.allow=never",
    // Issue #38: commit graphs can replace the tree/parent view for a validly
    // checksummed commit; force Git to resolve through the commit object.
    "-c",
    "core.commitGraph=false",
];

/// Subcommand guards for diff/show (the commands that render diffs).
fn safe_mid(subcommand: &str) -> &'static [&'static str] {
    match subcommand {
        "diff" | "show" => &[
            "--no-ext-diff",
            "--no-textconv",
            "--word-diff=none",
            "--text",
        ],
        _ => &[],
    }
}

/// Run git with safe global options. `repo` is the optional `-C` dir.
/// `args` must begin with the subcommand (e.g. &["diff", "--name-only", ...]).
/// The default contract is a generated config without a remote section. Callers
/// that intentionally retain the generated origin for one operation must use
/// `safe_git_with_origin`, which compares that section to the trusted inputs.
pub fn safe_git(repo: Option<&Path>, args: &[&str]) -> Result<Output> {
    Ok(safe_git_command(repo, args)?.output()?)
}

/// Compute git blob hashes for a set of files using `git hash-object
/// --stdin-paths`. Unlike `safe_git`, this does not require a repository — it
/// is a pure hashing operation. The hardened environment (SAFE_PRE, env
/// isolation, no-replace-objects) is still applied so a poisoned global config
/// or environment cannot redirect the hash. Paths are interpreted relative to
/// `cwd`. Returns one SHA-1 hex string per input path, in order.
pub(crate) fn hash_objects(cwd: &Path, paths: &[String]) -> Result<Vec<String>> {
    let mut cmd = Command::new("/usr/bin/git");
    cmd.arg("--no-pager")
        .arg("--no-replace-objects")
        .args(SAFE_PRE);
    isolate_git_env(&mut cmd);
    cmd.arg("hash-object")
        .arg("--stdin-paths")
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().context("spawn git hash-object")?;
    {
        let stdin = child.stdin.take().context("hash-object stdin")?;
        let mut writer = std::io::BufWriter::new(stdin);
        for path in paths {
            writeln!(writer, "{path}")?;
        }
    }
    let out = child.wait_with_output().context("git hash-object")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!("git hash-object failed: {err}");
    }
    let hashes: Vec<String> = std::str::from_utf8(&out.stdout)
        .context("hash-object output is not UTF-8")?
        .lines()
        .map(String::from)
        .collect();
    if hashes.len() != paths.len() {
        bail!(
            "git hash-object returned {} hashes for {} paths",
            hashes.len(),
            paths.len()
        );
    }
    Ok(hashes)
}

/// Run one hardened Git command while checking the generated remote section
/// against the trusted origin and branch used to create it.
pub(crate) fn safe_git_with_origin(
    repo: Option<&Path>,
    args: &[&str],
    origin_url: &str,
    branch: &str,
) -> Result<Output> {
    Ok(safe_git_command_with_origin(repo, args, origin_url, branch)?.output()?)
}

/// Build a hardened git command for callers that need streaming stdin/stdout
/// (notably `cat-file --batch`). The returned wrapper owns a private Git
/// metadata view until the command has finished. Keep the wrapper alive while
/// a spawned child is running.
pub(crate) fn safe_git_command(repo: Option<&Path>, args: &[&str]) -> Result<SafeGitCommand> {
    safe_git_command_with_expected_origin(repo, args, None)
}

/// Streaming counterpart to [`safe_git_with_origin`].
pub(crate) fn safe_git_command_with_origin(
    repo: Option<&Path>,
    args: &[&str],
    origin_url: &str,
    branch: &str,
) -> Result<SafeGitCommand> {
    safe_git_command_with_expected_origin(repo, args, Some((origin_url, branch)))
}

/// An owned command plus the temporary Git directory that supplies its trusted
/// configuration. `Deref` keeps the ordinary `Command` builder API available
/// to the one streaming caller without allowing the view to be dropped early.
pub(crate) struct SafeGitCommand {
    command: Command,
    trusted_view: Option<TrustedGitView>,
}

impl SafeGitCommand {
    fn output(&mut self) -> std::io::Result<Output> {
        self.command.output()
    }

    pub(crate) fn stdin(&mut self, configuration: Stdio) -> &mut Self {
        self.command.stdin(configuration);
        self
    }

    pub(crate) fn stdout(&mut self, configuration: Stdio) -> &mut Self {
        self.command.stdout(configuration);
        self
    }

    pub(crate) fn stderr(&mut self, configuration: Stdio) -> &mut Self {
        self.command.stderr(configuration);
        self
    }

    /// Spawn the command while transferring the metadata view to the child
    /// handle. This prevents a temporary `Command` value from dropping the
    /// trusted config while Git is still running, including fluent builder
    /// calls on a temporary `SafeGitCommand`.
    pub(crate) fn spawn(&mut self) -> std::io::Result<SafeGitChild> {
        let child = self.command.spawn()?;
        Ok(SafeGitChild {
            child,
            _trusted_view: self.trusted_view.take(),
        })
    }
}

pub(crate) struct SafeGitChild {
    child: Child,
    _trusted_view: Option<TrustedGitView>,
}

impl SafeGitChild {
    pub(crate) fn wait_with_output(self) -> std::io::Result<Output> {
        self.child.wait_with_output()
    }
}

impl Deref for SafeGitChild {
    type Target = Child;

    fn deref(&self) -> &Self::Target {
        &self.child
    }
}

impl DerefMut for SafeGitChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}

impl Deref for SafeGitCommand {
    type Target = Command;

    fn deref(&self) -> &Self::Target {
        &self.command
    }
}

fn safe_git_command_with_expected_origin(
    repo: Option<&Path>,
    args: &[&str],
    expected_origin: Option<(&str, &str)>,
) -> Result<SafeGitCommand> {
    let subcommand = args.first().copied().unwrap_or("");
    if subcommand.is_empty()
        || subcommand.starts_with('-')
        || subcommand.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        bail!("git_safe: invalid subcommand");
    }

    // Do not validate the mutable local config and then ask Git to reopen it.
    // Build a private metadata view instead: the generated config, HEAD, and
    // index are snapshots, while refs remain linked to the real checkout so a
    // fetch persists its remote-tracking update. Git never sees the source
    // checkout's config, even if a same-user process swaps it now.
    let trusted_view = if subcommand != "init" && subcommand != "clone" {
        let dir = match repo {
            Some(path) => path.to_path_buf(),
            None => std::env::current_dir().context("resolve current directory for git")?,
        };
        let validated = validated_local_config(&dir, expected_origin)?.ok_or_else(|| {
            anyhow::anyhow!(
                "git_safe: repo config is not generated by aur-gate in {}",
                dir.display()
            )
        })?;
        Some(TrustedGitView::new(&validated)?)
    } else {
        None
    };

    let mut cmd = Command::new("/usr/bin/git");
    cmd.arg("--no-pager");
    // Issue #27: never honour `git replace` refs for any object resolution.
    cmd.arg("--no-replace-objects");
    if let Some(dir) = repo {
        cmd.arg("-C").arg(dir);
    }
    cmd.args(SAFE_PRE);
    isolate_git_env(&mut cmd);
    if let Some(view) = trusted_view.as_ref() {
        cmd.env("GIT_DIR", view.path());
        cmd.env("GIT_WORK_TREE", &view.work_tree);
        cmd.env("GIT_OBJECT_DIRECTORY", &view.object_directory);
        cmd.env("GIT_INDEX_FILE", view.index_path());
    }
    cmd.arg(subcommand);
    let caller_args = &args[1..];
    let forced_args = safe_mid(subcommand);
    if forced_args.is_empty() {
        cmd.args(caller_args);
    } else if let Some(separator) = caller_args.iter().position(|arg| *arg == "--") {
        // Keep forced rendering options before a pathspec separator, but after
        // caller options, so a caller cannot override the final safe value.
        cmd.args(&caller_args[..separator]);
        cmd.args(forced_args);
        cmd.args(&caller_args[separator..]);
    } else {
        // Git accepts these options after revisions/ranges. Putting them last
        // makes the safety contract win over any caller-supplied rendering
        // option without changing pathspec interpretation.
        cmd.args(caller_args);
        cmd.args(forced_args);
    }

    Ok(SafeGitCommand {
        command: cmd,
        trusted_view,
    })
}

const CRITICAL_GIT_ENV: &[&str] = &[
    "GIT_EXEC_PATH",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_COMMON_DIR",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_SHALLOW_FILE",
    "GIT_REPLACE_REF_BASE",
    "GIT_ATTR_SOURCE",
    "GIT_EXTERNAL_DIFF",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_PROXY_COMMAND",
    "GIT_ASKPASS",
];

const NETWORK_REDIRECTION_ENV: &[&str] = &[
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "CURL_CA_BUNDLE",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

fn isolate_git_env(cmd: &mut Command) {
    // Git has many redirection/execution variables, including GIT_EXEC_PATH,
    // GIT_CONFIG_PARAMETERS, GIT_COMMON_DIR, and the obvious GIT_DIR family.
    // A denylist ages badly; this process needs none of the caller's GIT_*
    // state, so remove the namespace wholesale and add back only fixed values.
    for variable in CRITICAL_GIT_ENV {
        cmd.env_remove(variable);
    }
    for (key, _) in std::env::vars_os() {
        if key.as_encoded_bytes().starts_with(b"GIT_") {
            cmd.env_remove(key);
        }
    }
    for var in ["PAGER", "VISUAL", "EDITOR"] {
        cmd.env_remove(var);
    }
    // libcurl honors generic proxy and CA variables independently of Git's
    // config. The gate must not inherit a caller's MITM or trust-store choice.
    for variable in NETWORK_REDIRECTION_ENV {
        cmd.env_remove(variable);
    }
    cmd.env("GIT_PROXY_COMMAND", "");
    cmd.env("GIT_ASKPASS", "/bin/true");
    cmd.env("GIT_TERMINAL_PROMPT", "0");
    // Issue #27: disable replacement refs even if a `--no-replace-objects`
    // command-line flag is somehow stripped by a caller. Grafts have no
    // command-line equivalent, so redirect their deprecated file explicitly.
    cmd.env("GIT_NO_REPLACE_OBJECTS", "1");
    cmd.env("GIT_GRAFT_FILE", "/dev/null");
    cmd.env("GIT_CONFIG_GLOBAL", "/dev/null");
    cmd.env("GIT_CONFIG_SYSTEM", "/dev/null");
}

struct ValidatedLocalConfig {
    values: BTreeMap<String, String>,
    git_dir: PathBuf,
    work_tree: PathBuf,
}

/// Git normally discovers `.git/config` from the checkout even after a caller
/// has validated it. This view gives each command a private `GIT_DIR` whose
/// config, HEAD, and index are snapshots. Refs remain linked to the real
/// checkout because fetch must persist `origin/<branch>` for the next command;
/// the source config is never part of that view.
struct TrustedGitView {
    directory: tempfile::TempDir,
    work_tree: PathBuf,
    object_directory: PathBuf,
}

impl TrustedGitView {
    fn new(config: &ValidatedLocalConfig) -> Result<Self> {
        let directory = tempfile::tempdir().context("create trusted Git metadata view")?;
        let view = directory.path();
        fs::write(
            view.join("config"),
            trusted_config_contents(&config.values)?,
        )
        .context("write trusted Git config snapshot")?;
        snapshot_required_file(&config.git_dir.join("HEAD"), &view.join("HEAD"), "HEAD")?;
        snapshot_optional_file(&config.git_dir.join("index"), &view.join("index"), "index")?;

        let objects = config.git_dir.join("objects");
        if !real_directory_if_present(&objects)? {
            bail!("Git object directory is missing: {}", objects.display());
        }

        let refs = config.git_dir.join("refs");
        if !real_directory_if_present(&refs)? {
            bail!("Git refs directory is missing: {}", refs.display());
        }
        validate_real_tree(&refs)?;
        unix_fs::symlink(&refs, view.join("refs"))
            .with_context(|| format!("link trusted Git refs from {}", refs.display()))?;

        let packed_refs = config.git_dir.join("packed-refs");
        match fs::symlink_metadata(&packed_refs) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("packed Git refs is a symlink: {}", packed_refs.display())
            }
            Ok(metadata) if !metadata.is_file() => {
                bail!(
                    "packed Git refs is not a regular file: {}",
                    packed_refs.display()
                )
            }
            Ok(_) => unix_fs::symlink(&packed_refs, view.join("packed-refs"))
                .with_context(|| format!("link packed Git refs from {}", packed_refs.display()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("inspect {}", packed_refs.display()))
            }
        }

        Ok(Self {
            directory,
            work_tree: config.work_tree.clone(),
            object_directory: objects,
        })
    }

    fn path(&self) -> &Path {
        self.directory.path()
    }

    fn index_path(&self) -> PathBuf {
        self.directory.path().join("index")
    }
}

fn snapshot_required_file(source: &Path, destination: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(source) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("Git {label} is a symlink: {}", source.display())
        }
        Ok(metadata) if !metadata.is_file() => {
            bail!("Git {label} is not a regular file: {}", source.display())
        }
        Ok(_) => {}
        Err(error) => return Err(error).with_context(|| format!("inspect Git {label}")),
    }
    let contents = fs::read(source).with_context(|| format!("read Git {label}"))?;
    fs::write(destination, contents).with_context(|| format!("snapshot Git {label}"))
}

fn snapshot_optional_file(source: &Path, destination: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(source) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("Git {label} is a symlink: {}", source.display())
        }
        Ok(metadata) if !metadata.is_file() => {
            bail!("Git {label} is not a regular file: {}", source.display())
        }
        Ok(_) => snapshot_required_file(source, destination, label),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect Git {label}")),
    }
}

fn trusted_config_contents(values: &BTreeMap<String, String>) -> Result<Vec<u8>> {
    let version = values
        .get("core.repositoryformatversion")
        .context("trusted Git config lacks repository format version")?;
    if version != "0" && version != "1" {
        bail!("trusted Git config has an unknown repository format version");
    }
    if values.get("core.bare").map(String::as_str) != Some("false")
        || values.get("core.logallrefupdates").map(String::as_str) != Some("true")
    {
        bail!("trusted Git config has unexpected core values");
    }
    match version.as_str() {
        "0" if values.contains_key("extensions.objectformat") => {
            bail!("SHA-256 extension is invalid for repository format version 0")
        }
        "1" if values.get("extensions.objectformat").map(String::as_str) != Some("sha256") => {
            bail!("SHA-256 repository lacks its object-format extension")
        }
        _ => {}
    }

    let mut contents = format!(
        "[core]\n\trepositoryformatversion = {version}\n\tbare = false\n\tlogallrefupdates = true\n"
    );
    if version == "1" {
        contents.push_str("[extensions]\n\tobjectFormat = sha256\n");
    }
    match (
        values.get("remote.origin.url"),
        values.get("remote.origin.fetch"),
    ) {
        (None, None) => {}
        (Some(url), Some(fetch)) => {
            contents.push_str("[remote ");
            contents.push('"');
            contents.push_str("origin");
            contents.push('"');
            contents.push_str("]\n\turl = ");
            contents.push_str(&quote_config_value(url)?);
            contents.push_str("\n\tfetch = ");
            contents.push_str(&quote_config_string(fetch)?);
            contents.push('\n');
        }
        _ => bail!("trusted Git config has an incomplete remote section"),
    }
    Ok(contents.into_bytes())
}

/// Replace `.git/config` with the configuration needed by aur-gate and the
/// helper checkout. This deliberately does not inspect or edit the existing
/// config through `git config`: that would ask Git to parse attacker bytes
/// before the trust decision. The replacement is atomic, so a failed write
/// cannot leave a partially generated config behind.
///
/// `origin_url` and `branch` are both present for a normal clone/cache reset.
/// Passing `(None, None)` is useful at the makepkg seam before the staged
/// record has been read; no remote configuration is needed for that first
/// repository-root lookup.
pub(crate) fn reset_local_config(
    repo: &Path,
    origin_url: Option<&str>,
    branch: Option<&str>,
) -> Result<()> {
    let config = local_config_path(repo)?;
    // SHA-256 repositories need one structural extension to remain usable.
    // Read only this repository-identity marker, accept only the two known
    // formats, and discard every other byte when the file is regenerated.
    let sha256 = existing_sha256_marker(&config)?;
    let remote = match (origin_url, branch) {
        (Some(url), Some(branch)) => Some((quote_config_value(url)?, branch_refspec(branch)?)),
        (None, None) => None,
        _ => bail!("origin URL and branch must be supplied together"),
    };

    let repository_format_version = if sha256 { "1" } else { "0" };
    let mut contents = format!(
        "[core]\n\trepositoryformatversion = {repository_format_version}\n\tbare = false\n\tlogallrefupdates = true\n"
    );
    if sha256 {
        contents.push_str("[extensions]\n\tobjectFormat = sha256\n");
    }
    if let Some((url, refspec)) = remote {
        contents.push_str("[remote \"origin\"]\n");
        contents.push_str("\turl = ");
        contents.push_str(&url);
        contents.push('\n');
        contents.push_str("\tfetch = ");
        contents.push_str(&refspec);
        contents.push('\n');
    }

    let git_dir = config
        .parent()
        .context("generated config has no Git directory parent")?;
    purge_git_artifacts(git_dir)?;
    replace_file_atomically(&config, contents.as_bytes())?;
    // Re-check after the atomic config replacement so the handoff leaves no
    // replacement/graft artifact behind even if one appeared during reset.
    purge_git_artifacts(git_dir)
}

/// Remove repository-local replacement, graft, commit-graph, and object
/// alternates state before a checkout is handed to any process that might
/// invoke ordinary Git. Rust's Git calls also disable these mechanisms
/// in-process, but cleanup closes the same-user gap if a helper or build
/// unsets those environment protections.
fn purge_git_artifacts(git_dir: &Path) -> Result<()> {
    // Issue #38: commit graphs and object alternates can both substitute the
    // tree/parent view for a validly checksummed commit. Purge them with the
    // same symlink/real-directory hygiene as refs/replace.
    purge_objects_info_artifacts(git_dir)?;

    let info = git_dir.join("info");
    if real_directory_if_present(&info)? {
        remove_regular_file_if_present(&info.join("grafts"))?;
    }

    let refs = git_dir.join("refs");
    if real_directory_if_present(&refs)? {
        purge_replace_directory(&refs.join("replace"))?;
    }
    purge_packed_replace_refs(&git_dir.join("packed-refs"))?;
    Ok(())
}

fn purge_objects_info_artifacts(git_dir: &Path) -> Result<()> {
    let objects = git_dir.join("objects");
    if !real_directory_if_present(&objects)? {
        return Ok(());
    }
    let objects_info = objects.join("info");
    if !real_directory_if_present(&objects_info)? {
        return Ok(());
    }

    remove_regular_file_if_present(&objects_info.join("commit-graph"))?;
    remove_regular_file_if_present(&objects_info.join("alternates"))?;

    let commit_graphs = objects_info.join("commit-graphs");
    if real_directory_if_present(&commit_graphs)? {
        validate_real_tree(&commit_graphs)
            .with_context(|| format!("validate {}", commit_graphs.display()))?;
        fs::remove_dir_all(&commit_graphs)
            .with_context(|| format!("remove {}", commit_graphs.display()))?;
    }
    Ok(())
}

fn real_directory_if_present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("Git state path is a symlink: {}", path.display())
        }
        Ok(metadata) if !metadata.is_dir() => {
            bail!("Git state path is not a directory: {}", path.display())
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn remove_regular_file_if_present(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("Git state file is a symlink: {}", path.display())
        }
        Ok(metadata) if !metadata.is_file() => {
            bail!("Git state file is not regular: {}", path.display())
        }
        Ok(_) => {
            fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
            if fs::symlink_metadata(path).is_ok() {
                bail!("Git state file remained after removal: {}", path.display());
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn validate_real_tree(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect Git state {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("Git state is a symlink: {}", path.display());
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            validate_real_tree(&entry?.path())?;
        }
    } else if !metadata.is_file() {
        bail!("Git state is not a regular file: {}", path.display());
    }
    Ok(())
}

fn purge_replace_directory(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!(
                "replacement refs directory is a symlink: {}",
                path.display()
            )
        }
        Ok(metadata) if !metadata.is_dir() => {
            bail!(
                "replacement refs path is not a directory: {}",
                path.display()
            )
        }
        Ok(_) => {}
    }
    validate_real_tree(path)?;
    fs::remove_dir_all(path).with_context(|| format!("remove {}", path.display()))?;
    if fs::symlink_metadata(path).is_ok() {
        bail!("replacement refs directory remained: {}", path.display());
    }
    Ok(())
}

fn packed_ref_is_replacement(line: &str) -> bool {
    if line.starts_with('#') || line.starts_with('^') {
        return false;
    }
    let mut fields = line.split_whitespace();
    let Some(_object) = fields.next() else {
        return false;
    };
    let Some(reference) = fields.next() else {
        return false;
    };
    fields.next().is_none() && reference.starts_with("refs/replace/")
}

fn packed_refs_has_replacements(text: &str) -> bool {
    text.lines().any(packed_ref_is_replacement)
}

fn purge_packed_replace_refs(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("packed Git refs is not a regular file: {}", path.display());
    }
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("packed Git refs is not UTF-8: {}", path.display()))?;
    if !packed_refs_has_replacements(text) {
        return Ok(());
    }

    let mut retained = String::with_capacity(text.len());
    let mut remove_peeled = false;
    for line in text.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        if remove_peeled {
            if body.starts_with('^') {
                remove_peeled = false;
                continue;
            }
            remove_peeled = false;
        }
        if packed_ref_is_replacement(body) {
            remove_peeled = true;
            continue;
        }
        retained.push_str(line);
    }
    replace_file_atomically(path, retained.as_bytes())?;

    let after = fs::read_to_string(path).with_context(|| format!("verify {}", path.display()))?;
    if packed_refs_has_replacements(&after) {
        bail!("replacement refs remain in {}", path.display());
    }
    Ok(())
}

/// Read the repository-format marker with Git's own config parser. This is
/// deliberately a semantic query rather than a line scanner: Git config has
/// continuations, quoting, comments, and case-insensitive keys. A marker that
/// is malformed, unknown, or duplicated is ambiguous and therefore blocks the
/// reset instead of silently downgrading a SHA-256 repository to SHA-1.
fn existing_sha256_marker(config: &Path) -> Result<bool> {
    match fs::read(config) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error).with_context(|| format!("read {}", config.display())),
    }

    let entries = config_entries(config)?;
    let markers: Vec<&str> = entries
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("extensions.objectformat"))
        .map(|(_, value)| value.as_str())
        .collect();
    match markers.as_slice() {
        [] => Ok(false),
        [value] if value.eq_ignore_ascii_case("sha256") => Ok(true),
        [_] => bail!("Git config has an unknown object format marker"),
        _ => bail!("Git config has duplicate object format markers"),
    }
}

/// Return the semantic key/value entries from one config file. `--null` keeps
/// multiline values unambiguous, while `--no-includes` makes the generated
/// local file the complete contract being checked. Values are kept exact after
/// Git's parsing; the validator below intentionally does not coerce booleans
/// or trim attacker-controlled data.
fn config_entries(config: &Path) -> Result<Vec<(String, String)>> {
    let mut command = Command::new("/usr/bin/git");
    command
        .args(["config", "--file"])
        .arg(config)
        .args(["--no-includes", "--null", "--list"]);
    isolate_git_env(&mut command);
    let output = command
        .output()
        .with_context(|| format!("parse Git config {}", config.display()))?;
    if !output.status.success() {
        bail!("Git config is malformed or unavailable");
    }

    let mut entries = Vec::new();
    for record in output.stdout.split(|byte| *byte == 0) {
        if record.is_empty() {
            continue;
        }
        let Some(separator) = record.iter().position(|byte| *byte == b'\n') else {
            bail!("Git config emitted a malformed key/value record");
        };
        let key = std::str::from_utf8(&record[..separator])?;
        if key.is_empty() {
            bail!("Git config emitted an empty key");
        }
        let value = std::str::from_utf8(&record[separator + 1..])?;
        entries.push((key.to_ascii_lowercase(), value.to_owned()));
    }
    Ok(entries)
}

/// Validate every existing path component without following symlinks. The
/// supported AUR/helper paths are absolute directories; accepting `..` or a
/// redirected ancestor would make the later config replacement target a
/// checkout outside the caller's path.
fn validate_no_follow_path(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        bail!("repository path must be absolute: {}", path.display());
    }
    let mut current = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::CurDir => {}
            Component::ParentDir => {
                bail!(
                    "repository path contains a parent component: {}",
                    path.display()
                )
            }
            Component::Normal(part) => {
                current.push(part);
                let metadata = fs::symlink_metadata(&current)
                    .with_context(|| format!("inspect path component {}", current.display()))?;
                if metadata.file_type().is_symlink() {
                    bail!("repository path contains a symlink: {}", current.display());
                }
                if !metadata.is_dir() {
                    bail!(
                        "repository path component is not a directory: {}",
                        current.display()
                    );
                }
            }
            Component::Prefix(_) => bail!("repository path has an unsupported prefix"),
        }
    }
    Ok(())
}

/// Find a normal checkout root without following an ancestor or `.git`
/// symlink. The supported AUR/helper caches are ordinary clones; linked
/// worktrees and redirected gitdirs are intentionally outside this boundary.
fn checkout_root(repo: &Path) -> Result<PathBuf> {
    validate_no_follow_path(repo)?;
    let mut checkout = repo.to_path_buf();
    loop {
        let candidate = checkout.join(".git");
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                bail!("{} is not a real .git directory", candidate.display());
            }
            Ok(_) => return Ok(checkout),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let Some(parent) = checkout.parent() else {
                    bail!("{} is not inside a normal Git checkout", repo.display());
                };
                if parent == checkout {
                    bail!("{} is not inside a normal Git checkout", repo.display());
                }
                checkout = parent.to_path_buf();
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspect {}", candidate.display()))
            }
        }
    }
}

/// Return a normal checkout's config path without following an ancestor,
/// `.git`, or `config` symlink. Reset callers must approve the checkout root
/// they pass; silently rewriting an enclosing checkout for a nested path is
/// an unsafe identity substitution.
fn local_config_path(repo: &Path) -> Result<PathBuf> {
    let checkout = checkout_root(repo)?;
    if !checkout.components().eq(repo.components()) {
        bail!(
            "{} is nested inside checkout {}; an approved checkout root is required",
            repo.display(),
            checkout.display()
        );
    }

    let dotgit = checkout.join(".git");
    let config = dotgit.join("config");
    match fs::symlink_metadata(&config) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!("{} is not a regular config file", config.display())
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("inspect {}", config.display())),
    }
    Ok(config)
}

fn replace_file_atomically(config: &Path, contents: &[u8]) -> Result<()> {
    let parent = config
        .parent()
        .context("generated file has no parent directory")?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".aur-gate-config.")
        .tempfile_in(parent)
        .context("create temporary Git config")?;
    temporary.write_all(contents)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(config)
        .map_err(|error| error.error)
        .with_context(|| format!("replace generated file {}", config.display()))?;
    Ok(())
}

fn quote_config_string(value: &str) -> Result<String> {
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("generated Git config value is not a single-line string");
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        match character {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            character if character.is_control() => {
                bail!("generated Git config value contains a control character")
            }
            character => quoted.push(character),
        }
    }
    quoted.push('"');
    Ok(quoted)
}

fn quote_config_value(value: &str) -> Result<String> {
    if value.is_empty()
        || !value.starts_with("http://") && !value.starts_with("https://")
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        bail!("origin URL is not a single-line HTTP(S) value");
    }
    quote_config_string(value)
}

fn valid_branch_name(branch: &str) -> bool {
    !branch.is_empty()
        && !branch.starts_with('-')
        && !branch.starts_with('.')
        && !branch.ends_with('.')
        && !branch.ends_with('/')
        && !branch.contains("..")
        && !branch.contains("//")
        && !branch.contains("@{")
        && branch
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
}

fn branch_refspec_value(branch: &str) -> Result<String> {
    if !valid_branch_name(branch) {
        bail!("branch is not safe for a generated Git refspec");
    }
    Ok(format!("+refs/heads/{branch}:refs/remotes/origin/{branch}"))
}

fn branch_refspec(branch: &str) -> Result<String> {
    Ok(format!("\"{}\"", branch_refspec_value(branch)?))
}

fn validated_local_config(
    dir: &Path,
    expected_origin: Option<(&str, &str)>,
) -> Result<Option<ValidatedLocalConfig>> {
    // Match the generator's layout policy before asking Git to list values.
    // In particular, never let this fallback inspect a redirected config.
    let config = match local_config_path(dir) {
        Ok(config) => config,
        Err(_) => return Ok(None),
    };
    let entries = config_entries(&config)?;
    let mut values = BTreeMap::new();

    // The generated config has one value for every key. Rejecting a second
    // occurrence is important: Git permits duplicate keys and resolves them
    // with last-value-wins semantics, while a name-only allowlist cannot see
    // that an attacker changed the effective contract.
    for (key, value) in entries {
        if values.insert(key, value).is_some() {
            return Ok(None);
        }
    }

    let Some(repository_format_version) = values.get("core.repositoryformatversion") else {
        return Ok(None);
    };
    if repository_format_version != "0" && repository_format_version != "1" {
        return Ok(None);
    }

    // Build the expected semantic multiset from the same fixed values as the
    // generator. SHA-256 is the only permitted extension, and core.filemode is
    // intentionally absent: Git's platform-derived default must not be made
    // part of the trust contract.
    let mut expected = BTreeMap::from([
        (
            "core.repositoryformatversion".to_owned(),
            repository_format_version.clone(),
        ),
        ("core.bare".to_owned(), "false".to_owned()),
        ("core.logallrefupdates".to_owned(), "true".to_owned()),
    ]);
    if repository_format_version == "1" {
        expected.insert("extensions.objectformat".to_owned(), "sha256".to_owned());
    }

    if let Some((origin_url, branch)) = expected_origin {
        // Remote values are exact too; only their trusted call-site inputs are
        // dynamic. A direct caller that omits these inputs is not allowed to
        // bless whatever URL happened to be left in the repository config.
        if quote_config_value(origin_url).is_err() {
            return Ok(None);
        }
        let Ok(fetch) = branch_refspec_value(branch) else {
            return Ok(None);
        };
        expected.insert("remote.origin.url".to_owned(), origin_url.to_owned());
        expected.insert("remote.origin.fetch".to_owned(), fetch);
    }

    if values == expected {
        let git_dir = config
            .parent()
            .context("generated config has no Git directory parent")?
            .to_path_buf();
        let work_tree = git_dir
            .parent()
            .context("Git directory has no checkout parent")?
            .to_path_buf();
        Ok(Some(ValidatedLocalConfig {
            values,
            git_dir,
            work_tree,
        }))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Stdio;

    #[test]
    fn git_environment_namespace_is_removed() {
        let command = safe_git_command(None, &["init"]).unwrap();
        let env: Vec<_> = command.get_envs().collect();
        for variable in CRITICAL_GIT_ENV {
            let value = env
                .iter()
                .find_map(|(key, value)| (*key == OsStr::new(variable)).then_some(*value));
            if *variable == "GIT_PROXY_COMMAND" || *variable == "GIT_ASKPASS" {
                assert!(
                    value.flatten().is_some(),
                    "{variable} must be replaced safely"
                );
            } else {
                assert_eq!(value, Some(None), "{variable} must be removed");
            }
        }

        for variable in NETWORK_REDIRECTION_ENV {
            let value = env
                .iter()
                .find_map(|(key, value)| (*key == OsStr::new(variable)).then_some(*value));
            assert_eq!(value, Some(None), "{variable} must be removed");
        }

        for (variable, expected) in [
            ("GIT_NO_REPLACE_OBJECTS", "1"),
            ("GIT_GRAFT_FILE", "/dev/null"),
        ] {
            let value = env
                .iter()
                .find_map(|(key, value)| (*key == OsStr::new(variable)).then_some(*value));
            assert_eq!(
                value.flatten().map(|s| s.to_os_string()),
                Some(std::ffi::OsString::from(expected)),
                "{variable} must be set to {expected}"
            );
        }
    }

    #[test]
    fn option_like_subcommands_are_rejected() {
        assert!(safe_git_command(None, &["--replace-objects", "show"]).is_err());
        assert!(safe_git_command(None, &["show with spaces"]).is_err());
    }

    #[test]
    fn unknown_repo_local_config_is_rejected() {
        for (key, value) in [
            ("protocol.ext.allow", "always"),
            ("diff.external", "/tmp/evil"),
            ("url.ext::evil.insteadOf", "https://aur.archlinux.org"),
            ("filter.payload.smudge", "/tmp/evil"),
            ("core.hooksPath", "/tmp/hooks"),
            ("remote.origin.proxy", "command"),
            ("include.path", "/tmp/evil-config"),
            ("http.proxy", "http://attacker:8080"),
            ("http.sslcainfo", "/tmp/evil-ca.pem"),
            (
                "http.https://aur.archlinux.org.proxy",
                "http://attacker:8080",
            ),
            ("includeif.onbranch.main.path", "/tmp/evil-config"),
            // This is intentionally not a known Git key. Future namespaces
            // must fail closed without a new denylist entry.
            ("future.behavior", "surprise"),
        ] {
            let temp = tempfile::tempdir().unwrap();
            assert!(Command::new("/usr/bin/git")
                .args(["init", "-q"])
                .arg(temp.path())
                .status()
                .unwrap()
                .success());
            reset_local_config(
                temp.path(),
                Some("https://aur.archlinux.org/example.git"),
                Some("master"),
            )
            .unwrap();
            assert!(Command::new("/usr/bin/git")
                .arg("-C")
                .arg(temp.path())
                .args(["config", key, value])
                .status()
                .unwrap()
                .success());
            assert!(
                safe_git(Some(temp.path()), &["status", "--short"]).is_err(),
                "unknown local config was accepted: {key}"
            );
        }
    }

    #[test]
    fn generated_local_config_rejects_mutated_values() {
        for (key, value) in [
            ("core.repositoryformatversion", "1"),
            ("core.bare", "true"),
            ("core.filemode", "false"),
            ("core.logallrefupdates", "false"),
            ("extensions.objectFormat", "sha1"),
            ("remote.origin.url", "file:///tmp/evil"),
            ("remote.origin.url", "https://evil.example/repo.git"),
            (
                "remote.origin.fetch",
                "+refs/heads/evil:refs/remotes/origin/other",
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            assert!(Command::new("/usr/bin/git")
                .args(["init", "-q"])
                .arg(temp.path())
                .status()
                .unwrap()
                .success());
            reset_local_config(
                temp.path(),
                Some("https://aur.archlinux.org/example.git"),
                Some("master"),
            )
            .unwrap();
            assert!(Command::new("/usr/bin/git")
                .arg("-C")
                .arg(temp.path())
                .args(["config", key, value])
                .status()
                .unwrap()
                .success());
            let checked = if key.starts_with("remote.origin.") {
                safe_git_with_origin(
                    Some(temp.path()),
                    &["status", "--short"],
                    "https://aur.archlinux.org/example.git",
                    "master",
                )
            } else {
                safe_git(Some(temp.path()), &["status", "--short"])
            };
            assert!(
                checked.is_err(),
                "mutated generated value was accepted: {key}={value}"
            );
        }
    }

    #[test]
    fn generated_local_config_rejects_duplicate_allowed_keys() {
        for key in ["core.bare", "remote.origin.url"] {
            let temp = tempfile::tempdir().unwrap();
            assert!(Command::new("/usr/bin/git")
                .args(["init", "-q"])
                .arg(temp.path())
                .status()
                .unwrap()
                .success());
            reset_local_config(
                temp.path(),
                Some("https://aur.archlinux.org/example.git"),
                Some("master"),
            )
            .unwrap();
            assert!(Command::new("/usr/bin/git")
                .arg("-C")
                .arg(temp.path())
                .args([
                    "config",
                    "--add",
                    key,
                    if key == "core.bare" {
                        "false"
                    } else {
                        "https://aur.archlinux.org/example.git"
                    }
                ])
                .status()
                .unwrap()
                .success());
            assert!(
                safe_git(Some(temp.path()), &["status", "--short"]).is_err(),
                "duplicate generated key was accepted: {key}"
            );
        }
    }

    #[test]
    fn sha256_marker_uses_config_semantics_not_continuation_text() {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("config");
        std::fs::write(
            &config,
            concat!(
                "[core]\n\tspoof = prefix ",
                "\\",
                "\n\t[extensions]\n\tobjectFormat = sha256\n"
            ),
        )
        .unwrap();
        // A physical-line scanner sees an [extensions] section here, but Git
        // parses both lookalike lines as part of core.* values.
        assert!(!existing_sha256_marker(&config).unwrap());

        std::fs::write(&config, "[extensions]\n\tobjectFormat = sha1\n").unwrap();
        assert!(existing_sha256_marker(&config).is_err());
        std::fs::write(
            &config,
            "[extensions]\n\tobjectFormat = sha256\n\tobjectFormat = sha256\n",
        )
        .unwrap();
        assert!(existing_sha256_marker(&config).is_err());
    }

    #[test]
    fn safe_git_uses_validated_config_snapshot_after_local_swap() {
        let temp = tempfile::tempdir().unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .arg(temp.path())
            .status()
            .unwrap()
            .success());
        reset_local_config(temp.path(), None, None).unwrap();

        let mut command = safe_git_command(Some(temp.path()), &["status", "--short"]).unwrap();
        let swapped_config = temp.path().join("attacker-config");
        std::fs::write(
            &swapped_config,
            "[include]\n\tpath = /tmp/attacker-config\n[core]\n\tbare = false\n\tfsmonitor = /tmp/aur-gate-config-canary\n",
        )
        .unwrap();
        std::fs::remove_file(temp.path().join(".git/config")).unwrap();
        std::os::unix::fs::symlink(&swapped_config, temp.path().join(".git/config")).unwrap();
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "Git reopened the swapped local config: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("aur-gate-config-canary"),
            "Git consulted the swapped fsmonitor configuration"
        );
    }

    #[test]
    fn safe_git_uses_a_snapshot_of_the_index() {
        let temp = tempfile::tempdir().unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .arg(temp.path())
            .status()
            .unwrap()
            .success());
        std::fs::write(temp.path().join("tracked"), "before\n").unwrap();
        assert!(Command::new("/usr/bin/git")
            .arg("-C")
            .arg(temp.path())
            .args(["add", "tracked"])
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .arg("-C")
            .arg(temp.path())
            .args([
                "-c",
                "user.name=test",
                "-c",
                "user.email=test@example.invalid"
            ])
            .args(["commit", "-q", "-m", "initial"])
            .status()
            .unwrap()
            .success());
        reset_local_config(temp.path(), None, None).unwrap();

        std::fs::write(temp.path().join("tracked"), "after\n").unwrap();
        assert!(Command::new("/usr/bin/git")
            .arg("-C")
            .arg(temp.path())
            .args(["add", "tracked"])
            .status()
            .unwrap()
            .success());

        let listed = safe_git(Some(temp.path()), &["ls-files", "--cached", "-z"]).unwrap();
        assert!(listed.status.success());
        assert_eq!(listed.stdout, b"tracked\0");
        let cached_diff = safe_git(
            Some(temp.path()),
            &["diff", "--cached", "--quiet", "HEAD", "--"],
        )
        .unwrap();
        assert!(!cached_diff.status.success());
    }

    #[test]
    fn reset_local_config_discards_unknown_keys() {
        let temp = tempfile::tempdir().unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .arg(temp.path())
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .arg("-C")
            .arg(temp.path())
            .args(["config", "include.path", "/tmp/evil"])
            .status()
            .unwrap()
            .success());
        reset_local_config(
            temp.path(),
            Some("https://aur.archlinux.org/example.git"),
            Some("feature/rust"),
        )
        .unwrap();

        let config = std::fs::read_to_string(temp.path().join(".git/config")).unwrap();
        assert!(!config.contains("include"));
        assert!(!config.contains("evil"));
        assert!(config.contains("remote \"origin\""));
        assert!(safe_git_with_origin(
            Some(temp.path()),
            &["status", "--short"],
            "https://aur.archlinux.org/example.git",
            "feature/rust",
        )
        .is_ok());
    }

    #[test]
    fn reset_local_config_purges_replace_and_graft_state() {
        let temp = tempfile::tempdir().unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .arg(temp.path())
            .status()
            .unwrap()
            .success());
        let git_dir = temp.path().join(".git");
        let replace_dir = git_dir.join("refs/replace");
        std::fs::create_dir_all(&replace_dir).unwrap();
        std::fs::write(replace_dir.join("a".repeat(40)), "replacement\n").unwrap();
        std::fs::write(
            git_dir.join("info/grafts"),
            format!("{} {}\n", "a".repeat(40), "b".repeat(40)),
        )
        .unwrap();
        std::fs::write(
            git_dir.join("packed-refs"),
            format!(
                "# pack-refs with: peeled\n{} refs/replace/{}\n^{}\n{} refs/heads/master\n",
                "c".repeat(40),
                "d".repeat(40),
                "e".repeat(40),
                "f".repeat(40)
            ),
        )
        .unwrap();

        reset_local_config(temp.path(), None, None).unwrap();

        assert!(!git_dir.join("info/grafts").exists());
        assert!(!git_dir.join("refs/replace").exists());
        let packed = std::fs::read_to_string(git_dir.join("packed-refs")).unwrap();
        assert!(!packed.contains("refs/replace/"));
        assert!(packed.contains("refs/heads/master"));
    }

    #[test]
    fn reset_local_config_rejects_replacement_state_symlink() {
        let temp = tempfile::tempdir().unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .arg(temp.path())
            .status()
            .unwrap()
            .success());
        let external = temp.path().join("external-replace");
        std::fs::create_dir(&external).unwrap();
        let replace = temp.path().join(".git/refs/replace");
        std::os::unix::fs::symlink(&external, &replace).unwrap();

        assert!(reset_local_config(temp.path(), None, None).is_err());
        assert!(replace.is_symlink());
        assert!(external.is_dir());
    }

    #[test]
    fn local_config_path_rejects_symlinked_ancestors() {
        let temp = tempfile::tempdir().unwrap();
        let real_parent = temp.path().join("real-parent");
        let repo = real_parent.join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .arg(&repo)
            .status()
            .unwrap()
            .success());
        let alias_parent = temp.path().join("alias-parent");
        std::os::unix::fs::symlink(&real_parent, &alias_parent).unwrap();
        let config_before = std::fs::read_to_string(repo.join(".git/config")).unwrap();

        assert!(reset_local_config(&alias_parent.join("repo"), None, None).is_err());
        assert_eq!(
            std::fs::read_to_string(repo.join(".git/config")).unwrap(),
            config_before
        );
    }

    #[test]
    fn reset_local_config_rejects_nested_checkout_path() {
        let temp = tempfile::tempdir().unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .arg(temp.path())
            .status()
            .unwrap()
            .success());
        let nested = temp.path().join("nested/package");
        std::fs::create_dir_all(&nested).unwrap();
        let config_before = std::fs::read_to_string(temp.path().join(".git/config")).unwrap();
        assert!(reset_local_config(&nested, None, None).is_err());
        assert_eq!(
            std::fs::read_to_string(temp.path().join(".git/config")).unwrap(),
            config_before
        );
    }

    #[test]
    fn reset_local_config_rejects_config_symlink() {
        let temp = tempfile::tempdir().unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .arg(temp.path())
            .status()
            .unwrap()
            .success());
        let config = temp.path().join(".git/config");
        let target = temp.path().join("outside-config");
        std::fs::write(&target, "[http]\n\tproxy = http://evil\n").unwrap();
        std::fs::remove_file(&config).unwrap();
        std::os::unix::fs::symlink(&target, &config).unwrap();
        assert!(reset_local_config(temp.path(), None, None).is_err());
        assert_eq!(
            std::fs::read_to_string(target).unwrap(),
            "[http]\n\tproxy = http://evil\n"
        );
    }

    #[test]
    fn reset_local_config_preserves_sha256_repository_identity() {
        let temp = tempfile::tempdir().unwrap();
        let initialized = Command::new("/usr/bin/git")
            .args(["init", "-q", "--object-format=sha256"])
            .arg(temp.path())
            .status()
            .unwrap();
        if !initialized.success() {
            eprintln!("git lacks SHA-256 object format; skipping");
            return;
        }
        reset_local_config(temp.path(), None, None).unwrap();
        let output = safe_git(Some(temp.path()), &["rev-parse", "--show-object-format"]).unwrap();
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "sha256");
    }

    #[test]
    fn replace_objects_are_disabled_by_git_command() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        assert!(std::process::Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .arg(repo)
            .status()
            .unwrap()
            .success());
        for (k, v) in [("user.email", "t@t"), ("user.name", "t")] {
            assert!(std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["config", k, v])
                .status()
                .unwrap()
                .success());
        }

        std::fs::write(repo.join("PKGBUILD"), "original\n").unwrap();
        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["add", "PKGBUILD"])
            .status()
            .unwrap()
            .success());
        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["commit", "-q", "-m", "original commit"])
            .status()
            .unwrap()
            .success());
        let original = String::from_utf8(
            std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();

        std::fs::write(repo.join("PKGBUILD"), "replaced\n").unwrap();
        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["commit", "-q", "-am", "replace commit"])
            .status()
            .unwrap()
            .success());
        let replacement = String::from_utf8(
            std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();

        reset_local_config(
            repo,
            Some("https://aur.archlinux.org/example.git"),
            Some("master"),
        )
        .unwrap();
        assert!(std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["replace", &original, &replacement])
            .status()
            .unwrap()
            .success());

        // A plain git call resolves the replacement.
        let raw = std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["show", "--no-patch", "--format=%s", &original])
            .output()
            .unwrap()
            .stdout;
        assert_eq!(
            String::from_utf8_lossy(&raw).trim(),
            "replace commit",
            "fixture: plain git should honour the replace ref"
        );

        // safe_git must see the original object.
        let safe = safe_git_with_origin(
            Some(repo),
            &["show", "--no-patch", "--format=%s", &original],
            "https://aur.archlinux.org/example.git",
            "master",
        )
        .unwrap();
        assert!(
            safe.status.success(),
            "safe git failed: {}",
            String::from_utf8_lossy(&safe.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&safe.stdout).trim(),
            "original commit"
        );
    }

    #[test]
    fn grafts_are_disabled_by_safe_git() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        assert!(std::process::Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .arg(repo)
            .status()
            .unwrap()
            .success());
        for (k, v) in [("user.email", "t@t"), ("user.name", "t")] {
            assert!(std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["config", k, v])
                .status()
                .unwrap()
                .success());
        }

        for (name, content) in [("one", "one\n"), ("two", "two\n"), ("three", "three\n")] {
            std::fs::write(repo.join("PKGBUILD"), content).unwrap();
            assert!(std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["add", "PKGBUILD"])
                .status()
                .unwrap()
                .success());
            assert!(std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["commit", "-q", "-m", name])
                .status()
                .unwrap()
                .success());
        }
        let first = String::from_utf8(
            std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["rev-list", "--max-count=1", "--reverse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        let second = String::from_utf8(
            std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["rev-parse", "HEAD~1"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        let tip = String::from_utf8(
            std::process::Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();

        // Grafts rewrite only ancestry: make the tip appear rooted at the
        // first commit instead of its real second-commit parent.
        reset_local_config(
            repo,
            Some("https://aur.archlinux.org/example.git"),
            Some("master"),
        )
        .unwrap();
        let grafts = repo.join(".git/info/grafts");
        std::fs::create_dir_all(grafts.parent().unwrap()).unwrap();
        std::fs::write(&grafts, format!("{tip} {first}\n")).unwrap();

        let raw = std::process::Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["show", "-s", "--format=%P", &tip])
            .env("GIT_GRAFT_FILE", &grafts)
            .output()
            .unwrap();
        assert!(raw.status.success());
        assert_eq!(
            String::from_utf8_lossy(&raw.stdout).trim(),
            first,
            "fixture: plain git should honour the grafted parent"
        );

        let safe = safe_git_with_origin(
            Some(repo),
            &["show", "-s", "--format=%P", &tip],
            "https://aur.archlinux.org/example.git",
            "master",
        )
        .unwrap();
        assert!(
            safe.status.success(),
            "safe git failed: {}",
            String::from_utf8_lossy(&safe.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&safe.stdout).trim(),
            second,
            "safe_git must use the committed parent, not info/grafts"
        );
    }

    #[test]
    fn reset_local_config_purges_commit_graph_and_alternates() {
        let temp = tempfile::tempdir().unwrap();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .arg(temp.path())
            .status()
            .unwrap()
            .success());
        let git_dir = temp.path().join(".git");
        let objects_info = git_dir.join("objects/info");
        std::fs::create_dir_all(&objects_info).unwrap();
        std::fs::write(objects_info.join("commit-graph"), b"CGPH\x01fake\n").unwrap();
        std::fs::write(objects_info.join("alternates"), b"/tmp/other-objects\n").unwrap();
        let commit_graphs = objects_info.join("commit-graphs");
        std::fs::create_dir_all(&commit_graphs).unwrap();
        std::fs::write(commit_graphs.join("graph-1"), b"graph").unwrap();

        reset_local_config(temp.path(), None, None).unwrap();

        assert!(!objects_info.join("commit-graph").exists());
        assert!(!objects_info.join("alternates").exists());
        assert!(!commit_graphs.exists());
    }

    #[test]
    fn safe_git_ignores_poisoned_commit_graph() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        assert!(Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .arg(repo)
            .status()
            .unwrap()
            .success());
        for (k, v) in [("user.name", "t"), ("user.email", "t@example.invalid")] {
            assert!(Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["config", k, v])
                .status()
                .unwrap()
                .success());
        }

        std::fs::write(repo.join("PKGBUILD"), b"pkg\n").unwrap();
        assert!(Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["add", "PKGBUILD"])
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["commit", "-qm", "initial"])
            .status()
            .unwrap()
            .success());

        // Normalize the generated config so safe_git accepts the repo, then
        // write a real commit-graph. (reset purges any stale graph.)
        reset_local_config(repo, None, None).unwrap();

        let true_tree = String::from_utf8(
            Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["log", "--format=%T", "-n1", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        let empty_tree = String::from_utf8(
            Command::new("/usr/bin/git")
                .arg("-C")
                .arg(repo)
                .args(["mktree"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        assert!(crate::state::is_object_id(&true_tree));
        assert!(crate::state::is_object_id(&empty_tree));
        assert_ne!(true_tree, empty_tree);

        assert!(Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(["commit-graph", "write", "--reachable"])
            .status()
            .unwrap()
            .success());

        let graph = repo.join(".git/objects/info/commit-graph");
        let mut bytes = std::fs::read(&graph).unwrap();
        // SHA-1 hash version 1: the final 20 bytes are the checksum.
        let checksum_len = 20;
        assert!(bytes.len() > checksum_len);

        let true_tree_bytes = hex_to_bytes(&true_tree);
        let empty_tree_bytes = hex_to_bytes(&empty_tree);
        let pos = bytes
            .windows(true_tree_bytes.len())
            .position(|window| window == true_tree_bytes.as_slice())
            .expect("true tree OID not found in commit-graph");
        bytes[pos..pos + true_tree_bytes.len()].copy_from_slice(&empty_tree_bytes);

        // Recompute the SHA-1 checksum for the bytes before the existing one.
        let new_checksum = sha1_bytes(&bytes[..bytes.len() - checksum_len]);
        bytes.truncate(bytes.len() - checksum_len);
        bytes.extend_from_slice(&new_checksum);
        // Git writes the graph read-only; make it writable for the fixture.
        std::fs::set_permissions(&graph, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&graph, &bytes).unwrap();

        // Plain git with the graph enabled must see the poisoned tree. Use
        // `git log`, not `rev-parse HEAD^{tree}`, because the latter parses the
        // commit object directly and does not consult the graph.
        let poisoned = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args([
                "-c",
                "core.commitGraph=true",
                "log",
                "--format=%T",
                "-n1",
                "HEAD",
            ])
            .output()
            .unwrap();
        assert!(
            poisoned.status.success(),
            "{}",
            String::from_utf8_lossy(&poisoned.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&poisoned.stdout).trim(),
            empty_tree,
            "fixture: poisoned graph should win when commitGraph is enabled"
        );

        // safe_git forces core.commitGraph=false and resolves the real tree.
        let safe = safe_git(Some(repo), &["log", "--format=%T", "-n1", "HEAD"]).unwrap();
        assert!(
            safe.status.success(),
            "safe git failed: {}",
            String::from_utf8_lossy(&safe.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&safe.stdout).trim(),
            true_tree,
            "safe_git must ignore the commit-graph and use the commit object"
        );
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn sha1_bytes(data: &[u8]) -> Vec<u8> {
        let mut child = Command::new("/usr/bin/sha1sum")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.as_mut().unwrap().write_all(data).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        let hex = text.split_whitespace().next().unwrap();
        hex_to_bytes(hex)
    }
}
