// This module is compiled into every integration-test binary, and each binary
// only exercises a subset of the fixture API. Module-wide dead-code allowance
// is therefore deliberate rather than a lazy suppression.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aur_gate::classifier::{CollectingReporter, NoLlm};
use aur_gate::cli::dispatch;
use aur_gate::config::Config;
use aur_gate::engine::App;
use aur_gate::rpc::CurlRpc;
use aur_gate::srcinfo::{parse_desc, LocalRecord, Pacman};
use aur_gate::state::Paths;

pub const DRIVER_ENV: &str = "AUR_GATE_DRIVER";
pub const FIXTURE_MAKEPKG_ENV: &str = "AUR_GATE_FIXTURE_MAKEPKG";
pub const FIXTURE_PACMAN_DB_ENV: &str = "AUR_GATE_PACMAN_DB";
pub const FIXTURE_LOG_ENV: &str = "AUR_GATE_FIXTURE_LOG";
pub const FIXTURE_FAKE_UPDATE_ENV: &str = "AUR_GATE_FAKE_UPDATE";
pub const FIXTURE_FAKE_PACMAN_SYNC_ENV: &str = "AUR_GATE_FAKE_PACMAN_SYNC";
pub const FIXTURE_MAKEPKG_STATUS_ENV: &str = "AUR_GATE_MAKEPKG_STATUS";
pub const FIXTURE_HELPER_PREMAKEPKG_FAILURE_ENV: &str = "AUR_GATE_HELPER_PREMAKEPKG_FAILURE";
pub const FIXTURE_HELPER_POSTBUILD_FAILURE_ENV: &str = "AUR_GATE_HELPER_POSTBUILD_FAILURE";
pub const FIXTURE_UNRELATED_INSTALL_ENV: &str = "AUR_GATE_UNRELATED_INSTALL_ON_FAILURE";
pub const FIXTURE_ACCEPT_FAILURE_ENV: &str = "AUR_GATE_TEST_ACCEPT_FAILURE";

/// Run a list of test functions from a `harness = false` integration test binary.
/// When the binary is re-entered as a fake subprocess, dispatch to that role
/// instead of running tests.
pub fn main(tests: &[(&'static str, fn())]) {
    if std::env::var(DRIVER_ENV).as_deref() == Ok("1") {
        driver_main();
        return;
    }
    let mut failed = Vec::new();
    for (name, test) in tests {
        eprintln!("\n---- running {} ----", name);
        let result = std::panic::catch_unwind(*test);
        if result.is_err() {
            failed.push(*name);
        }
    }
    if !failed.is_empty() {
        eprintln!("\nFAILED: {}", failed.join(", "));
        std::process::exit(101);
    }
    eprintln!("\nall tests passed");
}

/// Re-entry point for the fixture binary. The parent test creates symlinks
/// named `aur-gate`, `yay`, `paru`, `makepkg`, and `pacman` all pointing to
/// the same test binary. `argv[0]` and the inherited fixture environment
/// select the role.
fn driver_main() {
    let first_arg = std::env::args().next().unwrap_or_default();
    let argv0 = Path::new(&first_arg)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    match argv0 {
        "aur-gate" => run_as_aur_gate(),
        "yay" => fake_yay_or_paru("yay"),
        "paru" => fake_yay_or_paru("paru"),
        "makepkg" => fake_makepkg(),
        "pacman" => fake_pacman(),
        other => {
            eprintln!("aur-gate driver: unknown argv0 '{other}'");
            std::process::exit(1);
        }
    }
}

// --- child driver (production CLI in a controlled fixture) -----------------

fn run_as_aur_gate() {
    let config = Config::load().expect("fixture driver config");
    let paths = Paths::new(config.state_dir.clone());
    paths.ensure_dirs().expect("fixture state dirs");

    let pacman_db = std::env::var_os(FIXTURE_PACMAN_DB_ENV)
        .map(PathBuf::from)
        .expect("fixture driver needs AUR_GATE_PACMAN_DB");
    let pacman = FixturePacman::new(pacman_db);
    let rpc = CurlRpc::new(PathBuf::from("/usr/bin/curl"), config.aur_url.clone());
    let mut reporter = CollectingReporter::default();
    let mut llm = NoLlm;

    let makepkg_path = std::env::var_os(FIXTURE_MAKEPKG_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/bin/makepkg"));

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
        makepkg_path,
        staging: std::env::var("AUR_GATE_STAGING").as_deref() == Ok("1"),
        llm_auto_boring: false,
        explain_maxlines: config.explain_maxlines,
        explain_model: "none".into(),
        hard: aur_gate::rules::hard_rules(),
        review: aur_gate::rules::review_rules(),
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = if std::env::var("AUR_GATE_AS_MAKEPKG").as_deref() == Ok("1") {
        "makepkg-guard"
    } else {
        args.first().map(String::as_str).unwrap_or("usage")
    };
    append_event(&format!("cli:{command}:start"));
    if std::env::var(FIXTURE_ACCEPT_FAILURE_ENV).is_ok()
        && args.first().is_some_and(|arg| arg == "accept")
    {
        append_event("cli:accept:simulated-failure");
        eprintln!("aur-gate: simulated accept failure");
        std::process::exit(1);
    }
    let rc = dispatch(&mut app, &args);
    append_event(&format!("cli:{command}:end:{rc}"));
    std::process::exit(rc);
}

// --- file-backed pacman adapter --------------------------------------------

pub struct FixturePacman {
    db_dir: PathBuf,
}

impl FixturePacman {
    pub fn new(db_dir: PathBuf) -> Self {
        fs::create_dir_all(&db_dir).unwrap();
        Self { db_dir }
    }

    /// Seed an installed package record (version A) before the gate runs.
    pub fn seed_installed(
        &self,
        name: &str,
        version: &str,
        pkgbase: &str,
        build_epoch: u64,
        install_epoch: u64,
    ) {
        self.write_desc(name, version, pkgbase, build_epoch, install_epoch);
    }

    pub fn write_desc(
        &self,
        name: &str,
        version: &str,
        pkgbase: &str,
        build_epoch: u64,
        install_epoch: u64,
    ) {
        let dir = self.db_dir.join(format!("{}-{}", name, version));
        fs::create_dir_all(&dir).unwrap();
        let content = format!(
            "%NAME%\n{}\n%VERSION%\n{}\n%BASE%\n{}\n%BUILDDATE%\n{}\n%INSTALLDATE%\n{}\n",
            name, version, pkgbase, build_epoch, install_epoch
        );
        fs::write(dir.join("desc"), content).unwrap();
    }

    pub fn find_record(&self, name: &str) -> Option<LocalRecord> {
        let entries = fs::read_dir(&self.db_dir).ok()?;
        let mut chosen: Option<LocalRecord> = None;
        for e in entries.flatten() {
            let fname = e.file_name().to_string_lossy().to_string();
            if !fname.starts_with(&format!("{name}-")) {
                continue;
            }
            let desc = e.path().join("desc");
            let content = fs::read_to_string(&desc).ok()?;
            if let Some(rec) = parse_desc(&content, name) {
                // Prefer the newest record so an updated install overwrites
                // the pre-gate baseline for `accept`.
                if chosen
                    .as_ref()
                    .map(|c| rec.build_epoch > c.build_epoch)
                    .unwrap_or(true)
                {
                    chosen = Some(rec);
                }
            }
        }
        chosen
    }
}

impl Pacman for FixturePacman {
    fn query(&self, name: &str) -> Option<String> {
        self.find_record(name)
            .map(|r| format!("{} {}", r.name, r.version))
    }

    fn local_record(&self, name: &str) -> Option<LocalRecord> {
        self.find_record(name)
    }

    fn sync_info(&self, _name: &str) -> bool {
        false
    }

    fn dep_satisfied(&self, _spec: &str) -> bool {
        false
    }
}

// --- HTTP AUR fixture ------------------------------------------------------

#[derive(Debug, Clone)]
pub struct HttpRecord {
    pub path: String,
}

pub struct HttpFixture {
    handle: Option<std::thread::JoinHandle<()>>,
    stop_tx: mpsc::Sender<()>,
    _temp: tempfile::TempDir,
    pub port: u16,
    pub records: Arc<Mutex<Vec<HttpRecord>>>,
    pub repo: PathBuf,
}

impl HttpFixture {
    /// Serve a bare git repository and AUR RPC from a temporary directory.
    /// `pkgbase` is the repository name; `rpc_json` is returned for
    /// `/rpc/v5/info` queries. The repository itself is at `<root>/<pkgbase>.git`.
    pub fn serve(pkgbase: &str, rpc_json: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind HTTP fixture");
        let port = listener.local_addr().unwrap().port();

        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join(format!("{pkgbase}.git"));
        fs::create_dir_all(&repo).unwrap();

        let records = Arc::new(Mutex::new(Vec::new()));
        let (stop_tx, stop_rx) = mpsc::channel::<()>();

        let records2 = Arc::clone(&records);
        let repo2 = repo.clone();
        let rpc_json = rpc_json.to_string();

        let handle = std::thread::spawn(move || {
            server_thread(listener, stop_rx, records2, repo2, rpc_json);
        });

        HttpFixture {
            handle: Some(handle),
            stop_tx,
            _temp: temp,
            port,
            records,
            repo,
        }
    }

    pub fn stop(&mut self) {
        let _ = self.stop_tx.send(());
        let _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
        if let Some(handle) = self.handle.take() {
            handle.join().ok();
        }
    }
}

fn server_thread(
    listener: TcpListener,
    stop_rx: mpsc::Receiver<()>,
    records: Arc<Mutex<Vec<HttpRecord>>>,
    repo: PathBuf,
    rpc_json: String,
) {
    listener.set_nonblocking(false).ok();
    loop {
        match listener.accept() {
            Ok((stream, _)) => handle_connection(stream, &records, &repo, &rpc_json),
            Err(_) => break,
        }
        if stop_rx.try_recv().is_ok() {
            break;
        }
    }
}

fn handle_connection(
    mut stream: TcpStream,
    records: &Arc<Mutex<Vec<HttpRecord>>>,
    repo: &Path,
    rpc_json: &str,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));

    while let Some((_method, raw_path, _headers)) = read_request(&mut stream) {
        let path = raw_path
            .split_once('?')
            .map(|(p, _)| p)
            .unwrap_or(&raw_path)
            .to_string();

        records
            .lock()
            .unwrap()
            .push(HttpRecord { path: path.clone() });

        let repo_name = repo.file_name().unwrap().to_string_lossy();
        let prefix = format!("/{}/", repo_name);

        if path == "/rpc/v5/info" {
            respond(&mut stream, 200, "application/json", rpc_json.as_bytes());
            continue;
        }

        if !path.starts_with(&prefix) {
            not_found(&mut stream);
            continue;
        }

        let inside = &path[prefix.len()..];
        if inside.contains("..") || inside.starts_with('/') {
            not_found(&mut stream);
            continue;
        }

        let target = repo.join(inside);
        match fs::read(&target) {
            Ok(body) => {
                let ct = if inside.ends_with("info/refs") || inside.ends_with("HEAD") {
                    "text/plain; charset=utf-8"
                } else {
                    "application/octet-stream"
                };
                respond(&mut stream, 200, ct, &body);
            }
            Err(_) => not_found(&mut stream),
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Option<(String, String, Vec<String>)> {
    let mut buf = [0u8; 8192];
    let mut accum = Vec::new();
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return None,
            Ok(n) => accum.extend_from_slice(&buf[..n]),
            Err(_) => {
                if accum.is_empty() {
                    return None;
                }
                break;
            }
        }
        if accum.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let header_end = accum
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(accum.len());
    let head = String::from_utf8_lossy(&accum[..header_end]);
    let mut lines = head.lines();
    let request = lines.next()?;
    let mut parts = request.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let headers: Vec<String> = lines.map(|s| s.to_string()).collect();
    Some((method, path, headers))
}

fn not_found(stream: &mut TcpStream) {
    let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\n\r\n");
}

fn respond(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {} OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        status, content_type, body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
}

// --- fixture environment ---------------------------------------------------

pub struct Fixture {
    pub temp: tempfile::TempDir,
    pub home: PathBuf,
    pub state: PathBuf,
    pub yay_cache: PathBuf,
    pub paru_cache: PathBuf,
    pub pacman_db: PathBuf,
    pub bin: PathBuf,
    pub config_file: PathBuf,
    pub log: PathBuf,
    pub http: HttpFixture,
    pub http_repo: PathBuf,
    pub aur_url: String,
    pub exe: PathBuf,
    pub makepkg: PathBuf,
    pub wrapper_sh: PathBuf,
}

impl Fixture {
    pub fn new(pkgbase: &str, rpc_json: &str) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let state = temp.path().join("state");
        let yay_cache = temp.path().join("yay");
        let paru_cache = temp.path().join("paru");
        let pacman_db = temp.path().join("pacman").join("local");
        let bin = temp.path().join("bin");
        let config_file = temp.path().join("config");
        let log = temp.path().join("fixture.log");
        let wrapper_sh = temp.path().join("wrapper.sh");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(state.join("accepted")).unwrap();
        fs::create_dir_all(state.join("staged")).unwrap();
        fs::create_dir_all(&yay_cache).unwrap();
        fs::create_dir_all(&paru_cache).unwrap();
        fs::create_dir_all(&pacman_db).unwrap();
        fs::create_dir_all(&bin).unwrap();

        let http = HttpFixture::serve(pkgbase, rpc_json);
        let aur_url = format!("http://127.0.0.1:{}", http.port);
        let http_repo = http.repo.clone();

        let exe = std::env::current_exe().expect("current test executable");
        for name in ["aur-gate", "yay", "paru", "makepkg", "pacman"] {
            let link = bin.join(name);
            symlink(&exe, &link).ok();
        }
        // The wrapper needs a few core utilities in PATH. Symlink them so we can
        // keep PATH scoped to fixture.bin and avoid calling a real yay/paru.
        for (name, target) in [
            ("flock", "/bin/flock"),
            ("env", "/bin/env"),
            ("mkdir", "/bin/mkdir"),
        ] {
            let _ = fs::remove_file(bin.join(name));
            let _ = symlink(target, bin.join(name));
        }

        let makepkg = bin.join("makepkg");
        fs::write(&config_file, "").unwrap();
        fs::write(&wrapper_sh, aur_gate::wrapper::WRAPPER).unwrap();
        Self {
            temp,
            home,
            state,
            yay_cache,
            paru_cache,
            pacman_db,
            bin,
            config_file,
            log,
            http,
            http_repo,
            aur_url,
            exe,
            makepkg,
            wrapper_sh,
        }
    }

    pub fn base_env(&self) -> HashMap<String, String> {
        // Keep PATH scoped to fixture.bin. This forces `cmd_gate` and the wrapper
        // to use our shims instead of any real yay/paru installed on /bin or /usr/bin.
        // The fixture bin already provides flock, env, and mkdir symlinks.
        let path = format!("{}", self.bin.display());
        let mut env = HashMap::new();
        env.insert("HOME".into(), self.home.to_string_lossy().to_string());
        env.insert(
            "AUR_GATE_STATE_DIR".into(),
            self.state.to_string_lossy().to_string(),
        );
        env.insert(
            "AUR_GATE_YAY_CACHE".into(),
            self.yay_cache.to_string_lossy().to_string(),
        );
        env.insert(
            "AUR_GATE_PARU_CACHE".into(),
            self.paru_cache.to_string_lossy().to_string(),
        );
        env.insert("AUR_GATE_AUR_URL".into(), self.aur_url.clone());
        env.insert(
            "AUR_GATE_CONFIG".into(),
            self.config_file.to_string_lossy().to_string(),
        );
        env.insert(
            "AUR_GATE_PACMAN_DB".into(),
            self.pacman_db.to_string_lossy().to_string(),
        );
        env.insert(
            "AUR_GATE_FIXTURE_MAKEPKG".into(),
            self.makepkg.to_string_lossy().to_string(),
        );
        env.insert(
            "AUR_GATE_FIXTURE_LOG".into(),
            self.log.to_string_lossy().to_string(),
        );
        env.insert("PATH".into(), path);
        env.insert("AUR_GATE_STAGING".into(), "1".into());
        env.insert(DRIVER_ENV.into(), "1".into());
        env
    }

    pub fn run_aur_gate(&self, args: &[&str], extra_env: &[(&str, &str)]) -> (i32, String, String) {
        let mut cmd = Command::new(self.bin.join("aur-gate"));
        cmd.args(args);
        for (k, v) in self.base_env() {
            cmd.env(k, v);
        }
        for (k, v) in extra_env {
            cmd.env(*k, *v);
        }
        let out = cmd.output().expect("spawn aur-gate");
        let rc = out.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        (rc, stdout, stderr)
    }

    pub fn run_wrapper(
        &self,
        helper: &str,
        args: &[&str],
        extra_env: &[(&str, &str)],
    ) -> (i32, String, String) {
        self.run_wrapper_shell("/bin/bash", helper, args, extra_env)
    }

    pub fn run_wrapper_shell(
        &self,
        shell: &str,
        helper: &str,
        args: &[&str],
        extra_env: &[(&str, &str)],
    ) -> (i32, String, String) {
        let mut script = format!("source {}\n", self.wrapper_sh.display());
        script.push_str(helper);
        for a in args {
            script.push(' ');
            script.push_str(&shell_quote(a));
        }

        let mut cmd = Command::new(shell);
        cmd.arg("-c").arg(&script);
        for (k, v) in self.base_env() {
            cmd.env(k, v);
        }
        for (k, v) in extra_env {
            cmd.env(*k, *v);
        }

        let out = cmd.output().expect("spawn wrapper");
        let rc = out.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        (rc, stdout, stderr)
    }

    pub fn read_staged(&self, pkgbase: &str) -> Option<String> {
        fs::read_to_string(self.state.join("staged").join(pkgbase)).ok()
    }

    pub fn read_accepted(&self, pkgbase: &str) -> Option<String> {
        fs::read_to_string(self.state.join("accepted").join(pkgbase)).ok()
    }

    pub fn read_manifest(&self) -> String {
        fs::read_to_string(self.state.join("last-gate")).unwrap_or_default()
    }

    pub fn records(&self) -> Vec<HttpRecord> {
        self.http.records.lock().unwrap().clone()
    }

    /// Remove the `yay` shim so `cmd_gate` must select `paru`.
    pub fn hide_yay(&self) {
        let _ = fs::remove_file(self.bin.join("yay"));
    }

    /// The fixture log is a JSON array; the last entry is always the most recent.
    pub fn helper_log(&self) -> Option<serde_json::Value> {
        log_last_by(&self.log, |v| {
            v.get("role")
                .and_then(|r| r.as_str())
                .map(|r| r == "yay" || r == "paru")
                .unwrap_or(false)
        })
    }

    pub fn makepkg_log(&self) -> Option<serde_json::Value> {
        log_last_by(&self.log, |v| {
            v.get("role")
                .and_then(|r| r.as_str())
                .map(|r| r == "makepkg")
                .unwrap_or(false)
        })
    }

    pub fn events(&self) -> Vec<String> {
        read_log(&self.log)
            .into_iter()
            .filter_map(|value| value.get("event")?.as_str().map(str::to_owned))
            .collect()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.http.stop();
    }
}

fn shell_quote(s: &str) -> String {
    if s.is_empty() || s.contains(|c: char| c.is_ascii_whitespace()) {
        format!("'{}'", s.replace('\'', "'\\''"))
    } else {
        s.to_string()
    }
}

fn read_log(log: &Path) -> Vec<serde_json::Value> {
    fs::read_to_string(log)
        .ok()
        .and_then(|content| serde_json::from_str(&content).ok())
        .unwrap_or_default()
}

fn log_last_by<F: Fn(&serde_json::Value) -> bool>(log: &Path, f: F) -> Option<serde_json::Value> {
    read_log(log).into_iter().rev().find(f)
}

// --- repository builders ---------------------------------------------------

/// Run fixture Git commands without consulting or executing user-controlled
/// configuration, hooks, helpers, pagers, or credential machinery. The fixture
/// must be deterministic even when the test runner inherits a hostile Git
/// environment from the developer's shell.
fn fixture_git() -> Command {
    let mut command = Command::new("/usr/bin/git");
    command.env_clear();
    command
        .env("HOME", "/nonexistent")
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_PAGER", "cat")
        .env("GIT_EDITOR", ":");
    command
}

/// Build the HTTP fixture repository with the requested commits and return their
/// SHAs in order. Each commit tuple is `(pkgver, extra_pkgbuild_lines)`.
pub fn build_http_repo(
    http_repo: &Path,
    pkgbase: &str,
    commits: &[(String, String)],
) -> Vec<String> {
    let src = http_repo.with_extension("src");
    let _ = fs::remove_dir_all(&src);
    fs::create_dir_all(&src).unwrap();

    assert!(fixture_git()
        .args(["-c", "init.defaultBranch=master", "init", "-q"])
        .arg(&src)
        .status()
        .unwrap()
        .success());

    let mut shas = Vec::new();
    for (version, extra) in commits {
        let pkgbuild = format!("pkgname={pkgbase}\npkgver={version}\npkgrel=1\n{extra}");
        let srcinfo = format!(
            "pkgbase = {pkgbase}\n\tpkgver = {version}\n\tpkgrel = 1\npkgname = {pkgbase}\n"
        );
        fs::write(src.join("PKGBUILD"), pkgbuild).unwrap();
        fs::write(src.join(".SRCINFO"), srcinfo).unwrap();

        let status = fixture_git()
            .arg("-C")
            .arg(&src)
            .args(["add", "-A"])
            .status()
            .unwrap();
        assert!(status.success());

        let status = fixture_git()
            .arg("-C")
            .arg(&src)
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                &format!("v{version}"),
            ])
            .status()
            .unwrap();
        assert!(status.success());

        let out = fixture_git()
            .arg("-C")
            .arg(&src)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap();
        assert!(out.status.success());
        shas.push(String::from_utf8_lossy(&out.stdout).trim().to_string());
    }

    // Replace the empty HTTP repo with a bare clone of the source.
    let _ = fs::remove_dir_all(http_repo);
    let status = fixture_git()
        .args(["clone", "--bare", "-q"])
        .arg(&src)
        .arg(http_repo)
        .status()
        .unwrap();
    assert!(status.success());

    let status = fixture_git()
        .arg("-C")
        .arg(http_repo)
        .arg("update-server-info")
        .status()
        .unwrap();
    assert!(status.success());

    shas
}

/// Like `build_http_repo`, but the package has a different pkgname from its
/// pkgbase (split package). The `pkgname` is used in PKGBUILD/.SRCINFO.
pub fn build_http_repo_split(
    http_repo: &Path,
    pkgbase: &str,
    pkgname: &str,
    commits: &[(String, String)],
) -> Vec<String> {
    let src = http_repo.with_extension("src");
    let _ = fs::remove_dir_all(&src);
    fs::create_dir_all(&src).unwrap();

    assert!(fixture_git()
        .args(["-c", "init.defaultBranch=master", "init", "-q"])
        .arg(&src)
        .status()
        .unwrap()
        .success());

    let mut shas = Vec::new();
    for (version, extra) in commits {
        let pkgbuild =
            format!("pkgbase={pkgbase}\npkgname={pkgname}\npkgver={version}\npkgrel=1\n{extra}");
        let srcinfo = format!(
            "pkgbase = {pkgbase}\n\tpkgver = {version}\n\tpkgrel = 1\npkgname = {pkgname}\n"
        );
        fs::write(src.join("PKGBUILD"), pkgbuild).unwrap();
        fs::write(src.join(".SRCINFO"), srcinfo).unwrap();

        let status = fixture_git()
            .arg("-C")
            .arg(&src)
            .args(["add", "-A"])
            .status()
            .unwrap();
        assert!(status.success());

        let status = fixture_git()
            .arg("-C")
            .arg(&src)
            .args([
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                &format!("v{version}"),
            ])
            .status()
            .unwrap();
        assert!(status.success());

        let out = fixture_git()
            .arg("-C")
            .arg(&src)
            .arg("rev-parse")
            .arg("HEAD")
            .output()
            .unwrap();
        shas.push(String::from_utf8_lossy(&out.stdout).trim().to_string());
    }

    let _ = fs::remove_dir_all(http_repo);
    let status = fixture_git()
        .args(["clone", "--bare", "-q"])
        .arg(&src)
        .arg(http_repo)
        .status()
        .unwrap();
    assert!(status.success());

    let status = fixture_git()
        .arg("-C")
        .arg(http_repo)
        .arg("update-server-info")
        .status()
        .unwrap();
    assert!(status.success());

    shas
}

// --- fake helper / makepkg / pacman ----------------------------------------

fn fake_yay_or_paru(name: &str) {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut log = serde_json::json!({
        "role": name,
        "args": args,
        "fd9_closed": fstat(9).is_err(),
        "env_caps": {},
    });

    if let Some(obj) = log.as_object_mut() {
        let caps = obj.get_mut("env_caps").unwrap().as_object_mut().unwrap();
        for var in [
            "AUR_GATE_AS_MAKEPKG",
            "AUR_GATE_TRANSACTION_ACTIVE",
            "AUR_GATE_LOCK_HELD",
            "AUR_GATE_STAGING",
        ] {
            let value = std::env::var(var)
                .ok()
                .map(serde_json::Value::String)
                .unwrap_or(serde_json::Value::Null);
            caps.insert(var.into(), value);
        }
    }

    // Non-blocking attempt on the run.lock; the wrapper should hold it.
    let lock_path = state_dir().join("run.lock");
    let lock_acquired = fs::OpenOptions::new()
        .write(true)
        .open(&lock_path)
        .map(|file| {
            let raw = file.as_raw_fd();
            let rc = unsafe { nix::libc::flock(raw, nix::libc::LOCK_EX | nix::libc::LOCK_NB) };
            rc == 0
        })
        .unwrap_or(false);
    if let Some(obj) = log.as_object_mut() {
        obj.insert("lock_acquired".into(), lock_acquired.into());
    }

    if args
        .windows(2)
        .any(|w| w[0] == "-Qua" && w[1] == "--pacman")
    {
        if let Ok(update) = std::env::var(FIXTURE_FAKE_UPDATE_ENV) {
            println!("{update}");
            std::process::exit(0);
        }
        std::process::exit(1);
    }

    append_event(&format!("helper:{name}:start"));
    let mut makepkg_bin: Option<PathBuf> = None;
    let mut mflags: Option<String> = None;
    for (i, arg) in args.iter().enumerate() {
        if arg == "--makepkg" {
            makepkg_bin = args.get(i + 1).map(PathBuf::from);
        } else if arg == "--mflags" {
            mflags = args.get(i + 1).cloned();
        }
    }

    let Some(makepkg_bin) = makepkg_bin else {
        eprintln!("{name}: --makepkg not provided");
        append_log(&log_path(), &log);
        std::process::exit(1);
    };

    let manifest = state_dir().join("last-gate");
    let content = fs::read_to_string(&manifest).unwrap_or_default();
    let mut pkgs: Vec<String> = content
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();

    if pkgs.is_empty() {
        // No gate manifest: fall back to the positional targets in the original
        // helper arg list (e.g. `yay -S repopkg` after the injected flags).
        let repo_env = std::env::var(FIXTURE_FAKE_PACMAN_SYNC_ENV).unwrap_or_default();
        let repo: HashSet<&str> = repo_env.split(',').filter(|s| !s.is_empty()).collect();
        let take_value: HashSet<&str> = [
            "--makepkg",
            "--mflags",
            "--pacman",
            "--git",
            "--gitflags",
            "--gpg",
            "--gpgflags",
            "--sudo",
            "--sudoflags",
        ]
        .into_iter()
        .collect();
        let mut skip = false;
        let mut from_args: Vec<String> = Vec::new();
        for arg in &args {
            if skip {
                skip = false;
                continue;
            }
            if take_value.contains(arg.as_str()) {
                skip = true;
                continue;
            }
            if !arg.starts_with('-') {
                from_args.push(arg.clone());
            }
        }

        // All targets are repo packages: nothing for the AUR helper to build.
        if !from_args.is_empty() && from_args.iter().all(|p| repo.contains(p.as_str())) {
            if let Some(obj) = log.as_object_mut() {
                obj.insert("repo_skip".into(), from_args.clone().into());
            }
            append_log(&log_path(), &log);
            append_event(&format!("helper:{name}:end:0"));
            std::process::exit(0);
        }

        pkgs = from_args;
    }

    if pkgs.is_empty() {
        eprintln!("{name}: no packages in manifest or args");
        append_log(&log_path(), &log);
        std::process::exit(1);
    }

    if std::env::var(FIXTURE_HELPER_PREMAKEPKG_FAILURE_ENV).is_ok() {
        if let Some(obj) = log.as_object_mut() {
            obj.insert("premakepkg_failure".into(), true.into());
        }
        eprintln!("{name}: failing before makepkg as requested");
        append_log(&log_path(), &log);
        append_event(&format!("helper:{name}:end:1"));
        std::process::exit(1);
    }

    if let Some(obj) = log.as_object_mut() {
        obj.insert("manifest".into(), pkgs.clone().into());
        obj.insert("mflags".into(), mflags.clone().into());
    }

    let cache = if name == "paru" {
        paru_cache()
    } else {
        yay_cache()
    };

    let mut guard_exit = 0i32;
    for pkgbase in &pkgs {
        let checkout = cache.join(pkgbase);
        let _ = fs::remove_dir_all(&checkout);

        let url = format!("{}/{pkgbase}.git", aur_url());
        let status = fixture_git()
            .args(["-c", "init.defaultBranch=master", "clone", "-q", "--", &url])
            .arg(&checkout)
            .status()
            .expect("fake helper clone");
        if !status.success() {
            eprintln!("{name}: clone failed for {pkgbase}");
            append_log(&log_path(), &log);
            std::process::exit(1);
        }

        if let Ok(window) = std::env::var("AUR_GATE_WINDOW_COMMIT") {
            if window_commit(&checkout, &window).is_ok() {
                if let Some(obj) = log.as_object_mut() {
                    obj.insert("window_commit".into(), window.into());
                }
            }
        }

        let mut guard = Command::new(&makepkg_bin);
        guard.current_dir(&checkout);
        // Inherit the wrapper-provided transaction capabilities exactly as a
        // real helper would; the fixture must not repair a broken wrapper.
        if let Some(m) = &mflags {
            for token in m.split_whitespace() {
                guard.arg(token);
            }
        }
        guard_exit = guard.status().map(|s| s.code().unwrap_or(1)).unwrap_or(1);
        if let Some(obj) = log.as_object_mut() {
            obj.insert("guard_exit".into(), guard_exit.into());
        }
        append_log(&log_path(), &log);

        if guard_exit != 0 {
            append_event(&format!("helper:{name}:end:{guard_exit}"));
            std::process::exit(guard_exit);
        }
        if std::env::var(FIXTURE_HELPER_POSTBUILD_FAILURE_ENV).is_ok() {
            if std::env::var(FIXTURE_UNRELATED_INSTALL_ENV).is_ok() {
                record_helper_install(&checkout);
                append_event(&format!("helper:{name}:unrelated-install"));
            }
            if let Some(obj) = log.as_object_mut() {
                obj.insert("postbuild_failure".into(), true.into());
            }
            append_log(&log_path(), &log);
            append_event(&format!("helper:{name}:end:1"));
            eprintln!("{name}: failing after build but before install as requested");
            std::process::exit(1);
        }
        record_helper_install(&checkout);
        append_event(&format!("helper:{name}:install"));
    }

    append_event(&format!("helper:{name}:end:{guard_exit}"));
    std::process::exit(guard_exit);
}

fn window_commit(checkout: &Path, payload: &str) -> anyhow::Result<()> {
    let mut pkgbuild = fs::read_to_string(checkout.join("PKGBUILD"))?;
    pkgbuild.push_str(&format!("\n# window commit marker: {}\n", payload));
    fs::write(checkout.join("PKGBUILD"), pkgbuild)?;

    let status = fixture_git()
        .arg("-C")
        .arg(checkout)
        .args(["add", "PKGBUILD"])
        .status()?;
    anyhow::ensure!(status.success());

    let out = fixture_git()
        .arg("-C")
        .arg(checkout)
        .arg("write-tree")
        .output()?;
    anyhow::ensure!(out.status.success());
    let tree = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let out = fixture_git()
        .arg("-C")
        .arg(checkout)
        .args(["rev-parse", "--verify", "HEAD"])
        .output()?;
    anyhow::ensure!(out.status.success());
    let parent = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let out = fixture_git()
        .arg("-C")
        .arg(checkout)
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.invalid")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.invalid")
        .args(["commit-tree", &tree, "-p", &parent, "-m", "window"])
        .output()?;
    anyhow::ensure!(out.status.success());
    let commit = String::from_utf8_lossy(&out.stdout).trim().to_string();

    let status = fixture_git()
        .arg("-C")
        .arg(checkout)
        .args(["reset", "--hard", &commit])
        .status()?;
    anyhow::ensure!(status.success());
    Ok(())
}

fn fake_makepkg() {
    append_event("makepkg:real:start");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut log = serde_json::json!({
        "role": "makepkg",
        "args": args,
    });

    let mut present_caps = Vec::new();
    for var in [
        "AUR_GATE_AS_MAKEPKG",
        "AUR_GATE_TRANSACTION_ACTIVE",
        "AUR_GATE_LOCK_HELD",
        "AUR_GATE_STAGING",
    ] {
        if std::env::var(var).is_ok() {
            present_caps.push(var);
        }
    }
    if !present_caps.is_empty() {
        eprintln!("makepkg: capability variables present: {present_caps:?}");
    }
    if let Some(obj) = log.as_object_mut() {
        obj.insert("capabilities_present".into(), present_caps.into());
    }

    let cwd = std::env::current_dir().expect("makepkg cwd");
    if let Some(obj) = log.as_object_mut() {
        obj.insert("cwd".into(), cwd.to_string_lossy().into_owned().into());
    }
    let pkgbuild = fs::read_to_string(cwd.join("PKGBUILD")).unwrap_or_default();
    if let Some(obj) = log.as_object_mut() {
        obj.insert("pkgbuild".into(), pkgbuild.clone().into());
    }
    let srcinfo = fs::read_to_string(cwd.join(".SRCINFO")).unwrap_or_default();
    let pkgbase = srcinfo
        .lines()
        .find(|l| l.starts_with("pkgbase ="))
        .and_then(|l| l.split_once(" = "))
        .map(|(_, v)| v.trim())
        .unwrap_or("");
    let pkgver = srcinfo
        .lines()
        .find(|l| l.starts_with("\tpkgver =") || l.starts_with("pkgver ="))
        .and_then(|l| l.split_once(" = "))
        .map(|(_, v)| v.trim())
        .unwrap_or("0");
    let pkgrel = srcinfo
        .lines()
        .find(|l| l.starts_with("\tpkgrel =") || l.starts_with("pkgrel ="))
        .and_then(|l| l.split_once(" = "))
        .map(|(_, v)| v.trim())
        .unwrap_or("0");
    let version = format!("{pkgver}-{pkgrel}");

    if let Some(obj) = log.as_object_mut() {
        obj.insert("pkgbase".into(), pkgbase.into());
        obj.insert("version".into(), version.clone().into());
    }

    append_log(&log_path(), &log);

    let status = std::env::var(FIXTURE_MAKEPKG_STATUS_ENV)
        .ok()
        .and_then(|s| s.parse::<i32>().ok())
        .unwrap_or(0);
    std::process::exit(status);
}

fn record_helper_install(checkout: &Path) {
    let srcinfo = fs::read_to_string(checkout.join(".SRCINFO")).expect("helper install .SRCINFO");
    let pkgbase = srcinfo
        .lines()
        .find(|line| line.starts_with("pkgbase ="))
        .and_then(|line| line.split_once(" = "))
        .map(|(_, value)| value.trim())
        .expect("helper install pkgbase");
    let pkgver = srcinfo
        .lines()
        .find(|line| line.starts_with("\tpkgver =") || line.starts_with("pkgver ="))
        .and_then(|line| line.split_once(" = "))
        .map(|(_, value)| value.trim())
        .expect("helper install pkgver");
    let pkgrel = srcinfo
        .lines()
        .find(|line| line.starts_with("\tpkgrel =") || line.starts_with("pkgrel ="))
        .and_then(|line| line.split_once(" = "))
        .map(|(_, value)| value.trim())
        .expect("helper install pkgrel");
    let version = format!("{pkgver}-{pkgrel}");
    let db_dir = std::env::var_os(FIXTURE_PACMAN_DB_ENV)
        .map(PathBuf::from)
        .expect("fake helper needs AUR_GATE_PACMAN_DB");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
        .max(1);

    for line in srcinfo.lines() {
        if line.starts_with("pkgname =") || line.starts_with("\tpkgname =") {
            if let Some((_, value)) = line.split_once(" = ") {
                let name = value.trim();
                let dir = db_dir.join(format!("{name}-{version}"));
                fs::create_dir_all(&dir).unwrap();
                let desc = format!(
                    "%NAME%\n{name}\n%VERSION%\n{version}\n%BASE%\n{pkgbase}\n%BUILDDATE%\n{now}\n%INSTALLDATE%\n{now}\n"
                );
                fs::write(dir.join("desc"), desc).unwrap();
            }
        }
    }
}

fn fake_pacman() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let sync = std::env::var(FIXTURE_FAKE_PACMAN_SYNC_ENV).unwrap_or_default();
    let repo: HashSet<&str> = sync.split(',').filter(|s| !s.is_empty()).collect();

    if let Some(pos) = args.iter().position(|a| a == "-Si") {
        let target = args
            .iter()
            .skip(pos + 1)
            .find(|a| *a != "--")
            .map(String::as_str)
            .unwrap_or("");
        if repo.contains(target) {
            std::process::exit(0);
        }
    }
    std::process::exit(1);
}

// --- utility accessors -----------------------------------------------------

fn aur_url() -> String {
    std::env::var("AUR_GATE_AUR_URL").unwrap_or_default()
}

fn state_dir() -> PathBuf {
    std::env::var_os("AUR_GATE_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_default()
}

fn yay_cache() -> PathBuf {
    std::env::var_os("AUR_GATE_YAY_CACHE")
        .map(PathBuf::from)
        .unwrap_or_default()
}

fn paru_cache() -> PathBuf {
    std::env::var_os("AUR_GATE_PARU_CACHE")
        .map(PathBuf::from)
        .unwrap_or_default()
}

fn log_path() -> PathBuf {
    std::env::var_os(FIXTURE_LOG_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/dev/null"))
}

fn fstat(fd: RawFd) -> Result<(), ()> {
    nix::sys::stat::fstat(fd).map(|_| ()).map_err(|_| ())
}

fn append_event(event: &str) {
    append_log(&log_path(), &serde_json::json!({ "event": event }));
}

fn append_log(path: &Path, value: &serde_json::Value) {
    if path == Path::new("/dev/null") {
        return;
    }
    let mut array: Vec<serde_json::Value> = fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    array.push(value.clone());
    fs::write(path, serde_json::to_string(&array).unwrap()).ok();
}
