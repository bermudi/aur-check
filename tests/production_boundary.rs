mod support;

use std::process::Command;

use support::build_http_repo;

fn run_aur_gate(args: &[&str], envs: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_aur-gate"));
    // Production configuration is environment-driven. Start from a deliberately
    // small environment so a developer's proxy, AUR_GATE_* setting, Git config,
    // or LLM credential cannot change this boundary test's behavior.
    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/bin");
    cmd.env("LANG", "C");
    cmd.env("LC_ALL", "C");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.args(args).output().expect("spawn aur-gate test binary");
    let status = out.status.code().unwrap_or(-1);
    (
        status,
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn main_startup_rejects_invalid_llm_backend_before_dispatch() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let state = temp.path().join("state");
    let config = temp.path().join("config");

    let (rc, _, err) = run_aur_gate(
        &["check", "anything"],
        &[
            ("HOME", home.to_str().unwrap()),
            ("AUR_GATE_CONFIG", config.to_str().unwrap()),
            ("AUR_GATE_STATE_DIR", state.to_str().unwrap()),
            ("AUR_GATE_LLM_BACKEND", "bogus"),
        ],
    );

    assert_eq!(
        rc, 3,
        "invalid backend must fail startup with code 3: {err}"
    );
    assert!(
        err.contains("unsupported AUR_GATE_LLM_BACKEND") || err.contains("invalid LLM backend"),
        "unexpected startup error output: {err}"
    );
}

#[test]
fn main_check_route_reaches_production_rpc_and_clone_boundaries() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let state = temp.path().join("state");
    let yay = temp.path().join("yay");
    let paru = temp.path().join("paru");
    let config = temp.path().join("config");

    let pkgbase = "boundary-pkg-aur-gate";
    let rpc_json = format!(
        "{{\"resultcount\":1,\"results\":[{{\"Name\":\"{pkgbase}\",\"PackageBase\":\"{pkgbase}\"}}]}}"
    );
    let mut fixture = support::HttpFixture::serve(pkgbase, &rpc_json);
    let _shas = build_http_repo(&fixture.repo, pkgbase, &[("1".into(), String::new())]);

    let aur_url = format!("http://127.0.0.1:{}", fixture.port);
    let (rc, _, err) = run_aur_gate(
        &["check", pkgbase],
        &[
            ("HOME", home.to_str().unwrap()),
            ("AUR_GATE_CONFIG", config.to_str().unwrap()),
            ("AUR_GATE_STATE_DIR", state.to_str().unwrap()),
            ("AUR_GATE_AUR_URL", &aur_url),
            ("AUR_GATE_YAY_CACHE", yay.to_str().unwrap()),
            ("AUR_GATE_PARU_CACHE", paru.to_str().unwrap()),
        ],
    );

    fixture.stop();
    assert_eq!(
        rc, 2,
        "check must reach gate codepath and return review for fixture package: {err}"
    );
    let requests = fixture.records.lock().unwrap().clone();
    assert!(
        requests.iter().any(|r| r.path == "/rpc/v5/info"),
        "expected AUR RPC call to /rpc/v5/info"
    );
    let clone_info = format!("/{pkgbase}.git/info/refs");
    assert!(
        requests.iter().any(|r| r.path == clone_info),
        "expected AUR clone info request to {clone_info}"
    );
}
