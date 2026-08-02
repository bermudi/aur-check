mod support;

use std::fs;

use support::{build_http_repo, Fixture, FixturePacman};

fn assert_pair(args: &[String], option: &str, value: &str) {
    let positions: Vec<usize> = args
        .iter()
        .enumerate()
        .filter_map(|(index, arg)| (arg == option).then_some(index))
        .collect();
    assert_eq!(
        positions.len(),
        1,
        "expected one fixed {option} option: {args:?}"
    );
    assert_eq!(
        args.get(positions[0] + 1).map(String::as_str),
        Some(value),
        "wrong fixed value for {option}: {args:?}"
    );
    assert!(
        !args
            .iter()
            .any(|arg| arg.starts_with(&format!("{option}="))),
        "conflicting equals-form {option} option: {args:?}"
    );
}

fn assert_flag_once(args: &[String], flag: &str) {
    assert_eq!(
        args.iter().filter(|arg| arg.as_str() == flag).count(),
        1,
        "expected one {flag}: {args:?}"
    );
}

fn assert_helper_caps(helper: &serde_json::Value) {
    let caps = helper["env_caps"].as_object().unwrap();
    assert_eq!(caps["AUR_SAFE_AS_MAKEPKG"], "1");
    assert_eq!(caps["AUR_SAFE_TRANSACTION_ACTIVE"], "1");
    assert!(caps["AUR_SAFE_LOCK_HELD"].is_null());
    assert!(caps["AUR_SAFE_STAGING"].is_null());
}

fn assert_transaction_events(fixture: &Fixture, helper: &str) {
    assert_eq!(
        fixture.events(),
        [
            "cli:gate:start",
            "cli:gate:end:0",
            &format!("helper:{helper}:start"),
            "cli:makepkg-guard:start",
            "makepkg:real:start",
            &format!("helper:{helper}:install"),
            &format!("helper:{helper}:end:0"),
            "cli:accept:start",
            "cli:accept:end:0",
        ],
        "gate → helper → guarded makepkg → accept order changed"
    );
}

fn wrapper_yay_gate_build_accepts_exact_audited_tip() {
    let pkgbase = "gatepkg";
    let rpc_json = format!(
        r#"{{"resultcount":1,"results":[{{"Name":"{pkgbase}","PackageBase":"{pkgbase}"}}]}}"#
    );
    let fixture = Fixture::new(pkgbase, &rpc_json);
    let shas = build_http_repo(
        &fixture.http_repo,
        pkgbase,
        &[("1".into(), "".into()), ("2".into(), "".into())],
    );

    let pacman = FixturePacman::new(fixture.pacman_db.clone());
    pacman.seed_installed(pkgbase, "1-1", pkgbase, 1000, 1001);
    fs::write(fixture.state.join("accepted").join(pkgbase), &shas[0]).unwrap();

    let (rc, _out, _err) = fixture.run_wrapper(
        "yay",
        &["-Syu"],
        &[
            ("AUR_SAFE_ALLOW_REVIEW", "1"),
            ("AUR_SAFE_FAKE_UPDATE", "gatepkg 2-1"),
        ],
    );
    assert_eq!(rc, 0, "yay wrapper transaction must return 0");

    // Accepted advanced from A to B.
    let accepted = fixture.read_accepted(pkgbase).expect("accepted must exist");
    let accepted_sha = accepted.lines().next().unwrap().split('\t').next().unwrap();
    assert_eq!(
        accepted_sha, shas[1],
        "accepted must advance to staged tip B"
    );
    assert!(
        fixture.read_staged(pkgbase).is_none(),
        "staged must be removed after accept"
    );
    assert!(
        fixture.read_manifest().trim().is_empty(),
        "manifest must be rotated"
    );

    let helper = fixture.helper_log().expect("helper log");
    assert_eq!(helper["role"], "yay");
    assert!(
        helper["fd9_closed"].as_bool().unwrap(),
        "helper child must not inherit lock fd"
    );
    assert!(
        !helper["lock_acquired"].as_bool().unwrap(),
        "helper must not acquire run.lock while wrapper holds it"
    );
    assert_helper_caps(&helper);
    let args: Vec<String> = helper["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_pair(&args, "--mflags", "--cleanbuild --force");
    assert_flag_once(&args, "-Syu");
    assert_flag_once(&args, "--rebuildall");
    assert_flag_once(&args, "--nomakepkgconf");
    assert_flag_once(&args, "--nodiffmenu");
    assert_flag_once(&args, "--noeditmenu");
    assert_pair(&args, "--pacman", "/usr/bin/pacman");
    assert_pair(&args, "--git", "/usr/bin/git");
    assert_pair(&args, "--gitflags", "");
    assert_pair(&args, "--gpg", "/usr/bin/gpg");
    assert_pair(&args, "--gpgflags", "");
    assert_pair(&args, "--sudo", "/usr/bin/sudo");
    assert_pair(&args, "--sudoflags", "");

    let mp = fixture.makepkg_log().expect("makepkg log");
    let mp_args: Vec<String> = mp["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(mp_args.len() >= 2);
    assert_eq!(mp_args[0], "--cleanbuild");
    assert_eq!(mp_args[1], "--force");
    assert!(
        mp["capabilities_present"].as_array().unwrap().is_empty(),
        "makepkg child must not inherit any capability variables"
    );
    assert_eq!(mp["pkgbase"], pkgbase);
    assert_eq!(mp["version"], "2-1");

    let fresh = pacman.find_record(pkgbase).expect("installed record");
    assert_eq!(fresh.version, "2-1");
    assert_eq!(fresh.pkgbase, pkgbase);
    assert_transaction_events(&fixture, "yay");
}

fn wrapper_paru_gate_build_accepts_exact_audited_tip() {
    let pkgbase = "gatepkg";
    let rpc_json = format!(
        r#"{{"resultcount":1,"results":[{{"Name":"{pkgbase}","PackageBase":"{pkgbase}"}}]}}"#
    );
    let fixture = Fixture::new(pkgbase, &rpc_json);
    let shas = build_http_repo(
        &fixture.http_repo,
        pkgbase,
        &[("1".into(), "".into()), ("2".into(), "".into())],
    );

    let pacman = FixturePacman::new(fixture.pacman_db.clone());
    pacman.seed_installed(pkgbase, "1-1", pkgbase, 1000, 1001);
    fs::write(fixture.state.join("accepted").join(pkgbase), &shas[0]).unwrap();
    fixture.hide_yay();

    let (rc, _out, _err) = fixture.run_wrapper(
        "paru",
        &["-Syu"],
        &[
            ("AUR_SAFE_ALLOW_REVIEW", "1"),
            ("AUR_SAFE_FAKE_UPDATE", "gatepkg 2-1"),
        ],
    );
    assert_eq!(rc, 0, "paru wrapper transaction must return 0");

    let accepted = fixture.read_accepted(pkgbase).expect("accepted must exist");
    let accepted_sha = accepted.lines().next().unwrap().split('\t').next().unwrap();
    assert_eq!(accepted_sha, shas[1]);

    let helper = fixture.helper_log().expect("helper log");
    assert_eq!(helper["role"], "paru");
    assert!(helper["fd9_closed"].as_bool().unwrap());
    assert!(!helper["lock_acquired"].as_bool().unwrap());
    assert_helper_caps(&helper);
    let args: Vec<String> = helper["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_flag_once(&args, "-Syu");
    assert_flag_once(&args, "--rebuild=all");
    assert_flag_once(&args, "--nochroot");
    assert_flag_once(&args, "--nolocalrepo");
    assert_flag_once(&args, "--skipreview");
    assert_flag_once(&args, "--nosavechanges");
    assert_pair(&args, "--mflags", "--cleanbuild --force");
    assert_pair(&args, "--pacman", "/usr/bin/pacman");
    assert_pair(&args, "--git", "/usr/bin/git");
    assert_pair(&args, "--gitflags", "");
    assert_pair(&args, "--gpg", "/usr/bin/gpg");
    assert_pair(&args, "--gpgflags", "");
    assert_pair(&args, "--sudo", "/usr/bin/sudo");
    assert_pair(&args, "--sudoflags", "");

    let mp = fixture.makepkg_log().expect("makepkg log");
    assert!(
        mp["capabilities_present"].as_array().unwrap().is_empty(),
        "makepkg child must not inherit any capability variables"
    );
    assert_eq!(mp["pkgbase"], pkgbase);
    assert_eq!(mp["version"], "2-1");
    assert_transaction_events(&fixture, "paru");
}

fn wrapper_window_commit_never_executes_makepkg_or_advances_anchor() {
    let pkgbase = "gatepkg";
    let rpc_json = format!(
        r#"{{"resultcount":1,"results":[{{"Name":"{pkgbase}","PackageBase":"{pkgbase}"}}]}}"#
    );
    let fixture = Fixture::new(pkgbase, &rpc_json);
    let shas = build_http_repo(
        &fixture.http_repo,
        pkgbase,
        &[("1".into(), "".into()), ("2".into(), "".into())],
    );

    let pacman = FixturePacman::new(fixture.pacman_db.clone());
    pacman.seed_installed(pkgbase, "1-1", pkgbase, 1000, 1001);
    fs::write(fixture.state.join("accepted").join(pkgbase), &shas[0]).unwrap();

    let (rc, _out, _err) = fixture.run_wrapper(
        "yay",
        &["-Syu"],
        &[
            ("AUR_SAFE_ALLOW_REVIEW", "1"),
            ("AUR_SAFE_FAKE_UPDATE", "gatepkg 2-1"),
            ("AUR_SAFE_WINDOW_COMMIT", "1"),
        ],
    );
    assert_ne!(rc, 0, "window-commit must fail the wrapper transaction");

    // Accepted must remain A.
    assert_eq!(
        fixture.read_accepted(pkgbase).unwrap().trim(),
        shas[0],
        "accepted must not advance after window commit"
    );

    // Staged SHA remains B (accept skipped promotion, only rotated manifest).
    let staged = fixture
        .read_staged(pkgbase)
        .expect("staged must remain after failed helper");
    let staged_sha = staged.lines().next().unwrap().split('\t').next().unwrap();
    assert_eq!(staged_sha, shas[1]);
    assert!(
        fixture.read_manifest().trim().is_empty(),
        "manifest rotated"
    );

    let helper = fixture.helper_log().expect("helper log");
    assert!(helper.get("window_commit").is_some());
    assert!(
        helper["guard_exit"].as_i64().unwrap() != 0,
        "guard must fail on checkout mismatch"
    );
    assert!(
        fixture.makepkg_log().is_none(),
        "makepkg must not run when guard rejects the checkout"
    );

    assert_helper_caps(&helper);

    // No fresh install evidence.
    let rec = pacman.find_record(pkgbase).expect("pacman record");
    assert_eq!(rec.version, "1-1", "installed version must remain A");
    assert_eq!(
        fixture.events(),
        [
            "cli:gate:start",
            "cli:gate:end:0",
            "helper:yay:start",
            "cli:makepkg-guard:start",
            "cli:makepkg-guard:end:1",
            "helper:yay:end:1",
            "cli:accept:start",
            "cli:accept:end:0",
        ],
        "a rejected checkout must skip real makepkg but still reach accept"
    );
}

static TESTS: &[(&str, fn())] = &[
    (
        "wrapper_yay_gate_build_accepts_exact_audited_tip",
        wrapper_yay_gate_build_accepts_exact_audited_tip,
    ),
    (
        "wrapper_paru_gate_build_accepts_exact_audited_tip",
        wrapper_paru_gate_build_accepts_exact_audited_tip,
    ),
    (
        "wrapper_window_commit_never_executes_makepkg_or_advances_anchor",
        wrapper_window_commit_never_executes_makepkg_or_advances_anchor,
    ),
];

fn main() {
    support::main(TESTS);
}
