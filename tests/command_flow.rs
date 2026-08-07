mod support;

use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use aur_gate::srcinfo::Pacman;
use support::{build_http_repo, build_http_repo_split, Fixture, FixturePacman};

fn accept_rejects_stale_install_then_promotes_fresh() {
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

    // Seed an accepted A and an installed A that is older than the staged timestamp will be.
    let pacman = FixturePacman::new(fixture.pacman_db.clone());
    pacman.seed_installed(pkgbase, "1-1", pkgbase, 1000, 1001);
    fs::write(fixture.state.join("accepted").join(pkgbase), &shas[0]).unwrap();

    // `check` stages B and appends to the manifest.
    let (rc, _out, _err) = fixture.run_aur_gate(&["check", pkgbase], &[]);
    assert_eq!(rc, 2, "clean missing-cache baseline must require review");
    assert_eq!(
        fixture
            .read_staged(pkgbase)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .split('\t')
            .next()
            .unwrap(),
        shas[1]
    );
    assert_eq!(fixture.read_manifest().trim(), pkgbase);

    // Provide a helper-side checkout (normally created by the helper build). The
    // accept logic must find it so it can read the staged .SRCINFO.
    let cache_dir = fixture.yay_cache.join(pkgbase);
    let url = format!("{}/{pkgbase}.git", fixture.aur_url);
    let status = Command::new("/usr/bin/git")
        .args(["-c", "init.defaultBranch=master", "clone", "-q", "--", &url])
        .arg(&cache_dir)
        .status()
        .unwrap();
    assert!(status.success());

    // Accept with stale installed A must skip promotion.
    let (rc, _out, _err) = fixture.run_aur_gate(&["accept"], &[]);
    assert_eq!(rc, 0, "accept must return 0 even when skipping");
    assert_eq!(
        fixture.read_accepted(pkgbase).unwrap().trim(),
        shas[0],
        "accepted must stay A when installed evidence is stale"
    );
    assert!(
        fixture.read_staged(pkgbase).is_some(),
        "staged must remain after skip"
    );

    // Now write fresh installed B and re-run accept.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    pacman.seed_installed(pkgbase, "2-1", pkgbase, now, now);
    fs::write(fixture.state.join("last-gate"), pkgbase).unwrap();
    let (rc, _out, _err) = fixture.run_aur_gate(&["accept"], &[]);
    assert_eq!(rc, 0);
    assert_eq!(
        fixture
            .read_accepted(pkgbase)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .split('\t')
            .next()
            .unwrap(),
        shas[1],
        "accepted must advance to B once install evidence is fresh"
    );
    assert!(fixture.read_staged(pkgbase).is_none());
    assert!(fixture.read_manifest().trim().is_empty());
}

fn explicit_aur_install_yay_audits_builds_accepts() {
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

    // No prior accepted anchor: first-contact whole-candidate review.
    // `cmd_audit` stages the candidate and exits 0 when allowed to proceed.
    let (rc, _out, _err) =
        fixture.run_wrapper("yay", &["-S", pkgbase], &[("AUR_GATE_ALLOW_REVIEW", "1")]);
    assert_eq!(rc, 0, "yay -S <aur pkg> must audit, build, and accept");

    let accepted = fixture.read_accepted(pkgbase).expect("accepted must exist");
    let accepted_sha = accepted.lines().next().unwrap().split('\t').next().unwrap();
    assert_eq!(
        accepted_sha, shas[1],
        "accepted must be the staged origin tip"
    );
    assert!(fixture.read_staged(pkgbase).is_none());
    assert!(fixture.read_manifest().trim().is_empty());
    assert!(fixture.makepkg_log().is_some(), "guarded makepkg must run");
    let helper = fixture.helper_log().expect("helper log");
    assert!(
        helper["args"]
            .as_array()
            .unwrap()
            .iter()
            .any(|arg| arg.as_str() == Some(pkgbase)),
        "the explicit AUR target must be forwarded to yay"
    );
    assert_eq!(
        fixture.events(),
        [
            "cli:state-dir:start",
            "cli:state-dir:end:0",
            "cli:init-state:start",
            "cli:init-state:end:0",
            "cli:begin:start",
            "cli:begin:end:0",
            "cli:audit:start",
            "cli:audit:end:0",
            "helper:yay:start",
            "cli:makepkg-guard:start",
            "makepkg:real:start",
            "helper:yay:install",
            "helper:yay:end:0",
            "cli:accept:start",
            "cli:accept:end:0",
        ],
        "explicit AUR installs must audit before helper execution"
    );
}

fn audit_first_contact_zero_hit_requires_review() {
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

    // No prior accepted anchor and a clean PKGBUILD: deterministic rules cannot
    // see inside source tarballs, so a first-contact audit must require human
    // review even with zero rule hits (Finding H10 / #31). Without
    // AUR_GATE_ALLOW_REVIEW the non-interactive audit returns 2 and must NOT
    // stage the candidate.
    let (rc, _out, _err) = fixture.run_aur_gate(&["audit", pkgbase], &[]);
    assert_eq!(
        rc, 2,
        "first-contact zero-hit audit must require review, not auto-proceed"
    );
    assert!(
        fixture.read_staged(pkgbase).is_none(),
        "first-contact audit must not stage without consent"
    );
    assert!(
        fixture.read_manifest().trim().is_empty(),
        "first-contact audit must not append to the manifest without consent"
    );
    // Whole-candidate evidence must be stashed for human review with a distinct
    // first-contact context so `aur-gate explain` can describe the reason.
    let context = fs::read_to_string(fixture.state.join(format!("flag.{pkgbase}.context")))
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(
        context, "audit-first-contact",
        "first-contact zero-hit audit must stash whole-candidate evidence"
    );
    assert!(fixture.state.join(format!("flag.{pkgbase}.diff")).is_file());

    // With explicit consent, the same first-contact audit proceeds and stages
    // the exact audited tip.
    let (rc, _out, _err) =
        fixture.run_aur_gate(&["audit", pkgbase], &[("AUR_GATE_ALLOW_REVIEW", "1")]);
    assert_eq!(rc, 0, "consented first-contact audit must proceed");
    let staged = fixture
        .read_staged(pkgbase)
        .expect("consented audit must stage");
    assert_eq!(staged.split('\t').next().unwrap(), shas[1]);
    assert_eq!(fixture.read_manifest().trim(), pkgbase);
}

fn split_pkgname_to_pkgbase_transaction() {
    let pkgbase = "foobase";
    let pkgname = "foo-bin";
    let rpc_json = format!(
        r#"{{"resultcount":1,"results":[{{"Name":"{pkgname}","PackageBase":"{pkgbase}"}}]}}"#
    );
    let fixture = Fixture::new(pkgbase, &rpc_json);
    let shas = build_http_repo_split(
        &fixture.http_repo,
        pkgbase,
        pkgname,
        &[("1".into(), "".into()), ("2".into(), "".into())],
    );

    let (rc, _out, _err) =
        fixture.run_wrapper("yay", &["-S", pkgname], &[("AUR_GATE_ALLOW_REVIEW", "1")]);
    assert_eq!(
        rc, 0,
        "split package install must resolve pkgbase and accept"
    );

    let accepted = fixture.read_accepted(pkgbase).expect("accepted must exist");
    let accepted_sha = accepted.lines().next().unwrap().split('\t').next().unwrap();
    assert_eq!(accepted_sha, shas[1]);

    // The installed record is under the pkgname, while the anchor key is the pkgbase.
    let pacman = FixturePacman::new(fixture.pacman_db.clone());
    let rec = pacman
        .local_record(pkgname)
        .expect("foo-bin must be installed");
    assert_eq!(rec.name, pkgname);
    assert_eq!(rec.pkgbase, pkgbase);
    assert_eq!(rec.version, "2-1");
    let helper = fixture.helper_log().expect("helper log");
    assert!(
        helper["args"]
            .as_array()
            .unwrap()
            .iter()
            .any(|arg| arg.as_str() == Some(pkgname)),
        "the split pkgname, not only its pkgbase, must be forwarded to yay"
    );
    assert!(fixture.read_accepted(pkgname).is_none());
    assert!(fixture.read_staged(pkgbase).is_none());
    assert!(fixture.read_manifest().trim().is_empty());
    assert_eq!(
        fixture.events(),
        [
            "cli:state-dir:start",
            "cli:state-dir:end:0",
            "cli:init-state:start",
            "cli:init-state:end:0",
            "cli:begin:start",
            "cli:begin:end:0",
            "cli:audit:start",
            "cli:audit:end:0",
            "helper:yay:start",
            "cli:makepkg-guard:start",
            "makepkg:real:start",
            "helper:yay:install",
            "helper:yay:end:0",
            "cli:accept:start",
            "cli:accept:end:0",
        ]
    );
}

fn helper_failure_before_makepkg_leaves_anchor_unchanged() {
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

    // Force the helper to fail before it reaches makepkg.
    let (rc, _out, _err) = fixture.run_wrapper(
        "yay",
        &["-Syu"],
        &[
            ("AUR_GATE_ALLOW_REVIEW", "1"),
            ("AUR_GATE_FAKE_UPDATE", "gatepkg 2-1"),
            ("AUR_GATE_HELPER_PREMAKEPKG_FAILURE", "1"),
        ],
    );
    assert_eq!(rc, 1, "helper failure must abort the wrapper");

    let helper = fixture.helper_log().expect("helper log must exist");
    assert!(
        helper.get("premakepkg_failure").is_some(),
        "helper must fail before makepkg"
    );
    assert!(fixture.makepkg_log().is_none(), "makepkg must not run");
    assert_eq!(
        fixture.read_accepted(pkgbase).unwrap().trim(),
        shas[0],
        "accepted must stay A when helper fails"
    );
    let staged = fixture
        .read_staged(pkgbase)
        .expect("audited B remains staged");
    assert_eq!(staged.split('\t').next().unwrap(), shas[1]);
    assert!(
        fixture.read_manifest().trim().is_empty(),
        "accept must run and rotate the manifest after helper failure"
    );
    assert_eq!(
        fixture.events(),
        [
            "cli:state-dir:start",
            "cli:state-dir:end:0",
            "cli:init-state:start",
            "cli:init-state:end:0",
            "cli:gate:start",
            "cli:gate:end:0",
            "helper:yay:start",
            "helper:yay:end:1",
            "cli:abort:start",
            "cli:abort:end:0",
        ]
    );
}

fn failed_helper_never_promotes_even_with_fresh_matching_evidence() {
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
            ("AUR_GATE_ALLOW_REVIEW", "1"),
            ("AUR_GATE_FAKE_UPDATE", "gatepkg 2-1"),
            ("AUR_GATE_HELPER_POSTBUILD_FAILURE", "1"),
            ("AUR_GATE_UNRELATED_INSTALL_ON_FAILURE", "1"),
        ],
    );
    assert_eq!(rc, 1);
    assert!(fixture.makepkg_log().is_some(), "build must complete");
    assert_eq!(
        pacman.find_record(pkgbase).unwrap().version,
        "2-1",
        "matching fresh evidence exists independently of helper success"
    );
    assert_eq!(fixture.read_accepted(pkgbase).unwrap().trim(), shas[0]);
    let staged = fixture.read_staged(pkgbase).expect("B remains staged");
    assert_eq!(staged.split('\t').next().unwrap(), shas[1]);
    assert!(fixture.read_manifest().trim().is_empty());
    assert_eq!(
        fixture.events(),
        [
            "cli:state-dir:start",
            "cli:state-dir:end:0",
            "cli:init-state:start",
            "cli:init-state:end:0",
            "cli:gate:start",
            "cli:gate:end:0",
            "helper:yay:start",
            "cli:makepkg-guard:start",
            "makepkg:real:start",
            "helper:yay:unrelated-install",
            "helper:yay:end:1",
            "cli:abort:start",
            "cli:abort:end:0",
        ],
        "a successful build is not installation evidence"
    );
}

fn wrapper_shows_accept_failure() {
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

    let (rc, _out, err) = fixture.run_wrapper(
        "yay",
        &["-Syu"],
        &[
            ("AUR_GATE_ALLOW_REVIEW", "1"),
            ("AUR_GATE_FAKE_UPDATE", "gatepkg 2-1"),
            ("AUR_GATE_TEST_ACCEPT_FAILURE", "1"),
        ],
    );
    // The wrapper prints accept failure to stderr even when the helper itself
    // completed; public exit code is the helper's result.
    assert_eq!(
        rc, 0,
        "helper must succeed; accept failure is surfaced in stderr"
    );
    assert!(
        err.contains("accept failed"),
        "wrapper must surface accept failure (err: {err})"
    );
    assert_eq!(
        fixture.read_accepted(pkgbase).unwrap().trim(),
        shas[0],
        "accepted must stay A when accept fails"
    );
    let staged = fixture.read_staged(pkgbase).expect("B must remain staged");
    assert_eq!(staged.split('\t').next().unwrap(), shas[1]);
    assert_eq!(fixture.read_manifest().trim(), pkgbase);
    assert!(fixture.makepkg_log().is_some(), "helper build must succeed");
    assert_eq!(
        fixture.events(),
        [
            "cli:state-dir:start",
            "cli:state-dir:end:0",
            "cli:init-state:start",
            "cli:init-state:end:0",
            "cli:gate:start",
            "cli:gate:end:0",
            "helper:yay:start",
            "cli:makepkg-guard:start",
            "makepkg:real:start",
            "helper:yay:install",
            "helper:yay:end:0",
            "cli:accept:start",
            "cli:accept:simulated-failure",
        ],
        "accept failure must happen after a successful guarded build"
    );
}

fn wrapper_uses_config_file_state_dir_for_transaction_lock() {
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
    fs::write(
        &fixture.config_file,
        format!("AUR_GATE_STATE_DIR={}\n", fixture.state.display()),
    )
    .unwrap();

    let script = format!("source {}\nyay -Syu", fixture.wrapper_sh.display());
    let mut command = Command::new("/bin/bash");
    command.arg("-c").arg(script);
    for (key, value) in fixture.base_env() {
        if key != "AUR_GATE_STATE_DIR" {
            command.env(key, value);
        }
    }
    command.env_remove("AUR_GATE_STATE_DIR");
    command.env("AUR_GATE_ALLOW_REVIEW", "1");
    command.env("AUR_GATE_FAKE_UPDATE", "gatepkg 2-1");
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "config-file state transaction failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fixture
            .read_accepted(pkgbase)
            .unwrap()
            .split('\t')
            .next()
            .unwrap(),
        shas[1]
    );
}

fn repo_package_skips_aur_audit_in_explicit_install() {
    let pkgbase = "gatepkg";
    let repo_pkg = "repopkg";
    let rpc_json = format!(
        r#"{{"resultcount":1,"results":[{{"Name":"{pkgbase}","PackageBase":"{pkgbase}"}}]}}"#
    );
    let fixture = Fixture::new(pkgbase, &rpc_json);
    let _shas = build_http_repo(
        &fixture.http_repo,
        pkgbase,
        &[("1".into(), "".into()), ("2".into(), "".into())],
    );

    // Mark `repopkg` as a repo package so `pacman -Si` returns 0. The wrapper
    // should skip AUR audit for it, leaving the manifest empty and returning 0.
    let (rc, _out, _err) = fixture.run_wrapper(
        "yay",
        &["-S", repo_pkg],
        &[("AUR_GATE_FAKE_PACMAN_SYNC", repo_pkg)],
    );
    assert_eq!(rc, 0, "wrapper must pass through repo packages");
    assert!(fixture.read_manifest().trim().is_empty());
    assert!(fixture
        .state
        .join("staged")
        .read_dir()
        .unwrap()
        .next()
        .is_none());
    assert_eq!(
        fixture.events(),
        [
            "cli:state-dir:start",
            "cli:state-dir:end:0",
            "cli:init-state:start",
            "cli:init-state:end:0",
            "cli:begin:start",
            "cli:begin:end:0",
            "helper:yay:start",
            "helper:yay:end:0",
            "cli:accept:start",
            "cli:accept:end:0",
        ],
        "repo packages must skip the AUR audit command entirely"
    );
}

static TESTS: &[(&str, fn())] = &[
    (
        "accept_rejects_stale_install_then_promotes_fresh",
        accept_rejects_stale_install_then_promotes_fresh,
    ),
    (
        "explicit_aur_install_yay_audits_builds_accepts",
        explicit_aur_install_yay_audits_builds_accepts,
    ),
    (
        "audit_first_contact_zero_hit_requires_review",
        audit_first_contact_zero_hit_requires_review,
    ),
    (
        "split_pkgname_to_pkgbase_transaction",
        split_pkgname_to_pkgbase_transaction,
    ),
    (
        "helper_failure_before_makepkg_leaves_anchor_unchanged",
        helper_failure_before_makepkg_leaves_anchor_unchanged,
    ),
    (
        "failed_helper_never_promotes_even_with_fresh_matching_evidence",
        failed_helper_never_promotes_even_with_fresh_matching_evidence,
    ),
    ("wrapper_shows_accept_failure", wrapper_shows_accept_failure),
    (
        "wrapper_uses_config_file_state_dir_for_transaction_lock",
        wrapper_uses_config_file_state_dir_for_transaction_lock,
    ),
    (
        "repo_package_skips_aur_audit_in_explicit_install",
        repo_package_skips_aur_audit_in_explicit_install,
    ),
    (
        "cached_empty_diff_stages_the_candidate",
        cached_empty_diff_stages_the_candidate,
    ),
    (
        "cached_hard_fail_restores_helper_remote",
        cached_hard_fail_restores_helper_remote,
    ),
];

fn cached_empty_diff_stages_the_candidate() {
    let pkgbase = "gatepkg";
    let rpc_json = format!(
        r#"{{"resultcount":1,"results":[{{"Name":"{pkgbase}","PackageBase":"{pkgbase}"}}]}}"#
    );
    let fixture = Fixture::new(pkgbase, &rpc_json);

    // Build one commit, then add an empty commit with the same tree so the
    // candidate has a different SHA but no changed paths. This is the
    // version-bump-only path that previously returned 0 without staging.
    let shas = build_http_repo(&fixture.http_repo, pkgbase, &[("1".into(), "".into())]);
    let src = fixture.http_repo.with_extension("src");
    assert!(Command::new("/usr/bin/git")
        .arg("-C")
        .arg(&src)
        .args(["commit", "--allow-empty", "-qm", "v2"])
        .status()
        .unwrap()
        .success());
    let status = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(&src)
        .args(["push", "-q", fixture.http_repo.to_str().unwrap(), "master"])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(Command::new("/usr/bin/git")
        .arg("-C")
        .arg(&fixture.http_repo)
        .arg("update-server-info")
        .status()
        .unwrap()
        .success());
    let out = Command::new("/usr/bin/git")
        .arg("-C")
        .arg(&fixture.http_repo)
        .args(["rev-parse", "refs/heads/master"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let candidate_sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_ne!(
        candidate_sha, shas[0],
        "empty commit must have a different SHA"
    );

    // Clone the remote into the yay cache so the cached path is used.
    let cache_dir = fixture.yay_cache.join(pkgbase);
    let url = format!("{}/{pkgbase}.git", fixture.aur_url);
    let status = Command::new("/usr/bin/git")
        .args(["-c", "init.defaultBranch=master", "clone", "-q", "--", &url])
        .arg(&cache_dir)
        .status()
        .unwrap();
    assert!(status.success());

    // Accepted is the first commit; the remote tip is the empty v2 commit.
    fs::write(fixture.state.join("accepted").join(pkgbase), &shas[0]).unwrap();

    let (rc, _out, _err) = fixture.run_aur_gate(&["check", pkgbase], &[]);
    assert_eq!(rc, 0, "version-bump-only cached update must be clean");
    assert_eq!(
        fixture
            .read_staged(pkgbase)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .split('\t')
            .next()
            .unwrap(),
        candidate_sha,
        "empty diff must still stage the candidate SHA"
    );
    assert_eq!(fixture.read_manifest().trim(), pkgbase);
}

fn cached_hard_fail_restores_helper_remote() {
    let pkgbase = "gatepkg";
    let rpc_json = format!(
        r#"{{"resultcount":1,"results":[{{"Name":"{pkgbase}","PackageBase":"{pkgbase}"}}]}}"#
    );
    let fixture = Fixture::new(pkgbase, &rpc_json);

    // Version 2 adds an `install=` line, which is a hard-fail rule.
    let shas = build_http_repo(
        &fixture.http_repo,
        pkgbase,
        &[
            ("1".into(), "".into()),
            ("2".into(), "install=myhook\n".into()),
        ],
    );

    // Clone the remote into the yay cache so the cached path is used.
    let cache_dir = fixture.yay_cache.join(pkgbase);
    let url = format!("{}/{pkgbase}.git", fixture.aur_url);
    let status = Command::new("/usr/bin/git")
        .args(["-c", "init.defaultBranch=master", "clone", "-q", "--", &url])
        .arg(&cache_dir)
        .status()
        .unwrap();
    assert!(status.success());

    fs::write(fixture.state.join("accepted").join(pkgbase), &shas[0]).unwrap();

    let (rc, _out, _err) = fixture.run_aur_gate(&["check", pkgbase], &[]);
    assert_eq!(rc, 1, "added install= line must hard-fail");

    // The helper checkout must have its remote restored even on hard-fail.
    let config = fs::read_to_string(cache_dir.join(".git/config")).unwrap();
    assert!(
        config.contains(r#"remote "origin""#),
        "helper remote must be restored after a hard-fail gate"
    );
}

fn main() {
    support::main(TESTS);
}
