mod support;

use std::fs;

use support::{build_http_repo, Fixture, FixturePacman};

fn missing_cache_http_no_baseline_requires_review_and_stages_tip() {
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
    let (rc, _out, _err) = fixture.run_aur_safe(&["check", pkgbase], &[]);
    assert_eq!(rc, 2, "no-baseline missing-cache must require review");

    let context = fs::read_to_string(fixture.state.join(format!("flag.{pkgbase}.context")))
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(context, "whole-file-review");

    let staged = fixture
        .read_staged(pkgbase)
        .expect("staged record must exist");
    let staged_sha = staged.lines().next().unwrap().split('\t').next().unwrap();
    assert_eq!(staged_sha, shas[1], "staged SHA must be origin tip B");

    assert_eq!(fixture.read_manifest().trim(), pkgbase);
    assert!(fixture.state.join(format!("flag.{pkgbase}.diff")).is_file());

    assert!(
        fixture
            .records()
            .iter()
            .any(|r| r.path.starts_with(&format!("/{pkgbase}.git/"))),
        "git must have requested the repository over HTTP"
    );
}

fn missing_cache_http_baseline_hard_delta_blocks_without_staging() {
    let pkgbase = "gatepkg";
    let rpc_json = format!(
        r#"{{"resultcount":1,"results":[{{"Name":"{pkgbase}","PackageBase":"{pkgbase}"}}]}}"#
    );
    let fixture = Fixture::new(pkgbase, &rpc_json);
    let shas = build_http_repo(
        &fixture.http_repo,
        pkgbase,
        &[
            ("1".into(), "".into()),
            ("2".into(), "npm install evil\n".into()),
        ],
    );

    let pacman = FixturePacman::new(fixture.pacman_db.clone());
    pacman.seed_installed(pkgbase, "1-1", pkgbase, 1000, 1001);
    fs::write(fixture.state.join("accepted").join(pkgbase), &shas[0]).unwrap();

    let (rc, _out, _err) = fixture.run_aur_safe(&["check", pkgbase], &[]);
    assert_eq!(rc, 1, "hard delta in missing-cache baseline must block");

    assert!(
        fixture.read_staged(pkgbase).is_none(),
        "no staged ref on hard-fail"
    );
    assert!(
        fixture.read_manifest().trim().is_empty(),
        "no manifest entry on hard-fail"
    );
    assert_eq!(
        fixture.read_accepted(pkgbase).unwrap().trim(),
        shas[0],
        "accepted must remain A"
    );
}

fn missing_cache_http_clone_failure_blocks_without_staging() {
    let pkgbase = "gatepkg";
    let rpc_json = format!(
        r#"{{"resultcount":1,"results":[{{"Name":"{pkgbase}","PackageBase":"{pkgbase}"}}]}}"#
    );
    let fixture = Fixture::new(pkgbase, &rpc_json);
    // Intentionally leave the HTTP repository empty so git clone fails.
    let (rc, _out, _err) = fixture.run_aur_safe(&["check", pkgbase], &[]);
    assert_eq!(
        rc, 1,
        "clone failure must return audit-unavailable, not review"
    );

    assert!(
        fixture.read_staged(pkgbase).is_none(),
        "no staging when clone fails"
    );
    assert!(fixture.read_manifest().trim().is_empty());
    assert!(fixture.read_accepted(pkgbase).is_none());
}

static TESTS: &[(&str, fn())] = &[
    (
        "missing_cache_http_no_baseline_requires_review_and_stages_tip",
        missing_cache_http_no_baseline_requires_review_and_stages_tip,
    ),
    (
        "missing_cache_http_baseline_hard_delta_blocks_without_staging",
        missing_cache_http_baseline_hard_delta_blocks_without_staging,
    ),
    (
        "missing_cache_http_clone_failure_blocks_without_staging",
        missing_cache_http_clone_failure_blocks_without_staging,
    ),
];

fn main() {
    support::main(TESTS);
}
