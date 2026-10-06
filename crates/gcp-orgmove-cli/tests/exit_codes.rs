//! Every exit code in §3.2 is reachable and means what the spec says.

mod common;

use common::*;
use gcp_orgmove_core::Result;

fn code(r: Result<u8>) -> u8 {
    match r {
        Ok(c) => c,
        Err(e) => e.exit_code(),
    }
}

#[tokio::test]
async fn exit_0_success() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    assert_eq!(code(cli(&world(), dir.path(), &["plan"]).await.code), 0);
}

#[tokio::test]
async fn exit_1_unexpected_error_such_as_a_held_state_lock() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    let _held = gcp_orgmove_core::StateStore::open(&dir.path().join("orgmove.state.json"))
        .await
        .unwrap();
    let r = cli(&g, dir.path(), &["apply", "--yes"]).await;
    let e = r.code.unwrap_err();
    assert_eq!(e.exit_code(), 1);
    assert!(e.message.contains("another gcp-orgmove run"));
}

#[tokio::test]
async fn exit_2_invalid_manifest_or_plan() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("orgmove.yaml"), "version: 1\nbogus: true\n").unwrap();
    assert_eq!(code(cli(&world(), dir.path(), &["plan"]).await.code), 2);
    write_manifest(dir.path());
    std::fs::write(dir.path().join("orgmove.plan.json"), "{ not json").unwrap();
    assert_eq!(
        code(cli(&world(), dir.path(), &["apply", "--yes"]).await.code),
        2
    );
}

#[tokio::test]
async fn exit_3_permission_failure() {
    let dir = tempfile::tempdir().unwrap();
    let g = world();
    g.deny_caller("organizations/111", "resourcemanager.organizations.get");
    assert_eq!(
        code(
            cli(&g, dir.path(), &["init", "--source-org", "111"])
                .await
                .code
        ),
        3
    );
}

#[tokio::test]
async fn exit_4_plan_contains_blockers() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = world();
    g.deny_caller("projects/proj-aaaa", "resourcemanager.projects.move");
    assert_eq!(code(cli(&g, dir.path(), &["plan"]).await.code), 4);
    // ...and apply refuses to run it, changing nothing.
    assert_eq!(code(cli(&g, dir.path(), &["apply", "--yes"]).await.code), 4);
    assert!(g.mutating_calls().is_empty());
}

#[tokio::test]
async fn exit_5_stale_or_drifted_plan() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    std::fs::write(
        dir.path().join("orgmove.yaml"),
        format!("{MANIFEST}# changed\n"),
    )
    .unwrap();
    assert_eq!(code(cli(&g, dir.path(), &["apply", "--yes"]).await.code), 5);
}

#[tokio::test]
async fn exit_6_partial_failure() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    g.fail_next_operation("boom");
    assert_eq!(code(cli(&g, dir.path(), &["apply", "--yes"]).await.code), 6);
}

#[tokio::test]
async fn exit_7_smoke_test_failure() {
    let dir = tempfile::tempdir().unwrap();
    let text = format!("{MANIFEST}smoke_tests:\n  - name: post\n    run: \"exit 1\"\n    timeout: 5s\n    phase: [after]\n");
    std::fs::write(dir.path().join("orgmove.yaml"), text).unwrap();
    let g = world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    assert_eq!(code(cli(&g, dir.path(), &["apply", "--yes"]).await.code), 7);
}
