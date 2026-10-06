mod common;

use common::*;
use gcp_orgmove_core::fake::FakeGcp;
use gcp_orgmove_core::state::read_state;
use gcp_orgmove_core::{Plan, Status};

const EXPORT: &str = "constraints/resourcemanager.allowedExportDestinations";
const IMPORT: &str = "constraints/resourcemanager.allowedImportSources";

/// Plan + apply, leaving proj-aaaa/bbbb in the destination.
async fn migrated(g: &FakeGcp, dir: &std::path::Path) {
    write_manifest(dir);
    assert_eq!(cli(g, dir, &["plan"]).await.code.unwrap(), 0);
    let r = cli(g, dir, &["apply", "--yes"]).await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
}

fn status_of(dir: &std::path::Path, id: &str) -> Status {
    read_state(&dir.join("orgmove.state.json"))
        .unwrap()
        .project(&id.parse().unwrap())
        .unwrap()
        .status
        .clone()
}

fn pristine(g: &FakeGcp) {
    assert!(
        g.policy_at("organizations/111", EXPORT).is_none()
            && g.policy_at("organizations/111", IMPORT).is_none()
    );
    assert!(
        g.policy_at("organizations/222", EXPORT).is_none()
            && g.policy_at("organizations/222", IMPORT).is_none()
    );
}

#[tokio::test]
async fn verify_confirms_the_move_and_marks_projects_verified() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    migrated(&g, dir.path()).await;
    let r = cli(&g, dir.path(), &["verify"]).await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    for c in ["parent", "organization", "lifecycle", "constraints"] {
        assert!(r.out.contains(c), "{c} missing: {}", r.out);
    }
    assert!(r.out.contains("2 project(s) verified"));
    assert_eq!(status_of(dir.path(), "proj-aaaa"), Status::Verified);
    // idempotent
    assert_eq!(cli(&g, dir.path(), &["verify"]).await.code.unwrap(), 0);
}

#[tokio::test]
async fn verify_before_any_apply_explains_itself() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    write_manifest(dir.path());
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    let e = cli(&g, dir.path(), &["verify"]).await.code.unwrap_err();
    assert_eq!(e.exit_code(), 2);
    assert!(e.hint.unwrap().contains("apply"));
}

#[tokio::test]
async fn verify_fails_when_a_project_is_not_where_the_plan_says() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    migrated(&g, dir.path()).await;
    // Someone moves it elsewhere afterwards.
    g.folder("21", "organizations/222");
    use gcp_orgmove_core::Gcp;
    let op = g
        .move_project(
            &"proj-aaaa".parse().unwrap(),
            &"folders/21".parse().unwrap(),
        )
        .await
        .unwrap();
    while g.poll_operation(&op).await.unwrap() == gcp_orgmove_core::OperationStatus::Running {}
    let r = cli(&g, dir.path(), &["verify", "--wait", "0s"]).await;
    assert_eq!(r.code.unwrap(), 6);
    assert!(
        r.out.contains("FAIL") && r.out.contains("expected folders/20"),
        "{}",
        r.out
    );
    assert_eq!(
        status_of(dir.path(), "proj-aaaa"),
        Status::Moved,
        "a failed verify does not mark Verified"
    );
    assert_eq!(
        status_of(dir.path(), "proj-bbbb"),
        Status::Verified,
        "the other project is still verified"
    );
}

#[tokio::test]
async fn verify_flags_projects_that_never_moved_and_rejects_bad_wait() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    write_manifest(dir.path());
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    g.fail_next_operation("boom");
    cli(&g, dir.path(), &["apply", "--yes"]).await.code.unwrap();
    let r = cli(&g, dir.path(), &["verify"]).await;
    assert_eq!(r.code.unwrap(), 6);
    assert!(r.out.contains("not moved"));
    let e = cli(&g, dir.path(), &["verify", "--wait", "5x"])
        .await
        .code
        .unwrap_err();
    assert_eq!(e.exit_code(), 2);
}

#[tokio::test]
async fn rollback_requires_a_selection() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    migrated(&g, dir.path()).await;
    let e = cli(&g, dir.path(), &["rollback", "--yes"])
        .await
        .code
        .unwrap_err();
    assert_eq!(e.exit_code(), 2);
    assert!(e.message.contains("--all"));
}

#[tokio::test]
async fn rollback_is_a_dry_run_unless_confirmed() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    migrated(&g, dir.path()).await;
    g.clear_calls();
    let r = cli(&g, dir.path(), &["rollback", "--all"]).await;
    assert_eq!(r.code.unwrap(), 0);
    assert!(
        r.out.contains("Dry run") && r.out.contains("move proj-aaaa back to folders/10"),
        "{}",
        r.out
    );
    assert!(
        r.out.contains(EXPORT) && r.out.contains(IMPORT),
        "reverse constraints are listed: {}",
        r.out
    );
    assert!(g.mutating_calls().is_empty());
    assert_eq!(g.parent_of("proj-aaaa").to_string(), "folders/20");
}

#[tokio::test]
async fn rollback_moves_everything_back_with_reverse_constraints_then_restores_them() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    migrated(&g, dir.path()).await;
    let r = cli(&g, dir.path(), &["rollback", "--all", "--yes"]).await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    // The fake rejects cross-org moves without the constraints, so success proves they were set.
    assert_eq!(g.parent_of("proj-aaaa").to_string(), "folders/10");
    assert_eq!(g.parent_of("proj-bbbb").to_string(), "folders/10");
    assert!(r.out.contains("Constraints restored"));
    pristine(&g);
    assert_eq!(status_of(dir.path(), "proj-aaaa"), Status::RolledBack);
    let st = cli(&g, dir.path(), &["status"]).await;
    assert!(st.out.contains("rolledback"), "{}", st.out);
    // running it again is a no-op
    let again = cli(&g, dir.path(), &["rollback", "--all", "--yes"]).await;
    assert_eq!(again.code.unwrap(), 0);
    assert!(again.out.contains("Nothing to roll back"));
}

#[tokio::test]
async fn rollback_single_project_leaves_the_others() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    migrated(&g, dir.path()).await;
    let r = cli(
        &g,
        dir.path(),
        &["rollback", "--project", "proj-aaaa", "--yes"],
    )
    .await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    assert_eq!(g.parent_of("proj-aaaa").to_string(), "folders/10");
    assert_eq!(g.parent_of("proj-bbbb").to_string(), "folders/20");
    assert_eq!(status_of(dir.path(), "proj-bbbb"), Status::Moved);
}

#[tokio::test]
async fn rollback_of_a_project_that_never_moved_is_an_error() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    write_manifest(dir.path());
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    g.fail_next_operation("boom");
    cli(&g, dir.path(), &["apply", "--yes"]).await.code.unwrap();
    let e = cli(
        &g,
        dir.path(),
        &["rollback", "--project", "proj-aaaa", "--yes"],
    )
    .await
    .code
    .unwrap_err();
    assert_eq!(e.exit_code(), 2);
    assert!(e.message.contains("not moved"));
    let e = cli(
        &g,
        dir.path(),
        &["rollback", "--project", "proj-cccc", "--yes"],
    )
    .await
    .code
    .unwrap_err();
    assert!(e.message.contains("no recorded state"));
}

#[tokio::test]
async fn rollback_refuses_without_a_recorded_original_parent() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    migrated(&g, dir.path()).await;
    let path = dir.path().join("orgmove.state.json");
    let mut st = read_state(&path).unwrap();
    st.projects
        .get_mut(&"proj-aaaa".parse().unwrap())
        .unwrap()
        .original_parent = None;
    std::fs::write(&path, st.to_json_bytes().unwrap()).unwrap();
    g.clear_calls();
    let e = cli(&g, dir.path(), &["rollback", "--all", "--yes"])
        .await
        .code
        .unwrap_err();
    assert_eq!(e.exit_code(), 2);
    assert!(e.message.contains("proj-aaaa") && e.message.contains("original parent"));
    assert!(
        g.mutating_calls().is_empty(),
        "nothing is changed when selection is invalid"
    );
}

#[tokio::test]
async fn rollback_failure_exits_6_restores_constraints_and_can_resume() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    migrated(&g, dir.path()).await;
    g.fail_next_operation("backend exploded");
    let r = cli(&g, dir.path(), &["rollback", "--all", "--yes"]).await;
    assert_eq!(r.code.unwrap(), 6);
    assert!(r.out.contains("FAILED") && r.out.contains("backend exploded"));
    assert!(r.out.contains("Constraints restored"));
    pristine(&g);
    let again = cli(&g, dir.path(), &["rollback", "--all", "--yes"]).await;
    assert_eq!(again.code.unwrap(), 0, "{}", again.out);
    assert_eq!(g.parent_of("proj-aaaa").to_string(), "folders/10");
    assert_eq!(g.parent_of("proj-bbbb").to_string(), "folders/10");
}

#[tokio::test]
async fn revert_remediations_removes_only_what_parity_fix_added() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    g.grant(
        "organizations/111",
        "roles/compute.viewer",
        "group:eng@x.com",
    );
    g.grant("projects/proj-aaaa", "roles/owner", "user:owner@x.com");
    write_manifest(dir.path());
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    assert_eq!(
        cli(&g, dir.path(), &["parity", "fix", "--yes"])
            .await
            .code
            .unwrap(),
        0
    );
    assert_eq!(
        cli(&g, dir.path(), &["apply", "--yes"]).await.code.unwrap(),
        0
    );
    let has_viewer = |g: &FakeGcp| {
        g.iam_at("projects/proj-aaaa")
            .bindings
            .iter()
            .any(|b| b.role.as_str() == "roles/compute.viewer")
    };
    assert!(has_viewer(&g));

    // dry run previews the revert
    let dry = cli(
        &g,
        dir.path(),
        &["rollback", "--all", "--revert-remediations"],
    )
    .await;
    assert!(
        dry.out
            .contains("revert: remove group:eng@x.com from roles/compute.viewer"),
        "{}",
        dry.out
    );
    assert!(has_viewer(&g));

    let r = cli(
        &g,
        dir.path(),
        &["rollback", "--all", "--yes", "--revert-remediations"],
    )
    .await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    assert!(r.out.contains("reverted:"));
    assert!(!has_viewer(&g), "the tool's grant is gone");
    assert!(
        g.iam_at("projects/proj-aaaa")
            .bindings
            .iter()
            .any(|b| b.role.as_str() == "roles/owner"),
        "pre-existing access untouched"
    );
    // and the project is back under the source org, which still grants it
    assert_eq!(g.parent_of("proj-aaaa").to_string(), "folders/10");
}

#[tokio::test]
async fn rollback_without_revert_keeps_remediations() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    g.grant(
        "organizations/111",
        "roles/compute.viewer",
        "group:eng@x.com",
    );
    write_manifest(dir.path());
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    cli(&g, dir.path(), &["parity", "fix", "--yes"])
        .await
        .code
        .unwrap();
    cli(&g, dir.path(), &["apply", "--yes"]).await.code.unwrap();
    cli(&g, dir.path(), &["rollback", "--all", "--yes"])
        .await
        .code
        .unwrap();
    assert!(g
        .iam_at("projects/proj-aaaa")
        .bindings
        .iter()
        .any(|b| b.role.as_str() == "roles/compute.viewer"));
}

#[tokio::test]
async fn groups_roll_back_as_a_unit() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    let text = format!("{MANIFEST}groups:\n  - name: g\n    projects: [proj-aaaa, proj-bbbb]\n")
        .replace("batch_size: 1", "batch_size: 2");
    std::fs::write(dir.path().join("orgmove.yaml"), text).unwrap();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    assert_eq!(
        cli(&g, dir.path(), &["apply", "--yes"]).await.code.unwrap(),
        0
    );
    let _ = Plan::load(&dir.path().join("orgmove.plan.json")).unwrap();
    // Selecting one member rolls back both.
    let r = cli(
        &g,
        dir.path(),
        &["rollback", "--project", "proj-aaaa", "--yes"],
    )
    .await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    assert_eq!(g.parent_of("proj-aaaa").to_string(), "folders/10");
    assert_eq!(g.parent_of("proj-bbbb").to_string(), "folders/10");
}
