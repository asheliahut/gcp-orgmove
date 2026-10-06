mod common;

use common::*;
use gcp_orgmove_core::fake::FakeGcp;
use gcp_orgmove_core::{Gcp, Plan, State};

fn gap_world() -> FakeGcp {
    let g = world();
    g.grant(
        "organizations/111",
        "roles/compute.viewer",
        "group:eng@x.com",
    );
    g.grant("folders/10", "roles/editor", "user:lead@x.com");
    g
}

fn plan_of(dir: &std::path::Path) -> Plan {
    Plan::load(&dir.join("orgmove.plan.json")).unwrap()
}

fn state_of(dir: &std::path::Path) -> State {
    gcp_orgmove_core::state::read_state(&dir.join("orgmove.state.json")).unwrap()
}

#[tokio::test]
async fn plan_reports_gaps_and_apply_refuses_until_fixed() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = gap_world();
    let r = cli(&g, dir.path(), &["plan"]).await;
    assert_eq!(r.code.unwrap(), 0, "gaps are not blockers");
    let plan = plan_of(dir.path());
    assert_eq!(plan.summary.gaps, 4, "2 grants x 2 projects");
    assert!(r.out.contains("will not under"));

    let e = cli(&g, dir.path(), &["apply", "--yes"])
        .await
        .code
        .unwrap_err();
    assert_eq!(e.exit_code(), 4);
    assert!(e.message.contains("unresolved gap"));
    assert!(e.hint.unwrap().contains("parity fix"));
}

#[tokio::test]
async fn parity_fix_is_dry_run_by_default() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = gap_world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    g.clear_calls();
    let r = cli(&g, dir.path(), &["parity", "fix"]).await;
    assert_eq!(r.code.unwrap(), 0);
    assert!(
        r.out.contains("would apply")
            && r.out
                .contains("grant roles/compute.viewer to group:eng@x.com on projects/proj-aaaa")
    );
    assert!(r.out.contains("Dry run"));
    assert!(g.mutating_calls().is_empty());
}

#[tokio::test]
async fn fix_then_apply_moves_projects_with_access_already_in_place() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = gap_world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();

    let fix = cli(&g, dir.path(), &["parity", "fix", "--yes"]).await;
    assert_eq!(fix.code.unwrap(), 0, "{}", fix.out);
    assert!(fix.out.contains("All gaps are resolved"));
    for p in ["proj-aaaa", "proj-bbbb"] {
        let pol = g.iam_at(&format!("projects/{p}"));
        assert!(pol
            .bindings
            .iter()
            .any(|b| b.role.as_str() == "roles/compute.viewer"
                && b.members.contains("group:eng@x.com")));
    }
    let st = state_of(dir.path());
    assert_eq!(st.applied.len(), 4);
    assert_eq!(
        format!("{:?}", st.projects.values().next().unwrap().status.kind()),
        "ParityFixed"
    );

    let apply = cli(&g, dir.path(), &["apply", "--yes"]).await;
    assert_eq!(apply.code.unwrap(), 0, "{}", apply.out);
    assert_eq!(g.parent_of("proj-aaaa").to_string(), "folders/20");

    // After the move the project still has the access it had before.
    let eff = g
        .get_effective_iam(&"projects/proj-aaaa".parse().unwrap())
        .await
        .unwrap();
    assert!(eff
        .grants
        .iter()
        .any(|x| x.grant.member == "group:eng@x.com"
            && x.grant.role.as_str() == "roles/compute.viewer"));
    assert!(eff
        .grants
        .iter()
        .any(|x| x.grant.member == "user:lead@x.com" && x.grant.role.as_str() == "roles/editor"));
}

#[tokio::test]
async fn parity_check_reflects_live_changes_and_keeps_preflight_findings() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = gap_world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    assert_eq!(plan_of(dir.path()).summary.gaps, 4);

    // Someone grants the access at the destination in the meantime.
    g.grant("folders/20", "roles/compute.viewer", "group:eng@x.com");
    let r = cli(&g, dir.path(), &["parity", "check"]).await;
    assert_eq!(r.code.unwrap(), 0);
    assert_eq!(plan_of(dir.path()).summary.gaps, 2);

    // --project only refreshes that project
    g.grant("folders/20", "roles/editor", "user:lead@x.com");
    cli(
        &g,
        dir.path(),
        &["parity", "check", "--project", "proj-aaaa"],
    )
    .await
    .code
    .unwrap();
    let plan = plan_of(dir.path());
    let gaps = |id: &str| {
        plan.project(&id.parse().unwrap())
            .unwrap()
            .findings
            .iter()
            .filter(|f| f.severity == gcp_orgmove_core::Severity::Gap)
            .count()
    };
    assert_eq!(gaps("proj-aaaa"), 0);
    assert_eq!(gaps("proj-bbbb"), 1, "other project not refreshed");
}

#[tokio::test]
async fn parity_check_keeps_blockers_from_the_planner() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = gap_world();
    g.deny_caller("projects/proj-aaaa", "resourcemanager.projects.move");
    assert_eq!(cli(&g, dir.path(), &["plan"]).await.code.unwrap(), 4);
    let r = cli(&g, dir.path(), &["parity", "check"]).await;
    assert_eq!(
        r.code.unwrap(),
        4,
        "preflight blocker survives a parity refresh"
    );
}

#[tokio::test]
async fn folder_mode_requires_consent_and_grants_on_the_landing_folder() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = gap_world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    let e = cli(
        &g,
        dir.path(),
        &["parity", "fix", "--iam-fix", "folder", "--yes"],
    )
    .await
    .code
    .unwrap_err();
    assert_eq!(e.exit_code(), 2);
    assert!(g.mutating_calls().is_empty());

    let r = cli(
        &g,
        dir.path(),
        &[
            "parity",
            "fix",
            "--iam-fix",
            "folder",
            "--yes",
            "--yes-widen-access",
        ],
    )
    .await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    assert!(g
        .iam_at("folders/20")
        .bindings
        .iter()
        .any(|b| b.role.as_str() == "roles/compute.viewer"));
    assert!(
        r.out.contains("All gaps are resolved"),
        "folder-scope fixes still resolve the gaps: {}",
        r.out
    );
    assert_eq!(
        cli(&g, dir.path(), &["apply", "--yes"]).await.code.unwrap(),
        0
    );
}

#[tokio::test]
async fn gaps_can_be_accepted_in_the_manifest_instead() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = world();
    g.grant(
        "organizations/111",
        "roles/compute.viewer",
        "group:eng@x.com",
    );
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    let plan = plan_of(dir.path());
    let accept: String = plan
        .projects
        .iter()
        .flat_map(|p| p.findings.iter())
        .map(|f| format!("    - finding: \"{}\"\n      reason: \"reviewed\"\n", f.id))
        .collect();
    let edited = format!("{MANIFEST}parity:\n  accept:\n{accept}");
    std::fs::write(dir.path().join("orgmove.yaml"), edited).unwrap();
    // manifest changed => replan, then apply goes through without fixing anything
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    let r = cli(&g, dir.path(), &["apply", "--yes"]).await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
}

#[tokio::test]
async fn policy_override_flag_is_gated() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = gap_world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    let e = cli(
        &g,
        dir.path(),
        &["parity", "fix", "--policy-fix", "project-override"],
    )
    .await
    .code
    .unwrap_err();
    assert!(e.message.contains("--allow-policy-overrides"));
    let e = cli(
        &g,
        dir.path(),
        &["parity", "fix", "--iam-fix", "everywhere"],
    )
    .await
    .code
    .unwrap_err();
    assert_eq!(e.exit_code(), 2);
}

#[tokio::test]
async fn fix_failure_reports_exit_6_and_continues() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = gap_world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    g.inject_fault(
        "get_iam",
        gcp_orgmove_core::Error::new(gcp_orgmove_core::ErrorKind::PermissionDenied, "denied"),
    );
    let r = cli(&g, dir.path(), &["parity", "fix", "--yes"]).await;
    assert_eq!(r.code.unwrap(), 6);
    assert!(r.out.contains("FAILED") && r.out.contains("applied"));
    assert!(r.out.contains("gap(s) remain"));
    // Re-running finishes the job (idempotent).
    let again = cli(&g, dir.path(), &["parity", "fix", "--yes"]).await;
    assert_eq!(again.code.unwrap(), 0);
    assert!(again.out.contains("All gaps are resolved"));
}

fn manifest_with_smoke(before: &str, after: &str) -> String {
    format!(
        "{MANIFEST}smoke_tests:\n  - name: pre\n    run: \"{before}\"\n    timeout: 5s\n    phase: [before]\n  - name: post\n    run: \"{after}\"\n    timeout: 5s\n    phase: [after]\n"
    )
}

#[tokio::test]
async fn smoke_tests_run_around_the_move_and_are_shown_by_status() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("orgmove.yaml"),
        manifest_with_smoke("true", "test -n \\\"$ORGMOVE_PROJECT\\\""),
    )
    .unwrap();
    let g = world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    let dry = cli(&g, dir.path(), &["apply"]).await;
    assert!(dry.out.contains("smoke test"), "{}", dry.out);
    let r = cli(&g, dir.path(), &["apply", "--yes"]).await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    let st = cli(&g, dir.path(), &["status"]).await;
    assert!(
        st.out.contains("Smoke tests")
            && st.out.contains("pre")
            && st.out.contains("post")
            && st.out.contains("pass"),
        "{}",
        st.out
    );
}

#[tokio::test]
async fn failing_before_test_moves_nothing_and_exits_7() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("orgmove.yaml"),
        manifest_with_smoke("exit 1", "true"),
    )
    .unwrap();
    let g = world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    let e = cli(&g, dir.path(), &["apply", "--yes"])
        .await
        .code
        .unwrap_err();
    assert_eq!(e.exit_code(), 7);
    assert!(e.message.contains("pre") && e.message.contains("before"));
    assert_eq!(g.calls_to("move_project"), 0);
    assert!(
        g.policy_at(
            "organizations/111",
            "constraints/resourcemanager.allowedExportDestinations"
        )
        .is_none(),
        "constraints restored"
    );
}

#[tokio::test]
async fn failing_after_test_halts_exits_7_and_prints_the_rollback_command() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("orgmove.yaml"),
        manifest_with_smoke("true", "exit 1"),
    )
    .unwrap();
    let g = world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    let r = cli(&g, dir.path(), &["apply", "--yes"]).await;
    assert_eq!(r.code.unwrap(), 7);
    assert!(
        r.out.contains("Smoke test failed")
            && r.out.contains("gcp-orgmove rollback --project proj-aaaa"),
        "{}",
        r.out
    );
    assert_eq!(
        g.calls_to("move_project"),
        1,
        "batch halted after the first failure"
    );
}

#[tokio::test]
async fn skip_smoke_tests_ignores_failing_tests() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("orgmove.yaml"),
        manifest_with_smoke("exit 1", "exit 1"),
    )
    .unwrap();
    let g = world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    let r = cli(&g, dir.path(), &["apply", "--yes", "--skip-smoke-tests"]).await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
}

fn role(org: &str, perms: &[&str]) -> gcp_orgmove_core::CustomRole {
    gcp_orgmove_core::CustomRole {
        name: gcp_orgmove_core::RoleName::new(format!("organizations/{org}/roles/deployer")),
        title: "Deployer".into(),
        description: String::new(),
        permissions: perms.iter().map(|p| p.to_string()).collect(),
        stage: gcp_orgmove_core::RoleStage::Ga,
    }
}

fn roles_world() -> FakeGcp {
    let g = world();
    g.custom_role(role("111", &["compute.instances.get"]));
    g.grant(
        "projects/proj-aaaa",
        "organizations/111/roles/deployer",
        "serviceAccount:ci@proj-aaaa.iam.gserviceaccount.com",
    );
    g.grant(
        "organizations/111",
        "organizations/111/roles/deployer",
        "group:release@x.com",
    );
    g
}

fn recreate_manifest() -> String {
    format!("{MANIFEST}parity:\n  custom_roles: recreate\n")
}

#[tokio::test]
async fn custom_role_bindings_are_recreated_in_the_destination_before_the_move() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("orgmove.yaml"), recreate_manifest()).unwrap();
    let g = roles_world();
    let plan = cli(&g, dir.path(), &["plan"]).await;
    assert_eq!(plan.code.unwrap(), 0);
    assert!(
        plan.out
            .contains("must exist in the destination organization"),
        "{}",
        plan.out
    );

    let fix = cli(&g, dir.path(), &["parity", "fix", "--yes"]).await;
    assert_eq!(fix.code.unwrap(), 0, "{}", fix.out);
    assert!(fix.out.contains("All gaps are resolved"), "{}", fix.out);
    assert!(g.has_role("organizations/222/roles/deployer"));
    let pol = g.iam_at("projects/proj-aaaa");
    let new = pol
        .bindings
        .iter()
        .find(|b| b.role.as_str() == "organizations/222/roles/deployer")
        .expect("new-role binding");
    assert!(new
        .members
        .contains("serviceAccount:ci@proj-aaaa.iam.gserviceaccount.com"));
    assert!(
        new.members.contains("group:release@x.com"),
        "inherited custom-role grant is recreated on the project"
    );
    assert!(
        pol.bindings
            .iter()
            .any(|b| b.role.as_str() == "organizations/111/roles/deployer"),
        "old binding remains until prune"
    );

    assert_eq!(
        cli(&g, dir.path(), &["apply", "--yes"]).await.code.unwrap(),
        0
    );
    // After the move the new role resolves in the destination org.
    let eff = g
        .get_effective_iam(&"projects/proj-aaaa".parse().unwrap())
        .await
        .unwrap();
    assert!(eff.grants.iter().any(
        |x| x.grant.role.as_str() == "organizations/222/roles/deployer"
            && x.grant.member == "group:release@x.com"
    ));
}

#[tokio::test]
async fn custom_roles_off_leaves_gaps_that_fix_skips() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path()); // custom_roles defaults to off
    let g = roles_world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    let fix = cli(&g, dir.path(), &["parity", "fix", "--yes"]).await;
    assert_eq!(fix.code.unwrap(), 0);
    assert!(fix.out.contains("custom_roles: recreate"), "{}", fix.out);
    assert!(fix.out.contains("gap(s) remain"));
    assert!(!g.has_role("organizations/222/roles/deployer"));
    let e = cli(&g, dir.path(), &["apply", "--yes"])
        .await
        .code
        .unwrap_err();
    assert_eq!(e.exit_code(), 4);
}

#[tokio::test]
async fn conflicting_destination_role_blocks_the_plan() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("orgmove.yaml"), recreate_manifest()).unwrap();
    let g = roles_world();
    g.custom_role(role("222", &["storage.objects.get"]));
    let plan = cli(&g, dir.path(), &["plan"]).await;
    assert_eq!(plan.code.unwrap(), 4);
    assert!(plan.out.contains("different permissions"), "{}", plan.out);
}

#[tokio::test]
async fn rollback_with_revert_deletes_the_recreated_role_and_bindings() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("orgmove.yaml"), recreate_manifest()).unwrap();
    let g = roles_world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    cli(&g, dir.path(), &["parity", "fix", "--yes"])
        .await
        .code
        .unwrap();
    cli(&g, dir.path(), &["apply", "--yes"]).await.code.unwrap();
    let r = cli(
        &g,
        dir.path(),
        &["rollback", "--all", "--yes", "--revert-remediations"],
    )
    .await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    assert!(!g.has_role("organizations/222/roles/deployer"));
    assert!(g
        .iam_at("projects/proj-aaaa")
        .bindings
        .iter()
        .all(|b| b.role.as_str() != "organizations/222/roles/deployer"));
    assert!(
        g.has_role("organizations/111/roles/deployer"),
        "the source role is never touched"
    );
}

const OS_LOGIN: &str = "constraints/compute.requireOsLogin";

fn enforced() -> gcp_orgmove_core::OrgPolicy {
    let mut p = gcp_orgmove_core::OrgPolicy::empty(OS_LOGIN);
    p.rules.push(gcp_orgmove_core::PolicyRule {
        enforce: Some(true),
        ..Default::default()
    });
    p
}

fn strict_destination() -> FakeGcp {
    let g = world();
    g.policy("organizations/222", enforced());
    g
}

#[tokio::test]
async fn stricter_destination_policy_is_reported_and_blocks_apply_until_handled() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = strict_destination();
    let plan = cli(&g, dir.path(), &["plan"]).await;
    assert_eq!(plan.code.unwrap(), 0);
    assert!(
        plan.out.contains("is stricter under folders/20"),
        "{}",
        plan.out
    );
    assert!(plan.out.contains("Preferred fix"));
    let e = cli(&g, dir.path(), &["apply", "--yes"])
        .await
        .code
        .unwrap_err();
    assert_eq!(e.exit_code(), 4);
}

#[tokio::test]
async fn override_requires_both_flags_then_unblocks_apply_and_is_listed_by_status() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = strict_destination();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();

    // Without the flags nothing is relaxed.
    let none = cli(&g, dir.path(), &["parity", "fix", "--yes"]).await;
    assert!(
        none.out.contains("--allow-policy-overrides"),
        "{}",
        none.out
    );
    assert!(g.policy_at("projects/proj-aaaa", OS_LOGIN).is_none());

    // --policy-fix alone is refused.
    let e = cli(
        &g,
        dir.path(),
        &["parity", "fix", "--yes", "--policy-fix", "project-override"],
    )
    .await
    .code
    .unwrap_err();
    assert_eq!(e.exit_code(), 2);

    let r = cli(
        &g,
        dir.path(),
        &[
            "parity",
            "fix",
            "--yes",
            "--policy-fix",
            "project-override",
            "--allow-policy-overrides",
        ],
    )
    .await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    assert!(r.out.contains("All gaps are resolved"), "{}", r.out);
    for p in ["proj-aaaa", "proj-bbbb"] {
        // matches the project's current (source) effective policy: not enforced
        assert!(
            g.policy_at(&format!("projects/{p}"), OS_LOGIN).is_some(),
            "{p}"
        );
    }
    let proj = g.get_project(&"proj-aaaa".parse().unwrap()).await.unwrap();
    assert!(
        proj.labels.contains_key("orgmove-override-exp"),
        "audit label set"
    );

    let st = cli(&g, dir.path(), &["status", "--overrides"]).await;
    assert!(
        st.out.contains(OS_LOGIN) && st.out.contains("active"),
        "{}",
        st.out
    );
    assert!(
        st.out.contains("2026-") || st.out.contains("20"),
        "{}",
        st.out
    );

    assert_eq!(
        cli(&g, dir.path(), &["apply", "--yes"]).await.code.unwrap(),
        0
    );

    // rollback --revert-remediations removes the override and the label
    let rb = cli(
        &g,
        dir.path(),
        &["rollback", "--all", "--yes", "--revert-remediations"],
    )
    .await;
    assert_eq!(rb.code.unwrap(), 0, "{}", rb.out);
    assert!(g.policy_at("projects/proj-aaaa", OS_LOGIN).is_none());
    let proj = g.get_project(&"proj-aaaa".parse().unwrap()).await.unwrap();
    assert!(!proj.labels.contains_key("orgmove-override-exp"));
    let st = cli(&g, dir.path(), &["status", "--overrides"]).await;
    assert!(st.out.contains("No org policy overrides are active"));
}

#[tokio::test]
async fn manifest_can_enable_overrides_but_the_flag_is_still_required() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("orgmove.yaml"),
        format!("{MANIFEST}parity:\n  policy_fix: project-override\n"),
    )
    .unwrap();
    let g = strict_destination();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    let no_flag = cli(&g, dir.path(), &["parity", "fix", "--yes"]).await;
    assert!(g.policy_at("projects/proj-aaaa", OS_LOGIN).is_none());
    assert!(no_flag.out.contains("--allow-policy-overrides"));
    let ok = cli(
        &g,
        dir.path(),
        &["parity", "fix", "--yes", "--allow-policy-overrides"],
    )
    .await;
    assert_eq!(ok.code.unwrap(), 0, "{}", ok.out);
    assert!(g.policy_at("projects/proj-aaaa", OS_LOGIN).is_some());
}

#[tokio::test]
async fn ignored_constraints_are_not_reported() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("orgmove.yaml"),
        format!("{MANIFEST}parity:\n  ignore_constraints: [\"{OS_LOGIN}\"]\n"),
    )
    .unwrap();
    let g = strict_destination();
    let plan = cli(&g, dir.path(), &["plan"]).await;
    assert!(!plan.out.contains("stricter"), "{}", plan.out);
    assert_eq!(
        cli(&g, dir.path(), &["apply", "--yes"]).await.code.unwrap(),
        0
    );
}

const LEAD: &str = "user:lead@x.com";

fn probe_manifest() -> String {
    format!("{MANIFEST}parity:\n  principals_to_probe: [\"{LEAD}\"]\n  critical_permissions: [\"compute.instances.get\"]\n")
}

fn probe_world() -> FakeGcp {
    let g = world();
    g.grant("folders/10", "roles/editor", LEAD);
    g.principal_can(LEAD, &["compute.instances.get"]);
    g
}

#[tokio::test]
async fn parity_verify_passes_after_a_fix_and_unlocks_the_state() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("orgmove.yaml"), probe_manifest()).unwrap();
    let g = probe_world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    cli(&g, dir.path(), &["parity", "fix", "--yes"])
        .await
        .code
        .unwrap();
    assert_eq!(
        cli(&g, dir.path(), &["apply", "--yes"]).await.code.unwrap(),
        0
    );

    let r = cli(&g, dir.path(), &["parity", "verify"]).await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    assert!(
        r.out.contains("iam-diff") && r.out.contains("still effective"),
        "{}",
        r.out
    );
    assert!(r.out.contains("critical permission(s) granted"));
    assert!(r.out.contains("parity prune"));
    let st = gcp_orgmove_core::state::read_state(&dir.path().join("orgmove.state.json")).unwrap();
    assert!(st.parity_verify.values().all(|v| v.passed) && st.parity_verify.len() == 2);
}

#[tokio::test]
async fn parity_verify_catches_access_lost_by_accepting_a_gap() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("orgmove.yaml"), probe_manifest()).unwrap();
    let g = probe_world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    // Accept every gap instead of fixing it.
    let plan = plan_of(dir.path());
    let accept: String = plan
        .projects
        .iter()
        .flat_map(|p| p.findings.iter())
        .filter(|f| f.severity == gcp_orgmove_core::Severity::Gap)
        .map(|f| format!("    - finding: \"{}\"\n      reason: \"oops\"\n", f.id))
        .collect();
    let text = probe_manifest().replace("parity:\n", &format!("parity:\n  accept:\n{accept}"));
    std::fs::write(dir.path().join("orgmove.yaml"), text).unwrap();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    assert_eq!(
        cli(&g, dir.path(), &["apply", "--yes"]).await.code.unwrap(),
        0
    );

    let r = cli(&g, dir.path(), &["parity", "verify"]).await;
    assert_eq!(r.code.unwrap(), 6);
    assert!(r.out.contains("lost: roles/editor"), "{}", r.out);
    assert!(r.out.contains("failed parity verification"));
    let st = gcp_orgmove_core::state::read_state(&dir.path().join("orgmove.state.json")).unwrap();
    assert!(st.parity_verify.values().all(|v| !v.passed));
}

#[tokio::test]
async fn parity_verify_before_the_move_fails_politely() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("orgmove.yaml"), probe_manifest()).unwrap();
    let g = probe_world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    let r = cli(&g, dir.path(), &["parity", "verify"]).await;
    assert_eq!(r.code.unwrap(), 6);
    assert!(r.out.contains("has not been moved"));
}

/// fix -> apply -> parity verify, leaving old and new custom-role bindings on proj-aaaa.
async fn migrated_with_roles(dir: &std::path::Path, g: &FakeGcp) {
    std::fs::write(
        dir.join("orgmove.yaml"),
        format!("{}  principals_to_probe: []\n", recreate_manifest()),
    )
    .unwrap();
    cli(g, dir, &["plan"]).await.code.unwrap();
    assert_eq!(
        cli(g, dir, &["parity", "fix", "--yes"]).await.code.unwrap(),
        0
    );
    assert_eq!(cli(g, dir, &["apply", "--yes"]).await.code.unwrap(), 0);
}

fn old_role_members(g: &FakeGcp) -> usize {
    g.iam_at("projects/proj-aaaa")
        .bindings
        .iter()
        .filter(|b| b.role.as_str() == "organizations/111/roles/deployer")
        .map(|b| b.members.len())
        .sum()
}

#[tokio::test]
async fn prune_requires_a_passing_parity_verify() {
    let dir = tempfile::tempdir().unwrap();
    let g = roles_world();
    migrated_with_roles(dir.path(), &g).await;
    let e = cli(
        &g,
        dir.path(),
        &["parity", "prune", "--project", "proj-aaaa", "--yes"],
    )
    .await
    .code
    .unwrap_err();
    assert_eq!(e.exit_code(), 2);
    assert!(e.message.contains("parity verify"));
    let all = cli(&g, dir.path(), &["parity", "prune", "--yes"]).await;
    assert_eq!(all.code.unwrap(), 0);
    assert!(
        all.out.contains("skipping proj-aaaa") && all.out.contains("Nothing to prune"),
        "{}",
        all.out
    );
    assert_eq!(old_role_members(&g), 1, "nothing removed");
}

#[tokio::test]
async fn prune_removes_superseded_bindings_after_verify_and_rollback_restores_them() {
    let dir = tempfile::tempdir().unwrap();
    let g = roles_world();
    migrated_with_roles(dir.path(), &g).await;
    assert_eq!(
        cli(&g, dir.path(), &["parity", "verify"])
            .await
            .code
            .unwrap(),
        0
    );
    assert_eq!(old_role_members(&g), 1);

    let dry = cli(&g, dir.path(), &["parity", "prune"]).await;
    assert_eq!(dry.code.unwrap(), 0);
    assert!(
        dry.out.contains("Dry run")
            && dry
                .out
                .contains("superseded by organizations/222/roles/deployer"),
        "{}",
        dry.out
    );
    assert_eq!(old_role_members(&g), 1, "dry run removes nothing");

    let r = cli(&g, dir.path(), &["parity", "prune", "--yes"]).await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    assert!(r.out.contains("removed"));
    assert_eq!(old_role_members(&g), 0);
    let pol = g.iam_at("projects/proj-aaaa");
    assert!(
        pol.bindings
            .iter()
            .any(|b| b.role.as_str() == "organizations/222/roles/deployer"),
        "the new binding stays"
    );
    assert!(
        cli(&g, dir.path(), &["parity", "prune", "--yes"])
            .await
            .out
            .contains("Nothing to prune"),
        "idempotent"
    );

    // Rolling back with --revert-remediations puts the pruned binding back first.
    let rb = cli(
        &g,
        dir.path(),
        &["rollback", "--all", "--yes", "--revert-remediations"],
    )
    .await;
    assert_eq!(rb.code.unwrap(), 0, "{}", rb.out);
    assert!(rb.out.contains("restored:"), "{}", rb.out);
    assert_eq!(old_role_members(&g), 1, "the source-role binding is back");
    assert!(g
        .iam_at("projects/proj-aaaa")
        .bindings
        .iter()
        .all(|b| b.role.as_str() != "organizations/222/roles/deployer"));
}

#[tokio::test]
async fn prune_soak_period_protects_recent_changes() {
    let dir = tempfile::tempdir().unwrap();
    let g = roles_world();
    migrated_with_roles(dir.path(), &g).await;
    cli(&g, dir.path(), &["parity", "verify"])
        .await
        .code
        .unwrap();
    let r = cli(
        &g,
        dir.path(),
        &["parity", "prune", "--yes", "--older-than", "7d"],
    )
    .await;
    assert!(r.out.contains("Nothing to prune"), "{}", r.out);
    assert_eq!(old_role_members(&g), 1);
    let e = cli(&g, dir.path(), &["parity", "prune", "--older-than", "soon"])
        .await
        .code
        .unwrap_err();
    assert_eq!(e.exit_code(), 2);
}

#[tokio::test]
async fn prune_removes_project_bindings_the_destination_now_covers() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("orgmove.yaml"), probe_manifest()).unwrap();
    let g = probe_world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    cli(&g, dir.path(), &["parity", "fix", "--yes"])
        .await
        .code
        .unwrap();
    assert_eq!(
        cli(&g, dir.path(), &["apply", "--yes"]).await.code.unwrap(),
        0
    );
    cli(&g, dir.path(), &["parity", "verify"])
        .await
        .code
        .unwrap();
    // The destination later grants the same thing.
    g.grant("folders/20", "roles/editor", LEAD);
    let r = cli(&g, dir.path(), &["parity", "prune", "--yes"]).await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    assert!(r.out.contains("destination hierarchy"), "{}", r.out);
    assert!(g
        .iam_at("projects/proj-aaaa")
        .bindings
        .iter()
        .all(|b| b.role.as_str() != "roles/editor"));
    let eff = g
        .get_effective_iam(&"projects/proj-aaaa".parse().unwrap())
        .await
        .unwrap();
    assert!(
        eff.grants
            .iter()
            .any(|x| x.grant.member == LEAD && x.grant.role.as_str() == "roles/editor"),
        "access still effective via the destination"
    );
}

#[tokio::test]
async fn vpc_sc_membership_blocks_the_plan_unless_skipped() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = world();
    g.perimeter(gcp_orgmove_core::Perimeter {
        name: "accessPolicies/1/servicePerimeters/prod".into(),
        projects: vec!["1001".parse().unwrap()],
    });
    let r = cli(&g, dir.path(), &["plan"]).await;
    assert_eq!(r.code.unwrap(), 4);
    assert!(
        r.out.contains("VPC Service Controls perimeter") && r.out.contains("prod"),
        "{}",
        r.out
    );
    let skipped = cli(&g, dir.path(), &["plan", "--skip", "vpc-sc"]).await;
    assert_eq!(skipped.code.unwrap(), 0, "{}", skipped.out);
}

#[tokio::test]
async fn a_check_that_cannot_run_blocks_with_a_skip_hint() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = world();
    g.inject_fault(
        "list_vpc_sc_perimeters",
        gcp_orgmove_core::Error::new(
            gcp_orgmove_core::ErrorKind::PermissionDenied,
            "ACM not enabled",
        ),
    );
    let r = cli(&g, dir.path(), &["plan"]).await;
    assert_eq!(r.code.unwrap(), 4);
    assert!(
        r.out.contains("could not run") && r.out.contains("--skip vpc-sc"),
        "{}",
        r.out
    );
}

#[tokio::test]
async fn shared_vpc_projects_are_grouped_in_the_plan_output() {
    let dir = tempfile::tempdir().unwrap();
    let g = world();
    g.project("net-host-aa", "5001", "folders/10");
    g.shared_vpc("net-host-aa", "proj-aaaa");
    let text = MANIFEST
        .replace(
            "  - id: proj-aaaa",
            "  - id: proj-aaaa\n  - id: net-host-aa",
        )
        .replace("batch_size: 1", "batch_size: 3");
    std::fs::write(dir.path().join("orgmove.yaml"), text).unwrap();
    let r = cli(&g, dir.path(), &["plan"]).await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    assert!(r.out.contains("shared-vpc-net-host-aa"), "{}", r.out);
    assert_eq!(
        cli(&g, dir.path(), &["apply", "--yes"]).await.code.unwrap(),
        0
    );
    assert_eq!(g.parent_of("net-host-aa").to_string(), "folders/20");
    assert_eq!(g.parent_of("proj-aaaa").to_string(), "folders/20");
}
