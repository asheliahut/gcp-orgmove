use super::*;
use crate::fake::FakeGcp;
use crate::manifest::{LoadedManifest, Manifest};
use crate::model::{EXPORT_CONSTRAINT, IMPORT_CONSTRAINT};
use crate::planner::{build_plan, PlanOptions};
use crate::state::StateStore;

fn pid(s: &str) -> ProjectId {
    s.parse().unwrap()
}

fn now() -> DateTime<Utc> {
    "2026-10-05T12:00:00Z".parse().unwrap()
}

fn fast() -> ApplyOptions {
    let mut o = ApplyOptions::new(now());
    o.poll = PollConfig {
        initial: Duration::from_millis(1),
        max: Duration::from_millis(2),
        timeout: Duration::from_secs(5),
    };
    o
}

fn world() -> FakeGcp {
    let f = FakeGcp::new();
    f.org("111").org("222");
    f.folder("10", "organizations/111");
    f.folder("20", "organizations/222");
    f.project("proj-aaaa", "1001", "folders/10");
    f.project("proj-bbbb", "1002", "folders/10");
    f.project("proj-cccc", "1003", "folders/10");
    f
}

fn manifest(extra: &str) -> String {
    format!(
        r#"
version: 1
source_org: "111"
destination_org: "222"
default_destination_folder: "20"
projects:
  - id: proj-aaaa
  - id: proj-bbbb
  - id: proj-cccc
limits:
  batch_size: 1
{extra}
"#
    )
}

struct Env {
    gcp: FakeGcp,
    loaded: LoadedManifest,
    plan: Plan,
    store: StateStore,
    _dir: tempfile::TempDir,
}

async fn env_with(gcp: FakeGcp, extra: &str) -> Env {
    let loaded = Manifest::parse(&manifest(extra)).unwrap();
    let plan = build_plan(&gcp, &loaded, &[], &PlanOptions::new(now()))
        .await
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let store = StateStore::open(&dir.path().join("state.json"))
        .await
        .unwrap();
    gcp.clear_calls();
    Env {
        gcp,
        loaded,
        plan,
        store,
        _dir: dir,
    }
}

async fn env() -> Env {
    env_with(world(), "").await
}

async fn run(
    e: &Env,
    opts: &ApplyOptions,
    hooks: &dyn ApplyHooks,
    cancel: CancelFlag,
) -> Result<ApplyReport> {
    let snap = e.store.handle().snapshot().await.unwrap();
    let approved = preflight(
        &e.gcp,
        &e.plan,
        &e.loaded.manifest,
        &e.loaded.sha256,
        &snap,
        opts,
    )
    .await?;
    apply(
        &e.gcp,
        &e.plan,
        &approved,
        e.store.handle(),
        hooks,
        cancel,
        opts,
    )
    .await
}

fn no_cancel() -> CancelFlag {
    Arc::new(AtomicBool::new(false))
}

fn assert_constraints_pristine(g: &FakeGcp) {
    assert!(g
        .policy_at("organizations/111", EXPORT_CONSTRAINT)
        .is_none());
    assert!(g
        .policy_at("organizations/222", IMPORT_CONSTRAINT)
        .is_none());
}

#[tokio::test]
async fn happy_path_moves_everything_and_restores_constraints() {
    let e = env().await;
    let r = run(&e, &fast(), &NoHooks, no_cancel()).await.unwrap();
    assert_eq!(r.moved.len(), 3);
    assert!(r.failed.is_empty() && r.constraints_restored);
    assert_eq!(r.exit_code(), 0);
    for p in ["proj-aaaa", "proj-bbbb", "proj-cccc"] {
        assert_eq!(e.gcp.parent_of(p).to_string(), "folders/20");
    }
    assert_constraints_pristine(&e.gcp);
    let st = e.store.handle().snapshot().await.unwrap();
    for p in ["proj-aaaa", "proj-bbbb", "proj-cccc"] {
        let ps = st.project(&pid(p)).unwrap();
        assert_eq!(ps.status, Status::Moved);
        assert_eq!(
            ps.original_parent.as_ref().unwrap().to_string(),
            "folders/10"
        );
        assert!(ps.operation.is_none());
    }
    assert_eq!(st.pending_constraints().count(), 0);
}

#[tokio::test]
async fn restores_prior_policy_exactly() {
    let g = world();
    let mut prior = OrgPolicy::empty(EXPORT_CONSTRAINT);
    prior.allow_value("under:organizations/999");
    g.policy("organizations/111", prior);
    let e = env_with(g, "").await;
    run(&e, &fast(), &NoHooks, no_cancel()).await.unwrap();
    let after = e
        .gcp
        .policy_at("organizations/111", EXPORT_CONSTRAINT)
        .unwrap();
    assert!(after.allows("under:organizations/999"));
    assert!(!after.allows("under:organizations/222"));
}

#[tokio::test]
async fn failure_halts_later_batches_but_restores_constraints() {
    let e = env().await;
    e.gcp.fail_next_operation("backend exploded");
    let r = run(&e, &fast(), &NoHooks, no_cancel()).await.unwrap();
    assert_eq!(r.moved.len(), 0);
    assert_eq!(r.failed.len(), 1);
    assert_eq!(r.skipped.len(), 2);
    assert!(r.constraints_restored);
    assert_eq!(r.exit_code(), 6);
    assert_constraints_pristine(&e.gcp);
    let st = e.store.handle().snapshot().await.unwrap();
    assert!(matches!(
        st.project(&pid("proj-aaaa")).unwrap().status,
        Status::Failed { .. }
    ));
    // original parent recorded even though the move failed
    assert!(st
        .project(&pid("proj-aaaa"))
        .unwrap()
        .original_parent
        .is_some());
}

#[tokio::test]
async fn continue_on_error_proceeds_past_failures() {
    let e = env().await;
    e.gcp.fail_next_operation("boom");
    let mut o = fast();
    o.continue_on_error = true;
    let r = run(&e, &o, &NoHooks, no_cancel()).await.unwrap();
    assert_eq!(r.failed.len(), 1);
    assert_eq!(r.moved.len(), 2);
    assert_eq!(r.exit_code(), 6);
}

#[tokio::test]
async fn failed_project_can_be_retried() {
    let e = env().await;
    e.gcp.fail_next_operation("boom");
    run(&e, &fast(), &NoHooks, no_cancel()).await.unwrap();
    let r = run(&e, &fast(), &NoHooks, no_cancel()).await.unwrap();
    assert_eq!(r.moved.len(), 3);
    assert!(r.failed.is_empty());
}

#[tokio::test]
async fn group_halts_as_a_unit() {
    let e = env().await;
    // widen batch_size so the group fits
    let text = manifest("groups:\n  - name: g\n    projects: [proj-aaaa, proj-bbbb]\n")
        .replace("batch_size: 1", "batch_size: 2");
    let loaded = Manifest::parse(&text).unwrap();
    let plan = build_plan(&e.gcp, &loaded, &[], &PlanOptions::new(now()))
        .await
        .unwrap();
    let e = Env { loaded, plan, ..e };
    e.gcp.fail_next_operation("boom");
    let mut o = fast();
    o.concurrency = 1; // proj-aaaa starts first and fails; bbbb must not start
    let r = run(&e, &o, &NoHooks, no_cancel()).await.unwrap();
    assert_eq!(r.failed.len(), 1);
    assert!(r.skipped.contains(&pid("proj-bbbb")));
    assert_eq!(e.gcp.calls_to("move_project"), 1);
    assert_eq!(e.gcp.parent_of("proj-bbbb").to_string(), "folders/10");
}

struct CancelAfterFirst(CancelFlag);
#[async_trait]
impl ApplyHooks for CancelAfterFirst {
    async fn after_move(&self, _: &ProjectId) -> Result<()> {
        self.0.store(true, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn cancel_stops_new_work_and_restores_constraints() {
    let e = env().await;
    let cancel = no_cancel();
    let r = run(&e, &fast(), &CancelAfterFirst(cancel.clone()), cancel)
        .await
        .unwrap();
    assert_eq!(r.moved.len(), 1);
    assert_eq!(r.skipped.len(), 2);
    assert!(r.interrupted && r.constraints_restored);
    assert_eq!(r.exit_code(), 6);
    assert_constraints_pristine(&e.gcp);
}

struct Panics;
#[async_trait]
impl ApplyHooks for Panics {
    async fn after_move(&self, _: &ProjectId) -> Result<()> {
        panic!("hook exploded");
    }
}

#[tokio::test]
async fn panic_still_restores_constraints() {
    let e = env().await;
    let res = AssertUnwindSafe(run(&e, &fast(), &Panics, no_cancel()))
        .catch_unwind()
        .await;
    assert!(res.is_err(), "panic must propagate");
    assert_constraints_pristine(&e.gcp);
    let st = e.store.handle().snapshot().await.unwrap();
    assert_eq!(st.pending_constraints().count(), 0);
}

struct SmokeFails;
#[async_trait]
impl ApplyHooks for SmokeFails {
    async fn after_move(&self, p: &ProjectId) -> Result<()> {
        Err(Error::new(
            ErrorKind::SmokeFailed,
            format!("api-health failed for {p}"),
        ))
    }
}

#[tokio::test]
async fn smoke_failure_halts_and_exits_7() {
    let e = env().await;
    let r = run(&e, &fast(), &SmokeFails, no_cancel()).await.unwrap();
    assert_eq!(r.exit_code(), 7);
    assert_eq!(r.moved.len(), 1);
    assert_eq!(r.skipped.len(), 2);
    assert!(r.constraints_restored);
}

struct BeforeFails;
#[async_trait]
impl ApplyHooks for BeforeFails {
    async fn before_moves(&self) -> Result<()> {
        Err(Error::new(ErrorKind::SmokeFailed, "before test failed"))
    }
}

#[tokio::test]
async fn before_hook_failure_moves_nothing_and_restores() {
    let e = env().await;
    let err = run(&e, &fast(), &BeforeFails, no_cancel())
        .await
        .unwrap_err();
    assert_eq!(err.exit_code(), 7);
    assert_eq!(e.gcp.calls_to("move_project"), 0);
    assert_constraints_pristine(&e.gcp);
}

#[tokio::test]
async fn crashed_run_constraints_are_recovered_on_next_apply() {
    let e = env().await;
    // Simulate a crash after the constraint was changed and recorded.
    let change = e.plan.policy_changes[0].clone();
    set_constraint(&e.gcp, &e.store.handle(), &change)
        .await
        .unwrap();
    assert!(e
        .gcp
        .policy_at(change.scope.to_string().as_str(), &change.constraint)
        .is_some());
    assert_eq!(
        e.store
            .handle()
            .snapshot()
            .await
            .unwrap()
            .pending_constraints()
            .count(),
        1
    );

    // Recovery alone repairs it...
    let errs = recover_constraints(&e.gcp, &e.store.handle()).await;
    assert!(errs.is_empty());
    assert_constraints_pristine(&e.gcp);
    // ...and a full apply works afterwards.
    let r = run(&e, &fast(), &NoHooks, no_cancel()).await.unwrap();
    assert_eq!(r.moved.len(), 3);
}

#[tokio::test]
async fn recovery_runs_automatically_at_start_of_apply() {
    let e = env().await;
    let change = e.plan.policy_changes[0].clone();
    set_constraint(&e.gcp, &e.store.handle(), &change)
        .await
        .unwrap();
    // inject a failure so apply stops before doing anything else
    e.gcp.fail_next_operation("boom");
    let r = run(&e, &fast(), &NoHooks, no_cancel()).await.unwrap();
    assert!(r.constraints_restored);
    assert_constraints_pristine(&e.gcp);
}

struct ExternalEdit(FakeGcp);
#[async_trait]
impl ApplyHooks for ExternalEdit {
    async fn before_moves(&self) -> Result<()> {
        // Someone else adds an unrelated allowed value mid-run.
        let mut p = self
            .0
            .policy_at("organizations/111", EXPORT_CONSTRAINT)
            .unwrap();
        p.allow_value("under:organizations/777");
        self.0.policy("organizations/111", p);
        Ok(())
    }
}

#[tokio::test]
async fn restore_never_clobbers_concurrent_edits() {
    let e = env().await;
    let hooks = ExternalEdit(e.gcp.clone());
    run(&e, &fast(), &hooks, no_cancel()).await.unwrap();
    let after = e
        .gcp
        .policy_at("organizations/111", EXPORT_CONSTRAINT)
        .unwrap();
    assert!(
        after.allows("under:organizations/777"),
        "other party's value must survive"
    );
    assert!(
        !after.allows("under:organizations/222"),
        "our value must be removed"
    );
}

#[tokio::test]
async fn keep_constraints_leaves_them_and_reports() {
    let e = env().await;
    let mut o = fast();
    o.keep_constraints = true;
    let r = run(&e, &o, &NoHooks, no_cancel()).await.unwrap();
    assert!(!r.constraints_restored);
    assert_eq!(r.constraints_left.len(), 2);
    assert!(e
        .gcp
        .policy_at("organizations/111", EXPORT_CONSTRAINT)
        .is_some());
}

#[tokio::test]
async fn project_already_at_landing_parent_is_moved_without_a_move_call() {
    let e = env().await;
    // Move proj-aaaa behind the tool's back.
    e.gcp.allow_moves("111", "222");
    let op = e
        .gcp
        .move_project(&pid("proj-aaaa"), &"folders/20".parse().unwrap())
        .await
        .unwrap();
    while e.gcp.poll_operation(&op).await.unwrap() == OperationStatus::Running {}
    e.gcp.clear_calls();
    // clean the helper-set policies so the plan constraints still apply
    let r = run(&e, &fast(), &NoHooks, no_cancel()).await.unwrap();
    assert_eq!(r.moved.len(), 3);
    assert_eq!(e.gcp.calls_to("move_project"), 2);
}

#[tokio::test]
async fn resumes_inflight_operation_instead_of_removing() {
    let e = env().await;
    // Simulate a crash after the op was started and recorded.
    e.gcp.allow_moves("111", "222");
    let op = e
        .gcp
        .move_project(&pid("proj-aaaa"), &"folders/20".parse().unwrap())
        .await
        .unwrap();
    let name = op.name.clone();
    e.store
        .handle()
        .update(move |s| {
            let id = pid("proj-aaaa");
            s.set_status(&id, Status::Analyzed)?;
            s.set_status(&id, Status::Ready)?;
            s.set_status(&id, Status::Moving)?;
            let ps = s.ensure_project(&id);
            ps.original_parent = Some("folders/10".parse().unwrap());
            ps.operation = Some(name);
            Ok(())
        })
        .await
        .unwrap();
    e.gcp.clear_calls();
    let r = run(&e, &fast(), &NoHooks, no_cancel()).await.unwrap();
    assert_eq!(r.moved.len(), 3);
    assert_eq!(
        e.gcp.calls_to("move_project"),
        2,
        "aaaa must be resumed, not re-moved"
    );
}

// ---------------------------------------------------------------- preflight

#[tokio::test]
async fn stale_plan_is_rejected_with_exit_5() {
    let e = env().await;
    let mut o = fast();
    o.now = now() + chrono::Duration::hours(25);
    let err = run(&e, &o, &NoHooks, no_cancel()).await.unwrap_err();
    assert_eq!(err.exit_code(), 5);
    assert!(err.hint.unwrap().contains("plan"));
    assert!(e.gcp.mutating_calls().is_empty());
}

#[tokio::test]
async fn changed_manifest_is_rejected_with_exit_5() {
    let mut e = env().await;
    e.loaded.sha256 = "different".into();
    let err = run(&e, &fast(), &NoHooks, no_cancel()).await.unwrap_err();
    assert_eq!(err.exit_code(), 5);
}

#[tokio::test]
async fn drifted_parent_is_rejected_with_exit_5() {
    let e = env().await;
    e.gcp.folder("11", "organizations/111");
    e.gcp.allow_moves("111", "111");
    let op = e
        .gcp
        .move_project(&pid("proj-bbbb"), &"folders/11".parse().unwrap())
        .await
        .unwrap();
    while e.gcp.poll_operation(&op).await.unwrap() == OperationStatus::Running {}
    let err = run(&e, &fast(), &NoHooks, no_cancel()).await.unwrap_err();
    assert_eq!(err.exit_code(), 5);
    assert!(err.message.contains("proj-bbbb"));
    assert!(e
        .gcp
        .mutating_calls()
        .iter()
        .all(|c| !c.starts_with("set_policy")));
}

#[tokio::test]
async fn blockers_exit_4_unless_project_excluded() {
    let g = world();
    g.deny_caller("projects/proj-bbbb", "resourcemanager.projects.move");
    let e = env_with(g, "").await;
    let err = run(&e, &fast(), &NoHooks, no_cancel()).await.unwrap_err();
    assert_eq!(err.exit_code(), 4);
    assert!(err.message.contains("proj-bbbb"));
    assert!(e.gcp.mutating_calls().is_empty());

    let mut o = fast();
    o.projects = vec![pid("proj-aaaa"), pid("proj-cccc")];
    let r = run(&e, &o, &NoHooks, no_cancel()).await.unwrap();
    assert_eq!(r.moved.len(), 2);
    assert_eq!(e.gcp.parent_of("proj-bbbb").to_string(), "folders/10");
}

fn plan_with_gap(e: &mut Env) -> String {
    use crate::finding::{Category, Remediation};
    use crate::model::Binding;
    let p = pid("proj-aaaa");
    let f = Finding::new(
        p.clone(),
        "inherited-iam",
        Category::Iam,
        Severity::Gap,
        "x",
        "gap",
    )
    .with_remediation(Remediation::AddIamBinding {
        scope: Resource::Project(p.clone()),
        binding: Binding {
            role: RoleName::new("roles/viewer"),
            members: ["user:a@x.com".to_string()].into(),
            condition: None,
        },
    });
    let id = f.id.clone();
    e.plan
        .projects
        .iter_mut()
        .find(|x| x.id == p)
        .unwrap()
        .findings
        .push(f);
    e.plan.normalize();
    id
}

#[tokio::test]
async fn unresolved_gap_blocks_until_fixed_or_accepted() {
    let mut e = env().await;
    let gap_id = plan_with_gap(&mut e);
    let err = run(&e, &fast(), &NoHooks, no_cancel()).await.unwrap_err();
    assert_eq!(err.exit_code(), 4);
    assert!(err.message.contains(&gap_id));

    // accepted in the manifest
    let text = manifest(&format!(
        "parity:\n  accept:\n    - finding: \"{gap_id}\"\n      reason: \"known\"\n"
    ));
    let loaded = Manifest::parse(&text).unwrap();
    e.plan.manifest_sha256 = loaded.sha256.clone();
    e.loaded = loaded;
    let r = run(&e, &fast(), &NoHooks, no_cancel()).await.unwrap();
    assert_eq!(r.moved.len(), 3);
}

#[tokio::test]
async fn gap_with_applied_remediation_is_resolved() {
    let mut e = env().await;
    plan_with_gap(&mut e);
    let rem = e
        .plan
        .project(&pid("proj-aaaa"))
        .unwrap()
        .findings
        .iter()
        .find_map(|f| f.remediation.clone())
        .unwrap();
    e.store
        .handle()
        .update(move |s| {
            s.applied.push(crate::state::AppliedRemediation {
                finding: None,
                project: pid("proj-aaaa"),
                remediation: rem,
                prior: vec![],
                applied_at: Utc::now(),
                reverted: false,
                pruned: false,
            });
            Ok(())
        })
        .await
        .unwrap();
    assert!(run(&e, &fast(), &NoHooks, no_cancel()).await.is_ok());
}

#[tokio::test]
async fn partial_group_selection_is_rejected() {
    let e = env().await;
    let text = manifest("groups:\n  - name: g\n    projects: [proj-aaaa, proj-bbbb]\n")
        .replace("batch_size: 1", "batch_size: 2");
    let loaded = Manifest::parse(&text).unwrap();
    let plan = build_plan(&e.gcp, &loaded, &[], &PlanOptions::new(now()))
        .await
        .unwrap();
    let e = Env { loaded, plan, ..e };
    let mut o = fast();
    o.projects = vec![pid("proj-aaaa")];
    let err = run(&e, &o, &NoHooks, no_cancel()).await.unwrap_err();
    assert_eq!(err.exit_code(), 2);
}

#[tokio::test]
async fn dry_run_description_lists_actions() {
    let e = env().await;
    let sel: BTreeSet<ProjectId> = e.plan.projects.iter().map(|p| p.id.clone()).collect();
    let lines = describe(&e.plan, &sel, false);
    assert!(lines
        .iter()
        .any(|l| l.contains("allowedExportDestinations")));
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.trim_start().starts_with("move "))
            .count(),
        3
    );
    assert!(lines.last().unwrap().contains("restore"));
}

#[tokio::test]
async fn timeout_leaves_project_moving_for_resume() {
    let e = env().await;
    e.gcp.set_op_polls(1_000_000);
    let mut o = fast();
    o.poll.timeout = Duration::from_millis(30);
    let r = run(&e, &o, &NoHooks, no_cancel()).await.unwrap();
    assert_eq!(r.failed.len(), 1);
    assert!(r.failed[0].1.contains("re-run apply to resume"));
    let st = e.store.handle().snapshot().await.unwrap();
    let ps = st.project(&pid("proj-aaaa")).unwrap();
    assert_eq!(ps.status, Status::Moving);
    assert!(ps.operation.is_some());
    assert!(r.constraints_restored);
}

#[tokio::test]
async fn etag_conflict_when_setting_constraint_is_retried() {
    let e = env().await;
    e.gcp.inject_fault(
        "set_policy",
        Error::new(ErrorKind::Conflict, "etag mismatch"),
    );
    let r = run(&e, &fast(), &NoHooks, no_cancel()).await.unwrap();
    assert_eq!(r.moved.len(), 3);
    assert!(r.constraints_restored);
    assert_constraints_pristine(&e.gcp);
}

#[tokio::test]
async fn transient_poll_errors_are_tolerated() {
    let e = env().await;
    for _ in 0..3 {
        e.gcp.inject_fault(
            "poll_operation",
            Error::new(ErrorKind::QuotaExceeded, "429"),
        );
    }
    let r = run(&e, &fast(), &NoHooks, no_cancel()).await.unwrap();
    assert_eq!(r.moved.len(), 3, "{r:?}");
}

#[tokio::test]
async fn non_retryable_move_error_marks_failed_and_restores() {
    let e = env().await;
    e.gcp.inject_fault(
        "move_project",
        Error::new(ErrorKind::PermissionDenied, "denied"),
    );
    let r = run(&e, &fast(), &NoHooks, no_cancel()).await.unwrap();
    assert_eq!(r.failed.len(), 1);
    assert!(r.constraints_restored);
}

// ------------------------------------------------------------------ progress

use crate::progress::{Event, Recorder};

fn observed(rec: &std::sync::Arc<Recorder>) -> ApplyOptions {
    let mut o = fast();
    o.observer = rec.clone();
    o
}

#[tokio::test]
async fn apply_reports_one_phase_with_a_tick_per_project() {
    let e = env().await;
    let rec = Recorder::new();
    run(&e, &observed(&rec), &NoHooks, no_cancel())
        .await
        .unwrap();
    assert_eq!(rec.phases(), vec![("Moving projects".to_string(), 3)]);
    assert_eq!(rec.ticks(), 3);
    assert_eq!(rec.ends(), 1);
    let events = rec.events();
    assert!(matches!(events.first(), Some(Event::Phase { .. })));
    assert!(
        matches!(events.last(), Some(Event::End)),
        "End comes last: {events:?}"
    );
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::Tick(t) if t == "proj-aaaa moved")));
}

#[tokio::test]
async fn apply_ticks_failed_and_skipped_projects_too_and_still_ends_once() {
    let e = env().await;
    e.gcp.fail_next_operation("boom");
    let rec = Recorder::new();
    run(&e, &observed(&rec), &NoHooks, no_cancel())
        .await
        .unwrap();
    assert_eq!(rec.ends(), 1);
    assert!(rec
        .events()
        .iter()
        .any(|e| matches!(e, Event::Tick(t) if t.contains("FAILED"))));
    // batches after the failure never start, so they are not ticked; the phase still closes
    assert!(rec.ticks() >= 1);
}

#[tokio::test]
async fn apply_ends_the_phase_on_cancel_and_on_panic() {
    let e = env().await;
    let rec = Recorder::new();
    let cancel = no_cancel();
    run(
        &e,
        &observed(&rec),
        &CancelAfterFirst(cancel.clone()),
        cancel,
    )
    .await
    .unwrap();
    assert_eq!(rec.ends(), 1);

    let e = env().await;
    let rec = Recorder::new();
    let res = AssertUnwindSafe(run(&e, &observed(&rec), &Panics, no_cancel()))
        .catch_unwind()
        .await;
    assert!(res.is_err());
    assert_eq!(
        rec.ends(),
        1,
        "the guard closes the bar even when a hook panics"
    );
}

#[tokio::test]
async fn a_silent_observer_is_the_default() {
    let o = ApplyOptions::new(now());
    o.observer.tick("ignored"); // must not panic or print
}
