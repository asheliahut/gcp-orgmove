//! `parity verify` (§6.4.6): confirm that access and behavior survived the move.
//!
//! Three signals, per project:
//! 1. **Effective IAM diff** for `principals_to_probe`: the principal's own
//!    grants (from a snapshot taken just before the move) must still be
//!    effective afterwards.
//! 2. **Permission probes**: each `critical_permissions` entry must be granted
//!    to each probed principal, checked with the IAM Policy Troubleshooter
//!    (`testIamPermissions` only answers for the caller).
//! 3. **Smoke tests** configured for the `after` phase.

use std::collections::BTreeSet;

use chrono::Utc;
use gcp_orgmove_core::progress::{silent, ObserverExt, PhaseGuard, SharedObserver};
use gcp_orgmove_core::smoke::run_phase;
use gcp_orgmove_core::verify::Check;
use gcp_orgmove_core::{
    Error, Gcp, GrantKey, Manifest, Plan, ProjectId, Resource, Result, SmokePhase, StateHandle,
    Status, VerifyResult,
};

pub fn snapshot_key(project: &ProjectId, principal: &str) -> String {
    format!("{project}|{principal}")
}

/// Record each probed principal's own effective grants on each project.
/// Call this *before* the move.
pub async fn snapshot(
    gcp: &dyn Gcp,
    state: &StateHandle,
    projects: &[ProjectId],
    principals: &[String],
) -> Result<()> {
    if principals.is_empty() {
        return Ok(());
    }
    for project in projects {
        let eff = gcp
            .get_effective_iam(&Resource::Project(project.clone()))
            .await?;
        for principal in principals {
            let grants: Vec<GrantKey> = eff
                .grants
                .iter()
                .filter(|g| &g.grant.member == principal)
                .map(|g| g.grant.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let key = snapshot_key(project, principal);
            state
                .update(move |s| {
                    s.iam_snapshots.insert(key, grants);
                    Ok(())
                })
                .await?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectParity {
    pub project: ProjectId,
    pub checks: Vec<Check>,
}

impl ProjectParity {
    pub fn passed(&self) -> bool {
        self.checks.iter().all(|c| c.ok || !c.fatal)
    }
}

fn check(name: &'static str, ok: bool, detail: impl Into<String>) -> Check {
    Check {
        name,
        ok,
        detail: detail.into(),
        fatal: true,
    }
}

fn warn(name: &'static str, detail: impl Into<String>) -> Check {
    Check {
        name,
        ok: false,
        detail: detail.into(),
        fatal: false,
    }
}

/// Verify the selected projects (empty = all in the plan). Outcomes are
/// recorded in the state file; a pass is the precondition for `parity prune`.
pub async fn verify(
    gcp: &dyn Gcp,
    state: &StateHandle,
    manifest: &Manifest,
    plan: &Plan,
    only: &[ProjectId],
) -> Result<Vec<ProjectParity>> {
    verify_with(gcp, state, manifest, plan, only, &silent()).await
}

/// [`verify`] reporting progress, one tick per project.
pub async fn verify_with(
    gcp: &dyn Gcp,
    state: &StateHandle,
    manifest: &Manifest,
    plan: &Plan,
    only: &[ProjectId],
    observer: &SharedObserver,
) -> Result<Vec<ProjectParity>> {
    for id in only {
        if plan.project(id).is_none() {
            return Err(Error::invalid(format!("project {id} is not in the plan")));
        }
    }
    let snap = state.snapshot().await?;
    let parity = &manifest.parity;
    let selected = plan
        .projects
        .iter()
        .filter(|p| only.is_empty() || only.contains(&p.id))
        .count();
    let _phase = PhaseGuard::start(observer, "Verifying parity", selected);
    let mut out = vec![];
    for pp in plan
        .projects
        .iter()
        .filter(|p| only.is_empty() || only.contains(&p.id))
    {
        let id = &pp.id;
        observer.working(format!("verifying {id}"));
        let mut checks = vec![];
        let moved = matches!(
            snap.project(id).map(|s| &s.status),
            Some(Status::Moved | Status::Verified)
        );
        if !moved {
            checks.push(check(
                "moved",
                false,
                "project has not been moved; run `apply` first",
            ));
            out.push(ProjectParity {
                project: id.clone(),
                checks,
            });
            observer.tick(id);
            continue;
        }
        let me = Resource::Project(id.clone());

        // 1. Effective IAM diff.
        if parity.principals_to_probe.is_empty() {
            checks.push(warn(
                "iam-diff",
                "no principals_to_probe configured; skipped",
            ));
        } else {
            let eff = gcp.get_effective_iam(&me).await?;
            for principal in &parity.principals_to_probe {
                let key = snapshot_key(id, principal);
                let Some(before) = snap.iam_snapshots.get(&key) else {
                    checks.push(warn("iam-diff", format!("{principal}: no pre-move snapshot (was it listed in principals_to_probe when `apply` ran?)")));
                    continue;
                };
                let after: BTreeSet<&GrantKey> = eff
                    .grants
                    .iter()
                    .map(|g| &g.grant)
                    .filter(|g| &g.member == principal)
                    .collect();
                let lost: Vec<String> = before
                    .iter()
                    .filter(|g| !after.contains(g))
                    .map(|g| {
                        format!(
                            "{} (condition: {})",
                            g.role,
                            g.condition
                                .as_ref()
                                .map(|c| c.title.as_str())
                                .unwrap_or("none")
                        )
                    })
                    .collect();
                checks.push(check(
                    "iam-diff",
                    lost.is_empty(),
                    if lost.is_empty() {
                        format!(
                            "{principal}: all {} pre-move grant(s) still effective",
                            before.len()
                        )
                    } else {
                        format!("{principal} lost: {}", lost.join(", "))
                    },
                ));
            }
        }

        // 2. Permission probes.
        if parity.critical_permissions.is_empty() || parity.principals_to_probe.is_empty() {
            checks.push(warn(
                "permissions",
                "no critical_permissions/principals_to_probe configured; skipped",
            ));
        } else {
            for principal in &parity.principals_to_probe {
                match gcp
                    .troubleshoot_access(&me, principal, &parity.critical_permissions)
                    .await
                {
                    Ok(verdicts) => {
                        let denied: Vec<&str> = verdicts
                            .iter()
                            .filter(|v| !v.granted)
                            .map(|v| v.permission.as_str())
                            .collect();
                        checks.push(check(
                            "permissions",
                            denied.is_empty(),
                            if denied.is_empty() {
                                format!(
                                    "{principal}: all {} critical permission(s) granted",
                                    verdicts.len()
                                )
                            } else {
                                format!("{principal} is missing {}", denied.join(", "))
                            },
                        ));
                    }
                    // Troubleshooter unavailable: the IAM diff stays authoritative.
                    Err(e) => checks.push(warn(
                        "permissions",
                        format!("{principal}: could not probe ({e}); relying on the IAM diff"),
                    )),
                }
            }
        }

        // 3. Smoke tests (after phase).
        let results = run_phase(&manifest.smoke_tests, SmokePhase::After, Some(id)).await;
        if results.is_empty() {
            checks.push(warn("smoke", "no `after` smoke tests configured; skipped"));
        }
        for r in &results {
            checks.push(check(
                "smoke",
                r.passed,
                if r.passed {
                    format!("{} passed", r.name)
                } else {
                    format!("{} failed: {}", r.name, r.output)
                },
            ));
        }
        let recorded = results;
        state
            .update(move |s| {
                s.smoke_results.extend(recorded);
                Ok(())
            })
            .await?;

        let result = ProjectParity {
            project: id.clone(),
            checks,
        };
        let (pid, passed) = (id.clone(), result.passed());
        let detail = result
            .checks
            .iter()
            .filter(|c| !c.ok && c.fatal)
            .map(|c| format!("{}: {}", c.name, c.detail))
            .collect::<Vec<_>>()
            .join("; ");
        state
            .update(move |s| {
                s.parity_verify.insert(
                    pid,
                    VerifyResult {
                        passed,
                        detail,
                        at: Utc::now(),
                    },
                );
                Ok(())
            })
            .await?;
        observer.tick(id);
        out.push(result);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use gcp_orgmove_core::fake::FakeGcp;
    use gcp_orgmove_core::planner::{build_plan, PlanOptions};
    use gcp_orgmove_core::{Error as E, ErrorKind, StateStore};

    const USER: &str = "user:lead@x.com";

    fn manifest(extra: &str) -> String {
        format!(
            "version: 1\nsource_org: \"111\"\ndestination_org: \"222\"\ndefault_destination_folder: \"20\"\nprojects:\n  - id: proj-aaaa\nparity:\n  principals_to_probe: [\"{USER}\"]\n  critical_permissions: [\"compute.instances.get\"]\n{extra}"
        )
    }

    fn world() -> FakeGcp {
        let f = FakeGcp::new();
        f.org("111").org("222");
        f.folder("10", "organizations/111");
        f.folder("20", "organizations/222");
        f.project("proj-aaaa", "1001", "folders/10");
        f.grant("folders/10", "roles/editor", USER);
        f.principal_can(USER, &["compute.instances.get"]);
        f.set_op_polls(0);
        f
    }

    struct Env {
        g: FakeGcp,
        m: Manifest,
        plan: Plan,
        store: StateStore,
        _d: tempfile::TempDir,
    }

    async fn env(extra: &str) -> Env {
        let g = world();
        let loaded = Manifest::parse(&manifest(extra)).unwrap();
        let plan = build_plan(&g, &loaded, &[], &PlanOptions::new(Utc::now()))
            .await
            .unwrap();
        let d = tempfile::tempdir().unwrap();
        let store = StateStore::open(&d.path().join("s.json")).await.unwrap();
        Env {
            g,
            m: loaded.manifest,
            plan,
            store,
            _d: d,
        }
    }

    async fn mark_moved(e: &Env) {
        let id: ProjectId = "proj-aaaa".parse().unwrap();
        e.store
            .handle()
            .update(move |s| {
                for st in [
                    Status::Analyzed,
                    Status::Ready,
                    Status::Moving,
                    Status::Moved,
                ] {
                    s.set_status(&id, st)?;
                }
                Ok(())
            })
            .await
            .unwrap();
    }

    /// Simulate the move: reparent under the destination.
    async fn do_move(e: &Env) {
        e.g.allow_moves("111", "222");
        let id: ProjectId = "proj-aaaa".parse().unwrap();
        let op =
            e.g.move_project(&id, &"folders/20".parse().unwrap())
                .await
                .unwrap();
        while e.g.poll_operation(&op).await.unwrap() == gcp_orgmove_core::OperationStatus::Running {
        }
        mark_moved(e).await;
    }

    async fn run(e: &Env) -> Vec<ProjectParity> {
        verify(&e.g, &e.store.handle(), &e.m, &e.plan, &[])
            .await
            .unwrap()
    }

    fn find<'a>(r: &'a ProjectParity, name: &str) -> Vec<&'a Check> {
        r.checks.iter().filter(|c| c.name == name).collect()
    }

    #[tokio::test]
    async fn lost_inherited_access_is_detected() {
        let e = env("").await;
        let id: ProjectId = "proj-aaaa".parse().unwrap();
        snapshot(
            &e.g,
            &e.store.handle(),
            std::slice::from_ref(&id),
            &[USER.to_string()],
        )
        .await
        .unwrap();
        do_move(&e).await; // destination grants nothing: the folder editor role is gone
        let r = &run(&e).await[0];
        let diff = find(r, "iam-diff");
        assert!(
            !diff[0].ok && diff[0].detail.contains("lost: roles/editor"),
            "{:?}",
            diff[0]
        );
        assert!(!r.passed());
        assert!(!e.store.handle().snapshot().await.unwrap().parity_verify[&id].passed);
    }

    #[tokio::test]
    async fn access_preserved_by_a_fix_passes() {
        let e = env("").await;
        let id: ProjectId = "proj-aaaa".parse().unwrap();
        snapshot(
            &e.g,
            &e.store.handle(),
            std::slice::from_ref(&id),
            &[USER.to_string()],
        )
        .await
        .unwrap();
        e.g.grant("projects/proj-aaaa", "roles/editor", USER); // what parity fix would do
        do_move(&e).await;
        let r = &run(&e).await[0];
        assert!(find(r, "iam-diff")[0].ok, "{:?}", find(r, "iam-diff"));
        assert!(find(r, "permissions")[0].ok);
        assert!(r.passed());
        assert!(e.store.handle().snapshot().await.unwrap().parity_verify[&id].passed);
    }

    #[tokio::test]
    async fn missing_critical_permission_fails() {
        let e = env("").await;
        e.g.grant("projects/proj-aaaa", "roles/editor", USER);
        let id: ProjectId = "proj-aaaa".parse().unwrap();
        snapshot(&e.g, &e.store.handle(), &[id], &[USER.to_string()])
            .await
            .unwrap();
        do_move(&e).await;
        // the troubleshooter now says the principal can't do it
        let g2 = e.g.clone();
        g2.principal_can("user:other@x.com", &[]);
        let mut m = e.m.clone();
        m.parity.critical_permissions =
            vec!["compute.instances.get".into(), "storage.objects.get".into()];
        let r = &verify(&e.g, &e.store.handle(), &m, &e.plan, &[])
            .await
            .unwrap()[0];
        let p = find(r, "permissions");
        assert!(
            !p[0].ok && p[0].detail.contains("storage.objects.get"),
            "{:?}",
            p[0]
        );
    }

    #[tokio::test]
    async fn troubleshooter_failure_degrades_to_a_warning() {
        let e = env("").await;
        e.g.grant("projects/proj-aaaa", "roles/editor", USER);
        let id: ProjectId = "proj-aaaa".parse().unwrap();
        snapshot(&e.g, &e.store.handle(), &[id], &[USER.to_string()])
            .await
            .unwrap();
        do_move(&e).await;
        e.g.inject_fault(
            "troubleshoot_access",
            E::new(ErrorKind::PermissionDenied, "api disabled"),
        );
        let r = &run(&e).await[0];
        let p = find(r, "permissions");
        assert!(!p[0].ok && !p[0].fatal && p[0].detail.contains("relying on the IAM diff"));
        assert!(r.passed(), "a warning does not fail the project");
    }

    #[tokio::test]
    async fn missing_snapshot_is_a_warning_not_a_failure() {
        let e = env("").await;
        do_move(&e).await;
        let r = &run(&e).await[0];
        let d = find(r, "iam-diff");
        assert!(!d[0].fatal && d[0].detail.contains("no pre-move snapshot"));
    }

    #[tokio::test]
    async fn smoke_tests_run_with_the_project_in_the_environment() {
        let e = env("smoke_tests:\n  - name: needs-project\n    run: \"test \\\"$ORGMOVE_PROJECT\\\" = proj-aaaa\"\n    timeout: 5s\n    phase: [after]\n  - name: fails\n    run: \"exit 1\"\n    timeout: 5s\n    phase: [after]\n").await;
        e.g.grant("projects/proj-aaaa", "roles/editor", USER);
        let id: ProjectId = "proj-aaaa".parse().unwrap();
        snapshot(&e.g, &e.store.handle(), &[id], &[USER.to_string()])
            .await
            .unwrap();
        do_move(&e).await;
        let r = &run(&e).await[0];
        let smoke = find(r, "smoke");
        assert_eq!(smoke.len(), 2);
        assert!(smoke[0].ok && !smoke[1].ok);
        assert!(!r.passed());
        assert_eq!(
            e.store
                .handle()
                .snapshot()
                .await
                .unwrap()
                .smoke_results
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn unmoved_projects_fail_without_probing() {
        let e = env("").await;
        e.g.clear_calls();
        let r = &run(&e).await[0];
        assert!(!r.passed());
        assert_eq!(r.checks.len(), 1);
        assert_eq!(e.g.calls_to("get_effective_iam"), 0);
    }

    #[tokio::test]
    async fn snapshot_without_principals_is_a_noop_and_unknown_projects_error() {
        let e = env("").await;
        e.g.clear_calls();
        snapshot(
            &e.g,
            &e.store.handle(),
            &["proj-aaaa".parse().unwrap()],
            &[],
        )
        .await
        .unwrap();
        assert!(e.g.calls().is_empty());
        let err = verify(
            &e.g,
            &e.store.handle(),
            &e.m,
            &e.plan,
            &["proj-zzzz".parse().unwrap()],
        )
        .await
        .unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[tokio::test]
    async fn parity_verify_ticks_once_per_project_even_for_unmoved_ones() {
        use gcp_orgmove_core::progress::Recorder;
        let e = env("").await;
        let rec = Recorder::new();
        let obs: SharedObserver = rec.clone();
        verify_with(&e.g, &e.store.handle(), &e.m, &e.plan, &[], &obs)
            .await
            .unwrap();
        assert_eq!(rec.phases(), vec![("Verifying parity".to_string(), 1)]);
        assert_eq!((rec.ticks(), rec.ends()), (1, 1));
    }
}
