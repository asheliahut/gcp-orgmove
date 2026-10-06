//! `verify` (§6.6): confirm the structural outcome of the migration.

use std::time::{Duration, Instant};

use chrono::Utc;
use futures::stream::{self, StreamExt};

use crate::error::{Error, Result};
use crate::gcp::Gcp;
use crate::ids::*;
use crate::model::LifecycleState;
use crate::plan::{Plan, PlanProject};
use crate::progress::{ObserverExt, PhaseGuard, SharedObserver};
use crate::state::{State, StateHandle, VerifyResult};
use crate::status::Status;

#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// Poll until the parent change is visible, up to this long.
    pub wait: Duration,
    pub poll_initial: Duration,
    pub poll_max: Duration,
    pub concurrency: usize,
    /// Receives progress events; silent by default.
    pub observer: SharedObserver,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            wait: Duration::ZERO,
            poll_initial: Duration::from_secs(5),
            poll_max: Duration::from_secs(30),
            concurrency: 4,
            observer: crate::progress::silent(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
    /// Non-fatal checks are reported but do not fail the project.
    pub fatal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectVerification {
    pub project: ProjectId,
    pub checks: Vec<Check>,
}

impl ProjectVerification {
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

async fn verify_one(
    gcp: &dyn Gcp,
    p: &PlanProject,
    dest_org: &OrgId,
    state: &State,
    opts: &VerifyOptions,
) -> ProjectVerification {
    let id = &p.id;
    let mut checks = vec![];
    let status = state.project(id).map(|s| s.status.clone());
    if !matches!(status, Some(Status::Moved | Status::Verified)) {
        let what = status
            .map(|s| format!("{:?}", s.kind()).to_lowercase())
            .unwrap_or_else(|| "not started".into());
        checks.push(check(
            "moved",
            false,
            format!("project is {what}, not moved"),
        ));
        return ProjectVerification {
            project: id.clone(),
            checks,
        };
    }

    // 1. live parent == landing parent (the Console can lag by minutes).
    let started = Instant::now();
    let mut delay = opts.poll_initial;
    let live = loop {
        match gcp.get_project(id).await {
            Ok(proj) if proj.parent == p.landing_parent => break Ok(proj),
            Ok(proj) if started.elapsed() >= opts.wait => break Ok(proj),
            Ok(_) => {}
            Err(e) => break Err(e),
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(opts.poll_max);
    };
    let live = match live {
        Ok(l) => l,
        Err(e) => {
            checks.push(check("parent", false, format!("cannot read project: {e}")));
            return ProjectVerification {
                project: id.clone(),
                checks,
            };
        }
    };
    checks.push(check(
        "parent",
        live.parent == p.landing_parent,
        if live.parent == p.landing_parent {
            format!("under {}", live.parent)
        } else {
            format!("under {} but expected {}", live.parent, p.landing_parent)
        },
    ));

    // 2. destination organization is in the ancestry.
    match gcp.get_ancestry(id).await {
        Ok(a) => {
            let ok = a.last() == Some(&Parent::Org(dest_org.clone()));
            checks.push(check(
                "organization",
                ok,
                if ok {
                    format!("in organization {dest_org}")
                } else {
                    format!(
                        "ancestry ends at {:?}, expected {dest_org}",
                        a.last().map(ToString::to_string)
                    )
                },
            ));
        }
        Err(e) => checks.push(check(
            "organization",
            false,
            format!("cannot read ancestry: {e}"),
        )),
    }

    // 3. lifecycle state.
    checks.push(check(
        "lifecycle",
        live.state == LifecycleState::Active,
        format!("{:?}", live.state),
    ));

    // 4. export/import constraints restored (non-fatal: `--keep-constraints` leaves them on purpose).
    let pending = state.pending_constraints().count();
    checks.push(Check {
        name: "constraints",
        ok: pending == 0,
        detail: if pending == 0 { "restored".into() } else { format!("{pending} constraint(s) still modified (expected if apply used --keep-constraints)") },
        fatal: false,
    });
    ProjectVerification {
        project: id.clone(),
        checks,
    }
}

/// Verify the selected plan projects (empty = all). Passing projects become
/// `Verified`; every outcome is recorded in the state file.
pub async fn verify(
    gcp: &dyn Gcp,
    plan: &Plan,
    state: &StateHandle,
    only: &[ProjectId],
    opts: &VerifyOptions,
) -> Result<Vec<ProjectVerification>> {
    for id in only {
        if plan.project(id).is_none() {
            return Err(Error::invalid(format!("project {id} is not in the plan")));
        }
    }
    let snap = state.snapshot().await?;
    let targets: Vec<&PlanProject> = plan
        .projects
        .iter()
        .filter(|p| only.is_empty() || only.contains(&p.id))
        .collect();
    let _phase = PhaseGuard::start(&opts.observer, "Verifying projects", targets.len());
    let results: Vec<ProjectVerification> = stream::iter(targets)
        .map(|p| {
            let snap = &snap;
            async move {
                let r = verify_one(gcp, p, &plan.destination_org, snap, opts).await;
                opts.observer.tick(&p.id);
                r
            }
        })
        .buffered(opts.concurrency.clamp(1, 16))
        .collect()
        .await;

    for r in &results {
        if matches!(
            snap.project(&r.project).map(|s| &s.status),
            None | Some(
                Status::Discovered
                    | Status::Analyzed
                    | Status::Ready
                    | Status::ParityGaps
                    | Status::ParityFixed
                    | Status::Moving
                    | Status::Failed { .. }
            )
        ) {
            continue; // never moved: nothing to record
        }
        let (id, passed) = (r.project.clone(), r.passed());
        let detail = r
            .checks
            .iter()
            .filter(|c| !c.ok)
            .map(|c| format!("{}: {}", c.name, c.detail))
            .collect::<Vec<_>>()
            .join("; ");
        state
            .update(move |s| {
                s.verify.insert(
                    id.clone(),
                    VerifyResult {
                        passed,
                        detail,
                        at: Utc::now(),
                    },
                );
                if passed
                    && s.project(&id)
                        .map(|p| p.status == Status::Moved)
                        .unwrap_or(false)
                {
                    s.set_status(&id, Status::Verified)?;
                }
                Ok(())
            })
            .await?;
    }
    Ok(results)
}
