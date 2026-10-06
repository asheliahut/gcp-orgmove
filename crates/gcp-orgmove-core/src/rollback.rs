//! `rollback` (§6.7): move projects back to their recorded original parents.
//!
//! The export/import constraints are set in the *reverse* direction (export
//! on the destination, import on the source) under the same guard as `apply`
//! (backed up first, restored on success, error, panic and interrupt).
//! Move groups are rolled back as a unit.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use futures::stream::{self, StreamExt};

use crate::apply::{wait_for_operation, with_constraints, CancelFlag, PollConfig, WaitError};
use crate::error::{Error, ErrorKind, Result};
use crate::gcp::Gcp;
use crate::ids::*;
use crate::manifest::Manifest;
use crate::model::{Operation, EXPORT_CONSTRAINT, IMPORT_CONSTRAINT};
use crate::plan::PolicyChange;
use crate::planner::{plan_constraint, ConstraintPlan};
use crate::progress::{silent, ObserverExt, PhaseGuard, SharedObserver};
use crate::state::{ProjectState, State, StateHandle};
use crate::status::Status;

#[derive(Debug, Clone)]
pub struct RollbackOptions {
    /// Specific projects; ignored when `all`.
    pub projects: Vec<ProjectId>,
    pub all: bool,
    pub concurrency: usize,
    pub keep_constraints: bool,
    pub poll: PollConfig,
    /// Receives progress events; silent by default.
    pub observer: SharedObserver,
}

impl RollbackOptions {
    pub fn new() -> Self {
        Self {
            projects: vec![],
            all: false,
            concurrency: 4,
            keep_constraints: false,
            poll: PollConfig::default(),
            observer: silent(),
        }
    }
}

impl Default for RollbackOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RollbackReport {
    pub rolled_back: Vec<ProjectId>,
    pub failed: Vec<(ProjectId, String)>,
    pub skipped: Vec<ProjectId>,
    pub interrupted: bool,
    pub constraints_restored: bool,
    pub constraints_left: Vec<String>,
    pub restore_errors: Vec<String>,
}

impl RollbackReport {
    pub fn exit_code(&self) -> u8 {
        if !self.failed.is_empty() || self.interrupted || !self.restore_errors.is_empty() {
            ErrorKind::PartialFailure.exit_code()
        } else {
            0
        }
    }
}

fn in_destination(ps: &ProjectState) -> bool {
    matches!(ps.status, Status::Moved | Status::Verified)
}

/// Resolve the selection to the projects to move back, groups expanded.
/// Errors (before anything is changed) on unknown projects, projects that
/// were never moved, and projects with no recorded original parent.
pub fn select(state: &State, opts: &RollbackOptions) -> Result<Vec<ProjectId>> {
    let mut chosen: BTreeSet<ProjectId> = BTreeSet::new();
    if opts.all {
        chosen.extend(
            state
                .projects
                .iter()
                .filter(|(_, ps)| in_destination(ps))
                .map(|(id, _)| id.clone()),
        );
    } else {
        if opts.projects.is_empty() {
            return Err(Error::invalid("pass --all or at least one --project"));
        }
        for id in &opts.projects {
            let ps = state.project(id).ok_or_else(|| {
                Error::invalid(format!(
                    "project {id} has no recorded state; nothing to roll back"
                ))
            })?;
            match ps.status {
                Status::RolledBack => continue,
                _ if in_destination(ps) => {
                    chosen.insert(id.clone());
                }
                _ => {
                    return Err(Error::invalid(format!(
                        "project {id} is {:?}, not moved; nothing to roll back",
                        ps.status.kind()
                    )))
                }
            }
        }
    }
    // Groups roll back as a unit.
    let groups: BTreeSet<String> = chosen
        .iter()
        .filter_map(|id| state.project(id)?.group.clone())
        .collect();
    for (id, ps) in &state.projects {
        if in_destination(ps) && ps.group.as_ref().is_some_and(|g| groups.contains(g)) {
            chosen.insert(id.clone());
        }
    }
    let missing: Vec<&str> = chosen
        .iter()
        .filter(|id| {
            state
                .project(id)
                .and_then(|p| p.original_parent.as_ref())
                .is_none()
        })
        .map(|id| id.as_str())
        .collect();
    if !missing.is_empty() {
        return Err(Error::invalid(format!(
            "no original parent was recorded for: {}; cannot roll back safely",
            missing.join(", ")
        ))
        .with_hint("move them back manually with `gcloud projects move`"));
    }
    Ok(chosen.into_iter().collect())
}

/// Constraint changes for the reverse direction, skipping values already allowed.
pub async fn reverse_changes(gcp: &dyn Gcp, m: &Manifest) -> Result<Vec<PolicyChange>> {
    let src = Resource::Org(m.source_org.clone());
    let dst = Resource::Org(m.destination_org.clone());
    let mut out = vec![];
    for (scope, constraint, value) in [
        (
            dst.clone(),
            EXPORT_CONSTRAINT,
            format!("under:organizations/{}", m.source_org),
        ),
        (
            src.clone(),
            IMPORT_CONSTRAINT,
            format!("under:organizations/{}", m.destination_org),
        ),
    ] {
        let direct = gcp.get_policy(&scope, constraint).await?;
        match plan_constraint(scope.clone(), constraint, value, direct) {
            ConstraintPlan::AlreadyAllowed => {}
            ConstraintPlan::Change(c) => out.push(c),
            ConstraintPlan::Blocked(why) => {
                return Err(Error::new(ErrorKind::PolicyViolation, why).with_resource(scope))
            }
        }
    }
    Ok(out)
}

/// Lines describing what a rollback would do (dry run).
pub fn describe(state: &State, ids: &[ProjectId], changes: &[PolicyChange]) -> Vec<String> {
    let mut out: Vec<String> = changes
        .iter()
        .map(|c| {
            format!(
                "set {} on {}: allow {} (backup {})",
                c.constraint, c.scope, c.value, c.backup_ref
            )
        })
        .collect();
    for id in ids {
        if let Some(ps) = state.project(id) {
            out.push(format!(
                "move {id} back to {}",
                ps.original_parent
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default()
            ));
        }
    }
    if !changes.is_empty() {
        out.push("restore the backed-up constraints".into());
    }
    out
}

struct Ctx<'a> {
    gcp: &'a dyn Gcp,
    state: StateHandle,
    poll: PollConfig,
    cancel: CancelFlag,
    stop: AtomicBool,
    halted: Mutex<BTreeSet<String>>,
    observer: SharedObserver,
}

enum Outcome {
    Done,
    Failed(String),
    Skipped,
}

async fn mark_rolled_back(ctx: &Ctx<'_>, id: &ProjectId) -> Outcome {
    let id2 = id.clone();
    let res = ctx
        .state
        .update(move |s| {
            s.set_status(&id2, Status::RolledBack)?;
            s.ensure_project(&id2).operation = None;
            Ok(())
        })
        .await;
    match res {
        Ok(()) => Outcome::Done,
        Err(e) => Outcome::Failed(format!("moved back, but state could not be saved: {e}")),
    }
}

async fn rollback_one(
    ctx: &Ctx<'_>,
    id: &ProjectId,
    group: Option<&String>,
    original: &Parent,
    in_flight: Option<String>,
) -> Outcome {
    ctx.observer.working(format!("rolling back {id}"));
    let outcome = rollback_one_inner(ctx, id, group, original, in_flight).await;
    let label = match &outcome {
        Outcome::Done => "rolled back",
        Outcome::Failed(_) => "FAILED",
        Outcome::Skipped => "skipped",
    };
    ctx.observer.tick(format!("{id} {label}"));
    outcome
}

async fn rollback_one_inner(
    ctx: &Ctx<'_>,
    id: &ProjectId,
    group: Option<&String>,
    original: &Parent,
    in_flight: Option<String>,
) -> Outcome {
    if ctx.cancel.load(Ordering::SeqCst) || ctx.stop.load(Ordering::SeqCst) {
        return Outcome::Skipped;
    }
    if group.is_some_and(|g| ctx.halted.lock().unwrap().contains(g)) {
        return Outcome::Skipped;
    }
    let outcome = async {
        let live = match ctx.gcp.get_project(id).await {
            Ok(l) => l,
            Err(e) => return Outcome::Failed(format!("cannot read project: {e}")),
        };
        if &live.parent == original {
            return mark_rolled_back(ctx, id).await;
        }
        let op = match in_flight {
            Some(name) => Operation { name },
            None => {
                let op = match ctx.gcp.move_project(id, original).await {
                    Ok(op) => op,
                    Err(e) => return Outcome::Failed(e.message),
                };
                let (id2, name) = (id.clone(), op.name.clone());
                if let Err(e) = ctx
                    .state
                    .update(move |s| {
                        s.ensure_project(&id2).operation = Some(name);
                        Ok(())
                    })
                    .await
                {
                    return Outcome::Failed(format!("cannot record operation: {e}"));
                }
                op
            }
        };
        match wait_for_operation(ctx.gcp, &op, ctx.poll).await {
            Ok(()) => {}
            Err(WaitError::Unresolved(why)) => return Outcome::Failed(why),
            Err(WaitError::Failed(why)) => {
                // Definitive failure: drop the dead operation so a retry issues a new move.
                let id2 = id.clone();
                let _ = ctx
                    .state
                    .update(move |s| {
                        s.ensure_project(&id2).operation = None;
                        Ok(())
                    })
                    .await;
                return Outcome::Failed(why);
            }
        }
        match ctx.gcp.get_project(id).await {
            Ok(p) if &p.parent == original => mark_rolled_back(ctx, id).await,
            Ok(p) => Outcome::Failed(format!(
                "operation finished but project is under {}",
                p.parent
            )),
            Err(e) => Outcome::Failed(format!("operation finished but verification failed: {e}")),
        }
    }
    .await;
    if let Outcome::Failed(_) = &outcome {
        if let Some(g) = group {
            ctx.halted.lock().unwrap().insert(g.clone());
        }
        ctx.stop.store(true, Ordering::SeqCst);
    }
    outcome
}

/// Roll back the selection from [`select`]. Call [`reverse_changes`] for
/// `changes`. Constraints are always restored (unless `keep_constraints`).
pub async fn rollback(
    gcp: &dyn Gcp,
    state: StateHandle,
    ids: &[ProjectId],
    changes: &[PolicyChange],
    cancel: CancelFlag,
    opts: &RollbackOptions,
) -> Result<RollbackReport> {
    let snap = state.snapshot().await?;
    let work: Vec<(ProjectId, Option<String>, Parent, Option<String>)> = ids
        .iter()
        .filter_map(|id| {
            let ps = snap.project(id)?;
            Some((
                id.clone(),
                ps.group.clone(),
                ps.original_parent.clone()?,
                ps.operation.clone(),
            ))
        })
        .collect();
    let ctx = Ctx {
        gcp,
        state: state.clone(),
        poll: opts.poll,
        cancel: cancel.clone(),
        stop: AtomicBool::new(false),
        halted: Mutex::new(BTreeSet::new()),
        observer: opts.observer.clone(),
    };
    let mut report = RollbackReport::default();

    let guarded = with_constraints(gcp, &state, changes, opts.keep_constraints, async {
        let _phase = PhaseGuard::start(&opts.observer, "Rolling back projects", work.len());
        let results: Vec<(ProjectId, Outcome)> = stream::iter(work.iter())
            .map(|(id, group, original, op)| {
                let ctx = &ctx;
                async move {
                    (
                        id.clone(),
                        rollback_one(ctx, id, group.as_ref(), original, op.clone()).await,
                    )
                }
            })
            .buffer_unordered(opts.concurrency.clamp(1, 16))
            .collect()
            .await;
        let by_id: BTreeMap<_, _> = results.into_iter().collect();
        for (id, o) in by_id {
            match o {
                Outcome::Done => report.rolled_back.push(id),
                Outcome::Failed(why) => report.failed.push((id, why)),
                Outcome::Skipped => report.skipped.push(id),
            }
        }
        Ok(())
    })
    .await?;
    report.constraints_restored = guarded.restored;
    report.restore_errors = guarded.restore_errors.clone();
    report.constraints_left = guarded.left.clone();
    report.interrupted = cancel.load(Ordering::SeqCst);
    guarded.into_result()?;
    Ok(report)
}
