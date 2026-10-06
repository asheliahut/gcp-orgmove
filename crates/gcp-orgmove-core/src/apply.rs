//! `apply` engine (§6.5): pre-execution checks, constraint guard, moves.
//!
//! Safety properties enforced here and covered by tests:
//! * the original parent is durably recorded before `move_project` is called;
//! * export/import constraints are backed up (and marked `modified`) in the
//!   state file *before* they are changed, and are restored on success,
//!   error, panic and interrupt; a crashed run is repaired by
//!   [`recover_constraints`] on the next run;
//! * restoration only removes the value this tool added, so concurrent edits
//!   by others are never clobbered;
//! * a move group halts as a unit when any member fails.

use std::collections::{BTreeMap, BTreeSet};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use futures::stream::{self, StreamExt};
use futures::FutureExt;

use crate::error::{Error, ErrorKind, Result};
use crate::finding::{Finding, Severity};
use crate::gcp::Gcp;
use crate::ids::*;
use crate::manifest::Manifest;
use crate::model::{OperationStatus, OrgPolicy};
use crate::plan::{Plan, PlanProject, PolicyChange};
use crate::progress::{silent, ObserverExt, PhaseGuard, SharedObserver};
use crate::state::{PolicyBackup, State, StateHandle};
use crate::status::Status;

/// Cooperative cancellation (set by the CLI's SIGINT/SIGTERM handler).
/// No new work starts once set; in-flight operations are polled to completion
/// so state stays accurate, then constraints are restored.
pub type CancelFlag = Arc<AtomicBool>;

#[derive(Debug, Clone, Copy)]
pub struct PollConfig {
    pub initial: Duration,
    pub max: Duration,
    pub timeout: Duration,
}

impl Default for PollConfig {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(30),
            timeout: Duration::from_secs(30 * 60),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApplyOptions {
    pub concurrency: usize,
    pub keep_constraints: bool,
    /// Restrict to these projects (empty = whole plan). Must include whole groups.
    pub projects: Vec<ProjectId>,
    pub continue_on_error: bool,
    pub poll: PollConfig,
    pub now: DateTime<Utc>,
    /// Receives progress events; silent by default.
    pub observer: SharedObserver,
}

impl ApplyOptions {
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            concurrency: 4,
            keep_constraints: false,
            projects: vec![],
            continue_on_error: false,
            poll: PollConfig::default(),
            now,
            observer: silent(),
        }
    }
}

/// Extension points used by smoke tests (phase 7).
#[async_trait]
pub trait ApplyHooks: Send + Sync {
    /// Runs after constraints are set and before anything moves.
    /// An error halts the run before any move.
    async fn before_moves(&self) -> Result<()> {
        Ok(())
    }
    /// Runs after a project reached `Moved`. A `SmokeFailed` error halts
    /// the remaining batches.
    async fn after_move(&self, _project: &ProjectId) -> Result<()> {
        Ok(())
    }
}

pub struct NoHooks;
impl ApplyHooks for NoHooks {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyReport {
    pub moved: Vec<ProjectId>,
    pub failed: Vec<(ProjectId, String)>,
    /// Never started (a halt, cancel or earlier failure).
    pub skipped: Vec<ProjectId>,
    pub interrupted: bool,
    pub smoke_failure: Option<(ProjectId, String)>,
    pub constraints_restored: bool,
    /// Constraints still modified, as human-readable lines.
    pub constraints_left: Vec<String>,
    pub restore_errors: Vec<String>,
}

impl ApplyReport {
    /// Process exit code for the outcome (§3.2).
    pub fn exit_code(&self) -> u8 {
        if self.smoke_failure.is_some() {
            ErrorKind::SmokeFailed.exit_code()
        } else if !self.failed.is_empty() || self.interrupted || !self.restore_errors.is_empty() {
            ErrorKind::PartialFailure.exit_code()
        } else {
            0
        }
    }
}

// ------------------------------------------------------------------ checks

/// Gaps with neither an applied remediation nor an accepted finding ID.
pub fn unresolved_gaps<'a>(
    plan: &'a Plan,
    state: &State,
    m: &Manifest,
    only: &BTreeSet<ProjectId>,
) -> Vec<&'a Finding> {
    let accepted: BTreeSet<&str> = m.parity.accept.iter().map(|a| a.finding.as_str()).collect();
    plan.projects
        .iter()
        .filter(|p| only.contains(&p.id))
        .flat_map(|p| p.findings.iter())
        .filter(|f| f.severity == Severity::Gap)
        .filter(|f| !accepted.contains(f.id.as_str()))
        .filter(|f| match &f.remediation {
            // Resolved if applied by finding ID (the scope may have been
            // widened at fix time) or by identical remediation data.
            Some(r) if !r.is_manual() => !state.applied.iter().any(|a| {
                !a.reverted
                    && a.project == f.project
                    && (a.finding.as_deref() == Some(f.id.as_str()) || &a.remediation == r)
            }),
            _ => true,
        })
        .collect()
}

fn selected(plan: &Plan, opts: &ApplyOptions) -> Result<BTreeSet<ProjectId>> {
    let all: BTreeSet<ProjectId> = plan.projects.iter().map(|p| p.id.clone()).collect();
    if opts.projects.is_empty() {
        return Ok(all);
    }
    let sel: BTreeSet<ProjectId> = opts.projects.iter().cloned().collect();
    if let Some(unknown) = sel.iter().find(|p| !all.contains(*p)) {
        return Err(Error::invalid(format!(
            "project {unknown} is not in the plan"
        )));
    }
    for g in plan
        .projects
        .iter()
        .filter_map(|p| p.group.as_ref())
        .collect::<BTreeSet<_>>()
    {
        let members: Vec<&ProjectId> = plan
            .projects
            .iter()
            .filter(|p| p.group.as_ref() == Some(g))
            .map(|p| &p.id)
            .collect();
        let n = members.iter().filter(|m| sel.contains(**m)).count();
        if n != 0 && n != members.len() {
            return Err(Error::invalid(format!(
                "group {g:?} must be moved as a unit; --project selects only {n} of {} members",
                members.len()
            )));
        }
    }
    Ok(sel)
}

/// Result of a passed [`preflight`]: what `apply` is cleared to do.
#[derive(Debug, Clone)]
pub struct Approved {
    pub sel: BTreeSet<ProjectId>,
    pub manifest_sha256: String,
}

/// Pre-execution checks (§6.5). Stale/drifted plans exit 5; blockers and
/// unresolved gaps exit 4. Nothing is mutated.
pub async fn preflight(
    gcp: &dyn Gcp,
    plan: &Plan,
    manifest: &Manifest,
    manifest_sha256: &str,
    state: &State,
    opts: &ApplyOptions,
) -> Result<Approved> {
    let sel = selected(plan, opts)?;
    let replan = "re-run `gcp-orgmove plan`";

    let max_age =
        chrono::Duration::from_std(manifest.limits.plan_max_age.0).unwrap_or(chrono::Duration::MAX);
    if opts.now - plan.generated_at > max_age {
        return Err(Error::new(
            ErrorKind::StalePlan,
            format!(
                "plan generated at {} is older than limits.plan_max_age ({})",
                plan.generated_at, manifest.limits.plan_max_age
            ),
        )
        .with_hint(replan));
    }
    if plan.manifest_sha256 != manifest_sha256 {
        return Err(Error::new(
            ErrorKind::StalePlan,
            "manifest changed since the plan was generated",
        )
        .with_hint(replan));
    }

    let blocked: Vec<&PlanProject> = plan
        .projects
        .iter()
        .filter(|p| sel.contains(&p.id) && p.has_blocker())
        .collect();
    if !blocked.is_empty() {
        let names: Vec<&str> = blocked.iter().map(|p| p.id.as_str()).collect();
        return Err(Error::new(
            ErrorKind::Blocked,
            format!("plan has blockers for: {}", names.join(", ")),
        )
        .with_hint("fix them and re-plan, or exclude them with --project"));
    }
    let gaps = unresolved_gaps(plan, state, manifest, &sel);
    if !gaps.is_empty() {
        let ids: Vec<&str> = gaps.iter().map(|f| f.id.as_str()).collect();
        return Err(Error::new(
            ErrorKind::Blocked,
            format!("{} unresolved gap(s): {}", gaps.len(), ids.join(", ")),
        )
        .with_hint(
            "run `gcp-orgmove parity fix`, or accept them under parity.accept in the manifest",
        ));
    }

    // Drift: live parent must be the plan-time parent or already the landing parent.
    let live: Vec<(&PlanProject, Result<crate::model::Project>)> =
        stream::iter(plan.projects.iter().filter(|p| sel.contains(&p.id)))
            .map(|p| async move { (p, gcp.get_project(&p.id).await) })
            .buffered(opts.concurrency.clamp(1, 16))
            .collect()
            .await;
    for (p, res) in live {
        let project = res?;
        if project.parent != p.live_parent_at_plan_time && project.parent != p.landing_parent {
            return Err(Error::new(
                ErrorKind::StalePlan,
                format!(
                    "project {} is now under {} but the plan expected {}",
                    p.id, project.parent, p.live_parent_at_plan_time
                ),
            )
            .with_resource(format!("projects/{}", p.id))
            .with_hint(replan));
        }
    }
    Ok(Approved {
        sel,
        manifest_sha256: manifest_sha256.to_string(),
    })
}

// ------------------------------------------------------------ description

/// Human-readable action list printed by a dry run.
pub fn describe(plan: &Plan, sel: &BTreeSet<ProjectId>, keep_constraints: bool) -> Vec<String> {
    let mut out = vec![];
    for c in &plan.policy_changes {
        out.push(format!(
            "set {} on {}: allow {} (backup {})",
            c.constraint, c.scope, c.value, c.backup_ref
        ));
    }
    for (i, batch) in plan.order.iter().enumerate() {
        let members: Vec<&ProjectId> = batch.iter().filter(|p| sel.contains(*p)).collect();
        if members.is_empty() {
            continue;
        }
        out.push(format!("batch {}:", i + 1));
        for id in members {
            if let Some(p) = plan.project(id) {
                out.push(format!(
                    "  move {} from {} to {}",
                    p.id, p.current_parent, p.landing_parent
                ));
            }
        }
    }
    if keep_constraints {
        out.push("keep modified constraints (--keep-constraints)".into());
    } else if !plan.policy_changes.is_empty() {
        out.push("restore the backed-up constraints".into());
    }
    out
}

// -------------------------------------------------------------- constraints

async fn with_conflict_retry<T, F, Fut>(mut f: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut attempts = 0;
    loop {
        match f().await {
            Err(e) if e.kind == ErrorKind::Conflict && attempts < 5 => attempts += 1,
            other => return other,
        }
    }
}

/// Remove `value` from every unconditional rule; drop rules left empty.
fn remove_value(policy: &mut OrgPolicy, value: &str) -> bool {
    let mut changed = false;
    for r in &mut policy.rules {
        changed |= r.allowed_values.remove(value);
    }
    policy.rules.retain(|r| {
        r.enforce.is_some()
            || r.allow_all
            || r.deny_all
            || r.condition.is_some()
            || !r.allowed_values.is_empty()
            || !r.denied_values.is_empty()
    });
    changed
}

/// Back up and apply one change. The backup is persisted (`modified = true`)
/// before the policy is touched, so a crash in between is still repaired.
async fn set_constraint(gcp: &dyn Gcp, state: &StateHandle, change: &PolicyChange) -> Result<()> {
    let prior = gcp.get_policy(&change.scope, &change.constraint).await?;
    let backup = PolicyBackup {
        scope: change.scope.clone(),
        constraint: change.constraint.clone(),
        prior,
        added_value: change.value.clone(),
        modified: true,
    };
    let key = change.backup_ref.clone();
    state
        .update(move |s| {
            // Keep the first backup if a previous crashed run left one.
            s.policy_backups
                .entry(key)
                .and_modify(|b| b.modified = true)
                .or_insert(backup);
            Ok(())
        })
        .await?;
    with_conflict_retry(|| async {
        let mut policy = gcp
            .get_policy(&change.scope, &change.constraint)
            .await?
            .unwrap_or_else(|| OrgPolicy::empty(&change.constraint));
        policy.allow_value(&change.value);
        gcp.set_policy(&change.scope, policy).await
    })
    .await
}

/// Undo one backup by removing only the value we added.
async fn restore_one(gcp: &dyn Gcp, backup: &PolicyBackup) -> Result<()> {
    with_conflict_retry(|| async {
        let Some(mut current) = gcp.get_policy(&backup.scope, &backup.constraint).await? else {
            return Ok(());
        };
        remove_value(&mut current, &backup.added_value);
        if current.rules.is_empty() && backup.prior.is_none() {
            gcp.delete_policy(&backup.scope, &backup.constraint).await
        } else {
            gcp.set_policy(&backup.scope, current).await
        }
    })
    .await
}

/// Restore every constraint recorded as modified. Idempotent. Returns the
/// errors for backups that could not be restored (those stay `modified`).
pub async fn recover_constraints(gcp: &dyn Gcp, state: &StateHandle) -> Vec<String> {
    let snap = match state.snapshot().await {
        Ok(s) => s,
        Err(e) => return vec![format!("cannot read state: {e}")],
    };
    let mut errors = vec![];
    for (key, backup) in snap.pending_constraints() {
        match restore_one(gcp, backup).await {
            Ok(()) => {
                let key_owned = key.clone();
                if let Err(e) = state
                    .update(move |s| {
                        if let Some(b) = s.policy_backups.get_mut(&key_owned) {
                            b.modified = false;
                        }
                        Ok(())
                    })
                    .await
                {
                    errors.push(format!("{key}: restored but state not saved: {e}"));
                }
            }
            Err(e) => errors.push(format!("{} on {}: {e}", backup.constraint, backup.scope)),
        }
    }
    errors
}

fn pending_lines(state: &State) -> Vec<String> {
    state
        .pending_constraints()
        .map(|(_, b)| {
            format!(
                "{} on {} still allows {}",
                b.constraint, b.scope, b.added_value
            )
        })
        .collect()
}

// -------------------------------------------------------------------- moves

/// Outcome of running a body inside the constraint guard.
pub struct Guarded<T> {
    pub result: Result<T>,
    pub restored: bool,
    pub restore_errors: Vec<String>,
    /// Constraints still modified (`keep` was set), as readable lines.
    pub left: Vec<String>,
}

impl<T> Guarded<T> {
    /// The body's result, with any restore failure folded into the error so
    /// it can never be missed.
    pub fn into_result(self) -> Result<T> {
        match self.result {
            Ok(v) if self.restore_errors.is_empty() => Ok(v),
            Ok(_) => Err(Error::internal(format!(
                "constraint restore failed: {}",
                self.restore_errors.join("; ")
            ))),
            Err(e) if self.restore_errors.is_empty() => Err(e),
            Err(e) => Err(Error::new(
                e.kind,
                format!(
                    "{}; additionally, constraint restore failed: {}",
                    e.message,
                    self.restore_errors.join("; ")
                ),
            )),
        }
    }
}

/// Run `body` with `changes` applied to the org-policy constraints, restoring
/// them afterwards on success, error and panic (the panic is re-raised after
/// restoring). A crashed earlier run's leftovers are repaired first.
pub async fn with_constraints<T, F>(
    gcp: &dyn Gcp,
    state: &StateHandle,
    changes: &[PolicyChange],
    keep: bool,
    body: F,
) -> Result<Guarded<T>>
where
    F: std::future::Future<Output = Result<T>>,
{
    let leftover = recover_constraints(gcp, state).await;
    if !leftover.is_empty() {
        return Err(Error::internal(format!(
            "constraints from an earlier run could not be restored: {}",
            leftover.join("; ")
        ))
        .with_hint("fix the error, then re-run; or run `gcp-orgmove status`"));
    }
    let ran = AssertUnwindSafe(async {
        for change in changes {
            set_constraint(gcp, state, change).await?;
        }
        body.await
    })
    .catch_unwind()
    .await;

    let (restored, restore_errors, left) = if keep {
        let left = state
            .snapshot()
            .await
            .map(|s| pending_lines(&s))
            .unwrap_or_default();
        (false, vec![], left)
    } else {
        let errs = recover_constraints(gcp, state).await;
        (errs.is_empty(), errs, vec![])
    };
    match ran {
        Err(panic) => std::panic::resume_unwind(panic),
        Ok(result) => Ok(Guarded {
            result,
            restored,
            restore_errors,
            left,
        }),
    }
}

/// Why [`wait_for_operation`] stopped without success.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WaitError {
    /// The operation definitively failed (or no longer exists): forget it
    /// and issue a fresh one next time.
    Failed(String),
    /// Timed out or kept erroring: the operation may still be running, so
    /// keep its name and resume polling next time.
    Unresolved(String),
}

/// Poll a long-running operation to completion with exponential backoff.
pub(crate) async fn wait_for_operation(
    gcp: &dyn Gcp,
    op: &crate::model::Operation,
    cfg: PollConfig,
) -> std::result::Result<(), WaitError> {
    let started = Instant::now();
    let mut delay = cfg.initial;
    let mut transient = 0;
    loop {
        match gcp.poll_operation(op).await {
            Ok(OperationStatus::Done) => return Ok(()),
            Ok(OperationStatus::Failed { message, .. }) => return Err(WaitError::Failed(message)),
            Ok(OperationStatus::Running) => transient = 0,
            Err(e) if e.kind == ErrorKind::NotFound => {
                return Err(WaitError::Failed(format!(
                    "operation {} no longer exists",
                    op.name
                )))
            }
            Err(e) if e.kind.is_retryable() || e.kind == ErrorKind::Internal => {
                transient += 1;
                if transient > 5 {
                    return Err(WaitError::Unresolved(format!(
                        "polling {} kept failing: {e}",
                        op.name
                    )));
                }
            }
            Err(e) => {
                return Err(WaitError::Unresolved(format!(
                    "polling {} failed: {e}",
                    op.name
                )))
            }
        }
        if started.elapsed() > cfg.timeout {
            return Err(WaitError::Unresolved(format!(
                "timed out waiting for {}; re-run to resume",
                op.name
            )));
        }
        tokio::time::sleep(jitter(delay)).await;
        delay = (delay * 2).min(cfg.max);
    }
}

struct Ctx<'a> {
    gcp: &'a dyn Gcp,
    state: StateHandle,
    poll: PollConfig,
    cancel: CancelFlag,
    /// Set after a failure when not `continue_on_error`.
    stop: AtomicBool,
    continue_on_error: bool,
    halted_groups: Mutex<BTreeSet<String>>,
    hooks: &'a dyn ApplyHooks,
    smoke_failure: Mutex<Option<(ProjectId, String)>>,
    observer: SharedObserver,
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Moved,
    Failed(String),
    Skipped,
}

async fn fail(ctx: &Ctx<'_>, id: &ProjectId, reason: String) -> Outcome {
    let (id2, r2) = (id.clone(), reason.clone());
    let _ = ctx
        .state
        .update(move |s| {
            let p = s.ensure_project(&id2);
            p.status = Status::failed(r2);
            p.updated_at = Utc::now();
            Ok(())
        })
        .await;
    Outcome::Failed(reason)
}

async fn finish_moved(ctx: &Ctx<'_>, id: &ProjectId) -> Outcome {
    let id2 = id.clone();
    let res = ctx
        .state
        .update(move |s| {
            s.set_status(&id2, Status::Moved)?;
            s.ensure_project(&id2).operation = None;
            Ok(())
        })
        .await;
    match res {
        Ok(()) => Outcome::Moved,
        Err(e) => Outcome::Failed(format!("moved, but state could not be saved: {e}")),
    }
}

fn jitter(base: Duration) -> Duration {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    base + base.mul_f64(f64::from(nanos % 250) / 1000.0)
}

async fn poll_until_done(
    ctx: &Ctx<'_>,
    id: &ProjectId,
    landing: &Parent,
    op: crate::model::Operation,
) -> Outcome {
    let started = Instant::now();
    let mut delay = ctx.poll.initial;
    let mut transient = 0;
    loop {
        match ctx.gcp.poll_operation(&op).await {
            Ok(OperationStatus::Done) => {
                return match ctx.gcp.get_project(id).await {
                    Ok(p) if &p.parent == landing => finish_moved(ctx, id).await,
                    Ok(p) => {
                        fail(
                            ctx,
                            id,
                            format!(
                                "operation {} finished but project is under {}",
                                op.name, p.parent
                            ),
                        )
                        .await
                    }
                    Err(e) => {
                        fail(
                            ctx,
                            id,
                            format!("operation finished but verification failed: {e}"),
                        )
                        .await
                    }
                };
            }
            Ok(OperationStatus::Failed { message, .. }) => return fail(ctx, id, message).await,
            Ok(OperationStatus::Running) => transient = 0,
            Err(e) if e.kind.is_retryable() || e.kind == ErrorKind::Internal => {
                transient += 1;
                if transient > 5 {
                    return Outcome::Failed(format!("polling {} kept failing: {e}", op.name));
                }
            }
            Err(e) => return Outcome::Failed(format!("polling {} failed: {e}", op.name)),
        }
        if started.elapsed() > ctx.poll.timeout {
            // Leave the project in `Moving` with its operation recorded:
            // re-running apply resumes polling instead of re-moving.
            return Outcome::Failed(format!(
                "timed out waiting for {}; re-run apply to resume",
                op.name
            ));
        }
        tokio::time::sleep(jitter(delay)).await;
        delay = (delay * 2).min(ctx.poll.max);
    }
}

async fn start_move(ctx: &Ctx<'_>, p: &PlanProject, live_parent: &Parent) -> Outcome {
    // 1. Original parent + Moving, durable before the API call.
    let (id, landing, orig) = (p.id.clone(), p.landing_parent.clone(), live_parent.clone());
    let recorded = ctx
        .state
        .update(move |s| {
            s.set_status(&id, Status::Moving)?;
            let ps = s.ensure_project(&id);
            ps.original_parent.get_or_insert(orig);
            ps.landing_parent = Some(landing);
            Ok(())
        })
        .await;
    if let Err(e) = recorded {
        return Outcome::Failed(format!("cannot record state before move: {e}"));
    }
    // 2. Issue the move.
    let op = match ctx.gcp.move_project(&p.id, &p.landing_parent).await {
        Ok(op) => op,
        Err(e) => return fail(ctx, &p.id, e.message).await,
    };
    // 3. Persist the operation name so a crash can resume polling it.
    let (id, name) = (p.id.clone(), op.name.clone());
    if let Err(e) = ctx
        .state
        .update(move |s| {
            s.ensure_project(&id).operation = Some(name);
            Ok(())
        })
        .await
    {
        return Outcome::Failed(format!("cannot record operation: {e}"));
    }
    poll_until_done(ctx, &p.id, &p.landing_parent, op).await
}

/// Move a single project; idempotent and resumable.
async fn move_one(ctx: &Ctx<'_>, p: &PlanProject) -> Outcome {
    if ctx.cancel.load(Ordering::SeqCst) || ctx.stop.load(Ordering::SeqCst) {
        return Outcome::Skipped;
    }
    if let Some(g) = &p.group {
        if ctx.halted_groups.lock().unwrap().contains(g) {
            return Outcome::Skipped;
        }
    }
    let snap = match ctx.state.snapshot().await {
        Ok(s) => s,
        Err(e) => return Outcome::Failed(e.to_string()),
    };
    let ps = snap.project(&p.id);
    let status = ps.map(|s| s.status.clone()).unwrap_or(Status::Ready);
    let live = match ctx.gcp.get_project(&p.id).await {
        Ok(l) => l,
        Err(e) => return Outcome::Failed(format!("cannot read project: {e}")),
    };
    match status {
        Status::Moved | Status::Verified => Outcome::Moved,
        Status::Ready if live.parent == p.landing_parent => {
            // Already there (idempotency): still record where it came from.
            let (id, orig) = (p.id.clone(), p.current_parent.clone());
            let _ = ctx
                .state
                .update(move |s| {
                    s.ensure_project(&id).original_parent.get_or_insert(orig);
                    Ok(())
                })
                .await;
            finish_moved(ctx, &p.id).await
        }
        Status::Ready => start_move(ctx, p, &live.parent).await,
        Status::Moving => {
            if live.parent == p.landing_parent {
                return finish_moved(ctx, &p.id).await;
            }
            match ps.and_then(|s| s.operation.clone()) {
                Some(name) => {
                    poll_until_done(
                        ctx,
                        &p.id,
                        &p.landing_parent,
                        crate::model::Operation { name },
                    )
                    .await
                }
                // Crashed between recording `Moving` and receiving the operation.
                None => {
                    let (id, landing, orig) =
                        (p.id.clone(), p.landing_parent.clone(), live.parent.clone());
                    let _ = ctx
                        .state
                        .update(move |s| {
                            let ps = s.ensure_project(&id);
                            ps.original_parent.get_or_insert(orig);
                            ps.landing_parent = Some(landing);
                            Ok(())
                        })
                        .await;
                    match ctx.gcp.move_project(&p.id, &p.landing_parent).await {
                        Ok(op) => poll_until_done(ctx, &p.id, &p.landing_parent, op).await,
                        Err(e) => fail(ctx, &p.id, e.message).await,
                    }
                }
            }
        }
        other => Outcome::Failed(format!("project is {other:?}, not ready to move")),
    }
}

/// Move one project and apply the halt rules *immediately*, so members that
/// have not started yet (same batch, same group) see them.
async fn run_member(ctx: &Ctx<'_>, p: &PlanProject) -> Outcome {
    ctx.observer.working(format!("moving {}", p.id));
    let outcome = move_one(ctx, p).await;
    let label = match &outcome {
        Outcome::Moved => "moved",
        Outcome::Failed(_) => "FAILED",
        Outcome::Skipped => "skipped",
    };
    ctx.observer.tick(format!("{} {label}", p.id));
    match &outcome {
        Outcome::Moved => {
            if let Err(e) = ctx.hooks.after_move(&p.id).await {
                ctx.stop.store(true, Ordering::SeqCst);
                if e.kind == ErrorKind::SmokeFailed {
                    *ctx.smoke_failure.lock().unwrap() = Some((p.id.clone(), e.message));
                } else {
                    return Outcome::Failed(e.message);
                }
            }
        }
        Outcome::Failed(_) => {
            if let Some(g) = &p.group {
                ctx.halted_groups.lock().unwrap().insert(g.clone());
            }
            if !ctx.continue_on_error {
                ctx.stop.store(true, Ordering::SeqCst);
            }
        }
        Outcome::Skipped => {}
    }
    outcome
}

/// Bring selected projects to `Ready` (preflight already vetted blockers/gaps).
async fn prepare_state(
    state: &StateHandle,
    plan: &Plan,
    sel: &BTreeSet<ProjectId>,
    manifest_sha: &str,
) -> Result<()> {
    let projects: Vec<(ProjectId, Option<String>, Parent, Parent)> = plan
        .projects
        .iter()
        .filter(|p| sel.contains(&p.id))
        .map(|p| {
            (
                p.id.clone(),
                p.group.clone(),
                p.current_parent.clone(),
                p.landing_parent.clone(),
            )
        })
        .collect();
    let sha = manifest_sha.to_string();
    state
        .update(move |s| {
            s.manifest_sha256 = sha;
            for (id, group, current, landing) in projects {
                let ps = s.ensure_project(&id);
                ps.group = group;
                ps.landing_parent = Some(landing);
                ps.original_parent.get_or_insert(current);
                loop {
                    let next = match &s.projects[&id].status {
                        Status::Discovered => Status::Analyzed,
                        Status::Analyzed | Status::ParityGaps | Status::ParityFixed | Status::Failed { .. } => Status::Ready,
                        Status::Blocked => Status::Analyzed,
                        Status::RolledBack => {
                            return Err(Error::invalid(format!(
                                "project {id} was rolled back; start from a fresh state file to move it again"
                            )))
                        }
                        Status::Ready | Status::Moving | Status::Moved | Status::Verified => break,
                    };
                    s.set_status(&id, next)?;
                }
            }
            Ok(())
        })
        .await
}

async fn run_batches(
    ctx: &Ctx<'_>,
    plan: &Plan,
    sel: &BTreeSet<ProjectId>,
    opts: &ApplyOptions,
    report: &mut ApplyReport,
) {
    for batch in &plan.order {
        let members: Vec<&PlanProject> = batch
            .iter()
            .filter(|id| sel.contains(*id))
            .filter_map(|id| plan.project(id))
            .collect();
        if members.is_empty() {
            continue;
        }
        let results: Vec<(&PlanProject, Outcome)> = stream::iter(members)
            .map(|p| async move { (p, run_member(ctx, p).await) })
            .buffer_unordered(opts.concurrency.clamp(1, 16))
            .collect()
            .await;
        let mut results = results;
        results.sort_by(|a, b| a.0.id.cmp(&b.0.id));
        for (p, outcome) in results {
            match outcome {
                Outcome::Moved => report.moved.push(p.id.clone()),
                Outcome::Failed(reason) => report.failed.push((p.id.clone(), reason)),
                Outcome::Skipped => report.skipped.push(p.id.clone()),
            }
        }
        if ctx.stop.load(Ordering::SeqCst) || ctx.cancel.load(Ordering::SeqCst) {
            break;
        }
    }
    let done: BTreeSet<&ProjectId> = report
        .moved
        .iter()
        .chain(report.failed.iter().map(|(p, _)| p))
        .collect();
    let skipped: Vec<ProjectId> = plan
        .projects
        .iter()
        .filter(|p| sel.contains(&p.id) && !done.contains(&p.id) && !report.skipped.contains(&p.id))
        .map(|p| p.id.clone())
        .collect();
    report.skipped.extend(skipped);
    report.skipped.sort();
}

/// Execute the plan. Call [`preflight`] first. Constraints are always
/// restored (unless `keep_constraints`), including on panic and cancel.
pub async fn apply(
    gcp: &dyn Gcp,
    plan: &Plan,
    approved: &Approved,
    state: StateHandle,
    hooks: &dyn ApplyHooks,
    cancel: CancelFlag,
    opts: &ApplyOptions,
) -> Result<ApplyReport> {
    // Repair any earlier crash before touching state for this run.
    let leftover = recover_constraints(gcp, &state).await;
    if !leftover.is_empty() {
        return Err(Error::internal(format!(
            "constraints from an earlier run could not be restored: {}",
            leftover.join("; ")
        ))
        .with_hint("fix the error, then re-run; or run `gcp-orgmove status`"));
    }
    let sel = &approved.sel;
    prepare_state(&state, plan, sel, &approved.manifest_sha256).await?;

    let mut report = ApplyReport::default();
    let ctx = Ctx {
        gcp,
        state: state.clone(),
        poll: opts.poll,
        cancel: cancel.clone(),
        stop: AtomicBool::new(false),
        continue_on_error: opts.continue_on_error,
        halted_groups: Mutex::new(BTreeSet::new()),
        hooks,
        smoke_failure: Mutex::new(None),
        observer: opts.observer.clone(),
    };

    let guarded = with_constraints(
        gcp,
        &state,
        &plan.policy_changes,
        opts.keep_constraints,
        async {
            hooks.before_moves().await?;
            let _phase = PhaseGuard::start(&opts.observer, "Moving projects", sel.len());
            run_batches(&ctx, plan, sel, opts, &mut report).await;
            Ok(())
        },
    )
    .await?;

    report.constraints_restored = guarded.restored;
    report.restore_errors = guarded.restore_errors.clone();
    report.constraints_left = guarded.left.clone();
    report.interrupted = cancel.load(Ordering::SeqCst);
    report.smoke_failure = ctx.smoke_failure.lock().unwrap().take();
    guarded.into_result()?;
    Ok(report)
}

/// Map state to per-project status for display.
pub fn statuses(state: &State) -> BTreeMap<ProjectId, Status> {
    state
        .projects
        .iter()
        .map(|(k, v)| (k.clone(), v.status.clone()))
        .collect()
}

#[cfg(test)]
mod tests;
