//! Remediation executor (§9.3): the single place that interprets
//! [`Remediation`] data. Additive only.
//!
//! * IAM writes are read-modify-write with the policy etag, retried on conflict.
//! * Before writing, the new policy is checked to be a superset of the old
//!   one; a change that would remove access is refused.
//! * Every applied change is recorded in the state file with the prior value.

use chrono::Utc;
use gcp_orgmove_core::progress::{silent, ObserverExt, PhaseGuard, SharedObserver};
use gcp_orgmove_core::{
    AppliedRemediation, Binding, CustomRoleMode, Error, ErrorKind, Gcp, IamFixMode, IamPolicy,
    OrgPolicy, Parent, PolicyFixMode, PriorValue, ProjectId, Remediation, Resource, Result,
    StateHandle,
};

/// Project label recording the earliest expiry of any override this tool set.
pub const OVERRIDE_LABEL: &str = "orgmove-override-exp";
const OVERRIDES_NOT_ENABLED: &str =
    "policy overrides need `--policy-fix project-override` and `--allow-policy-overrides`";
const CONFLICT_RETRIES: usize = 5;
const CUSTOM_ROLES_OFF: &str = "custom_roles is off (set `custom_roles: recreate` in the manifest)";

/// One remediation to run, with the context needed to scope it.
#[derive(Debug, Clone)]
pub struct FixItem {
    pub finding: Option<String>,
    pub project: ProjectId,
    pub landing: Parent,
    pub remediation: Remediation,
}

#[derive(Debug, Clone, Copy)]
pub struct FixOptions {
    pub iam_fix: IamFixMode,
    pub custom_roles: CustomRoleMode,
    pub policy_fix: PolicyFixMode,
    /// `--allow-policy-overrides`: required in addition to `policy_fix`.
    pub allow_policy_overrides: bool,
    pub override_expiry: std::time::Duration,
    pub now: chrono::DateTime<Utc>,
    /// `--yes-widen-access`: required for `folder` mode.
    pub widen_access: bool,
    pub dry_run: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Applied,
    /// The access was already there; nothing written.
    AlreadyPresent,
    /// Not auto-fixable or disabled by mode; the reason is user-facing.
    Skipped(String),
    /// Dry run: what would be done.
    WouldApply,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixResult {
    pub finding: Option<String>,
    pub project: ProjectId,
    pub description: String,
    pub outcome: std::result::Result<Outcome, String>,
}

/// Apply the IAM fix mode to a remediation: `project` keeps the project
/// scope, `folder` moves the grant to the landing folder (widening).
fn scope_for(item: &FixItem, mode: IamFixMode) -> Option<Resource> {
    let Remediation::AddIamBinding { scope, .. } = &item.remediation else {
        return None;
    };
    match (mode, &item.landing) {
        (IamFixMode::Folder, Parent::Folder(f)) => Some(Resource::Folder(f.clone())),
        // Landing at the org root: never widen to the whole organization.
        _ => Some(scope.clone()),
    }
}

pub fn describe(item: &FixItem, mode: IamFixMode) -> String {
    match &item.remediation {
        Remediation::AddIamBinding { binding, .. } => {
            let scope = scope_for(item, mode).expect("AddIamBinding has a scope");
            format!(
                "grant {} to {} on {scope}",
                binding.role,
                binding
                    .members
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        Remediation::Manual { instructions } => format!("manual: {instructions}"),
        Remediation::CreateCustomRole { role, .. } => format!("create custom role {}", role.name),
        Remediation::RewriteBinding { from, to, .. } => {
            format!("add bindings for {to} alongside {from}")
        }
        Remediation::SetPolicyOverride { policy, .. } => {
            format!("set project policy override for {}", policy.constraint)
        }
    }
}

/// Add `binding` to the policy on `scope`. Returns the prior policy if a
/// write happened, or `None` if the access was already present.
async fn add_binding(
    gcp: &dyn Gcp,
    scope: &Resource,
    binding: &Binding,
) -> Result<Option<IamPolicy>> {
    for _ in 0..=CONFLICT_RETRIES {
        let prior = gcp.get_iam(scope).await?;
        let mut next = prior.clone();
        if !next.add_binding(binding) {
            return Ok(None);
        }
        // Additive-only guard: nothing may be removed by this tool here.
        if !prior.is_subset_of(&next) {
            return Err(Error::internal(format!(
                "refusing IAM write on {scope}: it would remove existing access"
            )));
        }
        match gcp.set_iam(scope, next).await {
            Ok(_) => return Ok(Some(prior)),
            Err(e) if e.kind == ErrorKind::Conflict => continue,
            Err(e) => return Err(e),
        }
    }
    Err(Error::new(
        ErrorKind::Conflict,
        format!("IAM policy on {scope} kept changing; gave up after retries"),
    )
    .with_resource(scope))
}

/// Copy every binding of role `from` on `scope` to role `to`. Returns the
/// prior policy and the bindings actually added, or `None` if nothing changed.
async fn rewrite_bindings(
    gcp: &dyn Gcp,
    scope: &Resource,
    from: &gcp_orgmove_core::RoleName,
    to: &gcp_orgmove_core::RoleName,
) -> Result<Option<(IamPolicy, Vec<Binding>)>> {
    for _ in 0..=CONFLICT_RETRIES {
        let prior = gcp.get_iam(scope).await?;
        let mut next = prior.clone();
        let mut added = vec![];
        for b in prior.bindings.iter().filter(|b| &b.role == from) {
            let candidate = Binding {
                role: to.clone(),
                members: b.members.clone(),
                condition: b.condition.clone(),
            };
            let existing: std::collections::BTreeSet<String> = prior
                .bindings
                .iter()
                .filter(|x| x.role == candidate.role && x.condition == candidate.condition)
                .flat_map(|x| x.members.iter().cloned())
                .collect();
            let delta: std::collections::BTreeSet<String> =
                candidate.members.difference(&existing).cloned().collect();
            if !delta.is_empty() {
                let d = Binding {
                    members: delta,
                    ..candidate
                };
                next.add_binding(&d);
                added.push(d);
            }
        }
        if added.is_empty() {
            return Ok(None);
        }
        if !prior.is_subset_of(&next) {
            return Err(Error::internal(format!(
                "refusing IAM write on {scope}: it would remove existing access"
            )));
        }
        match gcp.set_iam(scope, next).await {
            Ok(_) => return Ok(Some((prior, added))),
            Err(e) if e.kind == ErrorKind::Conflict => continue,
            Err(e) => return Err(e),
        }
    }
    Err(Error::new(
        ErrorKind::Conflict,
        format!("IAM policy on {scope} kept changing; gave up after retries"),
    )
    .with_resource(scope))
}

/// ISO date `override_expiry` from now.
fn expiry_date(opts: &FixOptions) -> String {
    let d = chrono::Duration::from_std(opts.override_expiry)
        .unwrap_or_else(|_| chrono::Duration::days(30));
    (opts.now + d).format("%Y-%m-%d").to_string()
}

/// `YYYY-MM-DD` -> `YYYYMMDD`: compact, sortable, and a valid label value.
fn label_value(iso: &str) -> String {
    iso.replace('-', "")
}

async fn apply_override(
    gcp: &dyn Gcp,
    state: &StateHandle,
    item: &FixItem,
    project: &ProjectId,
    policy: &OrgPolicy,
    expires: &str,
) -> Result<Outcome> {
    let scope = Resource::Project(project.clone());
    let executed = Remediation::SetPolicyOverride {
        project: project.clone(),
        policy: policy.clone(),
        expires: expires.to_string(),
    };
    let prior = gcp.get_policy(&scope, &policy.constraint).await?;

    // Already exactly this policy: nothing to do (and nothing to revert later).
    if prior
        .as_ref()
        .is_some_and(|p| p.rules == policy.rules && !p.inherit_from_parent && !p.reset)
    {
        record(state, item, executed, vec![]).await?;
        return Ok(Outcome::AlreadyPresent);
    }

    let mut desired = policy.clone();
    desired.inherit_from_parent = false;
    desired.reset = false;
    desired.etag = prior.as_ref().map(|p| p.etag.clone()).unwrap_or_default();
    gcp.set_policy(&scope, desired).await?;

    // Audit label: keep the earliest expiry across all overrides on the project.
    let live = gcp.get_project(project).await?;
    let old_labels = live.labels.clone();
    let new_value = label_value(expires);
    let mut labels = old_labels.clone();
    let keep = old_labels
        .get(OVERRIDE_LABEL)
        .filter(|existing| existing.as_str() < new_value.as_str())
        .cloned();
    labels.insert(OVERRIDE_LABEL.to_string(), keep.unwrap_or(new_value));
    gcp.set_project_labels(project, labels).await?;

    record(
        state,
        item,
        executed,
        vec![
            PriorValue::PolicyOverride {
                project: project.clone(),
                prior,
            },
            PriorValue::Labels {
                project: project.clone(),
                labels: old_labels,
            },
        ],
    )
    .await?;
    Ok(Outcome::Applied)
}

async fn record(
    state: &StateHandle,
    item: &FixItem,
    executed: Remediation,
    prior: Vec<PriorValue>,
) -> Result<()> {
    let entry = AppliedRemediation {
        finding: item.finding.clone(),
        project: item.project.clone(),
        remediation: executed,
        prior,
        applied_at: Utc::now(),
        reverted: false,
        pruned: false,
    };
    state
        .update(move |s| {
            s.applied.push(entry);
            Ok(())
        })
        .await
}

async fn run_one(
    gcp: &dyn Gcp,
    state: &StateHandle,
    item: &FixItem,
    opts: &FixOptions,
) -> Result<Outcome> {
    match &item.remediation {
        Remediation::Manual { instructions } => Ok(Outcome::Skipped(format!(
            "needs manual action: {instructions}"
        ))),
        Remediation::AddIamBinding { binding, .. } => {
            if opts.iam_fix == IamFixMode::Off {
                return Ok(Outcome::Skipped("iam_fix is off".into()));
            }
            let scope = scope_for(item, opts.iam_fix).expect("AddIamBinding has a scope");
            if opts.dry_run {
                return Ok(Outcome::WouldApply);
            }
            let executed = Remediation::AddIamBinding {
                scope: scope.clone(),
                binding: binding.clone(),
            };
            match add_binding(gcp, &scope, binding).await? {
                Some(prior) => {
                    record(
                        state,
                        item,
                        executed,
                        vec![PriorValue::Iam {
                            scope,
                            policy: prior,
                        }],
                    )
                    .await?;
                    Ok(Outcome::Applied)
                }
                None => {
                    // Already present: recorded with no prior value, so a later
                    // revert never removes access this tool did not add.
                    record(state, item, executed, vec![]).await?;
                    Ok(Outcome::AlreadyPresent)
                }
            }
        }
        Remediation::CreateCustomRole { dest_org, role } => {
            if opts.custom_roles != CustomRoleMode::Recreate {
                return Ok(Outcome::Skipped(CUSTOM_ROLES_OFF.into()));
            }
            if opts.dry_run {
                return Ok(Outcome::WouldApply);
            }
            if gcp.get_custom_role(&role.name).await?.is_some() {
                record(state, item, item.remediation.clone(), vec![]).await?;
                return Ok(Outcome::AlreadyPresent);
            }
            gcp.create_custom_role(dest_org, role.clone()).await?;
            let prior = vec![PriorValue::CreatedRole {
                name: role.name.clone(),
            }];
            record(state, item, item.remediation.clone(), prior).await?;
            Ok(Outcome::Applied)
        }
        Remediation::RewriteBinding { project, from, to } => {
            if opts.custom_roles != CustomRoleMode::Recreate {
                return Ok(Outcome::Skipped(CUSTOM_ROLES_OFF.into()));
            }
            if opts.dry_run {
                return Ok(Outcome::WouldApply);
            }
            let scope = Resource::Project(project.clone());
            match rewrite_bindings(gcp, &scope, from, to).await? {
                None => {
                    record(state, item, item.remediation.clone(), vec![]).await?;
                    Ok(Outcome::AlreadyPresent)
                }
                Some((prior, added)) => {
                    // One entry per binding actually added, so a revert removes exactly these.
                    for binding in added {
                        let executed = Remediation::AddIamBinding {
                            scope: scope.clone(),
                            binding,
                        };
                        let prior_value = PriorValue::Iam {
                            scope: scope.clone(),
                            policy: prior.clone(),
                        };
                        record(state, item, executed, vec![prior_value]).await?;
                    }
                    Ok(Outcome::Applied)
                }
            }
        }
        Remediation::SetPolicyOverride {
            project,
            policy,
            expires,
        } => {
            if opts.policy_fix != PolicyFixMode::ProjectOverride || !opts.allow_policy_overrides {
                return Ok(Outcome::Skipped(OVERRIDES_NOT_ENABLED.into()));
            }
            if opts.dry_run {
                return Ok(Outcome::WouldApply);
            }
            let expires = if expires.is_empty() {
                expiry_date(opts)
            } else {
                expires.clone()
            };
            apply_override(gcp, state, item, project, policy, &expires).await
        }
    }
}

/// Run the remediations in order. A failure on one item is reported and the
/// rest still run, so one bad grant does not hide the others.
pub async fn execute(
    gcp: &dyn Gcp,
    state: &StateHandle,
    items: &[FixItem],
    opts: &FixOptions,
) -> Result<Vec<FixResult>> {
    execute_with(gcp, state, items, opts, &silent()).await
}

/// [`execute`] reporting progress. Previews (`dry_run`) report nothing: they
/// are instant and make no calls worth a bar.
pub async fn execute_with(
    gcp: &dyn Gcp,
    state: &StateHandle,
    items: &[FixItem],
    opts: &FixOptions,
    observer: &SharedObserver,
) -> Result<Vec<FixResult>> {
    if opts.iam_fix == IamFixMode::Folder && !opts.dry_run && !opts.widen_access {
        return Err(Error::invalid(
            "--iam-fix folder grants access to every project in the landing folder; pass --yes-widen-access to confirm",
        ));
    }
    // Roles must exist before any binding refers to them.
    let mut ordered: Vec<&FixItem> = items.iter().collect();
    ordered.sort_by_key(|i| !matches!(i.remediation, Remediation::CreateCustomRole { .. }));
    let _phase =
        (!opts.dry_run).then(|| PhaseGuard::start(observer, "Applying changes", ordered.len()));
    let mut out = vec![];
    for item in ordered {
        if !opts.dry_run {
            observer.working(describe(item, opts.iam_fix));
        }
        let outcome = run_one(gcp, state, item, opts).await.map_err(|e| e.message);
        if !opts.dry_run {
            observer.tick(format!(
                "{} {}",
                item.project,
                if outcome.is_ok() { "done" } else { "FAILED" }
            ));
        }
        out.push(FixResult {
            finding: item.finding.clone(),
            project: item.project.clone(),
            description: describe(item, opts.iam_fix),
            outcome,
        });
    }
    Ok(out)
}

// ------------------------------------------------------------------ revert

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevertOutcome {
    Removed,
    /// Access was already present before the tool ran; left alone.
    NotAddedByTool,
    /// The binding is already gone.
    AlreadyGone,
    WouldRemove,
    /// Access removed by `parity prune` was put back.
    Restored,
    WouldRestore,
    Skipped(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevertResult {
    pub project: ProjectId,
    pub description: String,
    pub outcome: std::result::Result<RevertOutcome, String>,
}

/// Remove exactly `members` from the `(role, condition)` binding on `scope`.
/// Returns whether anything was removed.
async fn remove_members(
    gcp: &dyn Gcp,
    scope: &Resource,
    binding: &Binding,
    members: &std::collections::BTreeSet<String>,
) -> Result<bool> {
    for _ in 0..=CONFLICT_RETRIES {
        let mut policy = gcp.get_iam(scope).await?;
        let mut changed = false;
        for b in policy
            .bindings
            .iter_mut()
            .filter(|b| b.role == binding.role && b.condition == binding.condition)
        {
            let before = b.members.len();
            b.members.retain(|m| !members.contains(m));
            changed |= b.members.len() != before;
        }
        if !changed {
            return Ok(false);
        }
        policy.bindings.retain(|b| !b.members.is_empty());
        match gcp.set_iam(scope, policy).await {
            Ok(_) => return Ok(true),
            Err(e) if e.kind == ErrorKind::Conflict => continue,
            Err(e) => return Err(e),
        }
    }
    Err(Error::new(
        ErrorKind::Conflict,
        format!("IAM policy on {scope} kept changing; gave up after retries"),
    )
    .with_resource(scope))
}

/// Reverse the remediations this tool applied for `projects`, newest first,
/// removing only the access it added (never what was there before).
pub async fn revert(
    gcp: &dyn Gcp,
    state: &StateHandle,
    projects: &std::collections::BTreeSet<ProjectId>,
    dry_run: bool,
) -> Result<Vec<RevertResult>> {
    let snap = state.snapshot().await?;
    let mut out = vec![];

    // First put back what `parity prune` removed, so the subsequent revert
    // sees the policy as it was when the remediations were applied.
    for (i, rec) in snap.pruned.iter().enumerate().rev() {
        if rec.restored || !projects.contains(&rec.project) {
            continue;
        }
        let description = format!(
            "restore {} to {} on {} (removed by parity prune)",
            rec.binding
                .members
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join(", "),
            rec.binding.role,
            rec.scope
        );
        let outcome = if dry_run {
            Ok(RevertOutcome::WouldRestore)
        } else {
            match add_binding(gcp, &rec.scope, &rec.binding).await {
                Ok(_) => {
                    state
                        .update(move |s| {
                            if let Some(r) = s.pruned.get_mut(i) {
                                r.restored = true;
                            }
                            Ok(())
                        })
                        .await?;
                    Ok(RevertOutcome::Restored)
                }
                Err(e) => Err(e.message),
            }
        };
        out.push(RevertResult {
            project: rec.project.clone(),
            description,
            outcome,
        });
    }

    for (idx, entry) in snap.applied.iter().enumerate().rev() {
        if entry.reverted || !projects.contains(&entry.project) {
            continue;
        }
        let (description, outcome) = match &entry.remediation {
            Remediation::AddIamBinding { scope, binding } => {
                let description = format!(
                    "remove {} from {} on {scope}",
                    binding
                        .members
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", "),
                    binding.role
                );
                let outcome = if entry.prior.is_empty() {
                    Ok(RevertOutcome::NotAddedByTool)
                } else if dry_run {
                    Ok(RevertOutcome::WouldRemove)
                } else {
                    // Only the members that were absent before we ran.
                    let before = entry.prior.iter().find_map(|p| match p {
                        PriorValue::Iam { policy, .. } => Some(policy),
                        _ => None,
                    });
                    let existed: std::collections::BTreeSet<String> = before
                        .map(|p| {
                            p.bindings
                                .iter()
                                .filter(|b| {
                                    b.role == binding.role && b.condition == binding.condition
                                })
                                .flat_map(|b| b.members.iter().cloned())
                                .collect()
                        })
                        .unwrap_or_default();
                    let to_remove: std::collections::BTreeSet<String> =
                        binding.members.difference(&existed).cloned().collect();
                    remove_members(gcp, scope, binding, &to_remove)
                        .await
                        .map(|removed| {
                            if removed {
                                RevertOutcome::Removed
                            } else {
                                RevertOutcome::AlreadyGone
                            }
                        })
                        .map_err(|e| e.message)
                };
                (description, outcome)
            }
            Remediation::CreateCustomRole { role, .. } => {
                let description = format!("delete custom role {}", role.name);
                let created = entry
                    .prior
                    .iter()
                    .any(|p| matches!(p, PriorValue::CreatedRole { .. }));
                let outcome = if !created {
                    Ok(RevertOutcome::NotAddedByTool)
                } else if dry_run {
                    Ok(RevertOutcome::WouldRemove)
                } else {
                    match gcp.delete_custom_role(&role.name).await {
                        Ok(()) => Ok(RevertOutcome::Removed),
                        Err(e) if e.kind == ErrorKind::NotFound => Ok(RevertOutcome::AlreadyGone),
                        Err(e) => Err(e.message),
                    }
                };
                (description, outcome)
            }
            Remediation::SetPolicyOverride {
                project, policy, ..
            } if !entry.prior.is_empty() => {
                let description = format!(
                    "remove the policy override for {} on {project}",
                    policy.constraint
                );
                let outcome = if dry_run {
                    Ok(RevertOutcome::WouldRemove)
                } else {
                    revert_override(gcp, &snap, idx, entry)
                        .await
                        .map_err(|e| e.message)
                };
                (description, outcome)
            }
            other if entry.prior.is_empty() => {
                (describe_any(other), Ok(RevertOutcome::NotAddedByTool))
            }
            other => (
                describe_any(other),
                Ok(RevertOutcome::Skipped(
                    "reverting this remediation type is not implemented yet (DKT-50)".into(),
                )),
            ),
        };
        if !dry_run
            && matches!(
                outcome,
                Ok(RevertOutcome::Removed
                    | RevertOutcome::NotAddedByTool
                    | RevertOutcome::AlreadyGone)
            )
        {
            state
                .update(move |s| {
                    if let Some(a) = s.applied.get_mut(idx) {
                        a.reverted = true;
                    }
                    Ok(())
                })
                .await?;
        }
        out.push(RevertResult {
            project: entry.project.clone(),
            description,
            outcome,
        });
    }
    Ok(out)
}

/// Restore the policy that was on the project before the override, and drop
/// the audit label once no other override remains.
async fn revert_override(
    gcp: &dyn Gcp,
    snap: &gcp_orgmove_core::State,
    idx: usize,
    entry: &AppliedRemediation,
) -> Result<RevertOutcome> {
    let Remediation::SetPolicyOverride {
        project, policy, ..
    } = &entry.remediation
    else {
        return Err(Error::internal("not an override"));
    };
    let scope = Resource::Project(project.clone());
    let prior: Option<OrgPolicy> = entry
        .prior
        .iter()
        .find_map(|p| match p {
            PriorValue::PolicyOverride { prior, .. } => Some(prior.clone()),
            _ => None,
        })
        .unwrap_or(None);
    for _ in 0..=CONFLICT_RETRIES {
        let current = gcp.get_policy(&scope, &policy.constraint).await?;
        let result = match (&prior, current) {
            (_, None) => {
                finish_label(gcp, snap, idx, project).await?;
                return Ok(RevertOutcome::AlreadyGone);
            }
            (None, Some(_)) => gcp.delete_policy(&scope, &policy.constraint).await,
            (Some(p), Some(cur)) => {
                let mut restore = p.clone();
                restore.etag = cur.etag;
                gcp.set_policy(&scope, restore).await
            }
        };
        match result {
            Ok(()) => {
                finish_label(gcp, snap, idx, project).await?;
                return Ok(RevertOutcome::Removed);
            }
            Err(e) if e.kind == ErrorKind::Conflict => continue,
            Err(e) => return Err(e),
        }
    }
    Err(Error::new(
        ErrorKind::Conflict,
        format!("policy on {scope} kept changing; gave up after retries"),
    )
    .with_resource(scope))
}

/// Remove the audit label if this was the project's last active override.
async fn finish_label(
    gcp: &dyn Gcp,
    snap: &gcp_orgmove_core::State,
    idx: usize,
    project: &ProjectId,
) -> Result<()> {
    let others = snap.applied.iter().enumerate().any(|(i, a)| {
        i != idx
            && !a.reverted
            && &a.project == project
            && matches!(a.remediation, Remediation::SetPolicyOverride { .. })
            && !a.prior.is_empty()
    });
    if others {
        return Ok(());
    }
    let live = gcp.get_project(project).await?;
    if live.labels.contains_key(OVERRIDE_LABEL) {
        let mut labels = live.labels;
        labels.remove(OVERRIDE_LABEL);
        gcp.set_project_labels(project, labels).await?;
    }
    Ok(())
}

fn describe_any(r: &Remediation) -> String {
    match r {
        Remediation::CreateCustomRole { role, .. } => format!("delete custom role {}", role.name),
        Remediation::RewriteBinding { to, .. } => format!("remove bindings for {to}"),
        Remediation::SetPolicyOverride { policy, .. } => {
            format!("remove policy override for {}", policy.constraint)
        }
        Remediation::Manual { instructions } => format!("manual: {instructions}"),
        Remediation::AddIamBinding { .. } => unreachable!("handled by the caller"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gcp_orgmove_core::fake::FakeGcp;
    use gcp_orgmove_core::StateStore;

    fn pid(s: &str) -> ProjectId {
        s.parse().unwrap()
    }

    fn item(role: &str, member: &str) -> FixItem {
        FixItem {
            finding: Some("F-1".into()),
            project: pid("proj-aaaa"),
            landing: "folders/20".parse().unwrap(),
            remediation: Remediation::AddIamBinding {
                scope: "projects/proj-aaaa".parse().unwrap(),
                binding: Binding {
                    role: gcp_orgmove_core::RoleName::new(role),
                    members: [member.to_string()].into(),
                    condition: None,
                },
            },
        }
    }

    fn opts(mode: IamFixMode) -> FixOptions {
        FixOptions {
            iam_fix: mode,
            custom_roles: CustomRoleMode::Recreate,
            policy_fix: PolicyFixMode::Off,
            allow_policy_overrides: false,
            override_expiry: std::time::Duration::from_secs(30 * 86_400),
            now: "2026-10-05T12:00:00Z".parse().unwrap(),
            widen_access: false,
            dry_run: false,
        }
    }

    fn world() -> FakeGcp {
        let f = FakeGcp::new();
        f.org("111").org("222");
        f.folder("10", "organizations/111");
        f.folder("20", "organizations/222");
        f.project("proj-aaaa", "1001", "folders/10");
        f.grant("projects/proj-aaaa", "roles/owner", "user:o@x.com");
        f
    }

    async fn store() -> (StateStore, tempfile::TempDir) {
        let d = tempfile::tempdir().unwrap();
        (StateStore::open(&d.path().join("s.json")).await.unwrap(), d)
    }

    #[tokio::test]
    async fn grants_on_the_project_and_records_the_prior_policy() {
        let (g, (st, _d)) = (world(), store().await);
        let r = execute(
            &g,
            &st.handle(),
            &[item("roles/viewer", "group:eng@x.com")],
            &opts(IamFixMode::Project),
        )
        .await
        .unwrap();
        assert_eq!(r[0].outcome, Ok(Outcome::Applied));
        let after = g.iam_at("projects/proj-aaaa");
        assert!(after
            .bindings
            .iter()
            .any(|b| b.role.as_str() == "roles/viewer" && b.members.contains("group:eng@x.com")));
        assert!(
            after
                .bindings
                .iter()
                .any(|b| b.role.as_str() == "roles/owner"),
            "existing access untouched"
        );
        let s = st.handle().snapshot().await.unwrap();
        assert_eq!(s.applied.len(), 1);
        assert_eq!(s.applied[0].finding.as_deref(), Some("F-1"));
        match &s.applied[0].prior[0] {
            PriorValue::Iam { policy, .. } => assert_eq!(policy.bindings.len(), 1),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn is_idempotent() {
        let (g, (st, _d)) = (world(), store().await);
        let it = item("roles/viewer", "group:eng@x.com");
        execute(
            &g,
            &st.handle(),
            std::slice::from_ref(&it),
            &opts(IamFixMode::Project),
        )
        .await
        .unwrap();
        g.clear_calls();
        let r = execute(&g, &st.handle(), &[it], &opts(IamFixMode::Project))
            .await
            .unwrap();
        assert_eq!(r[0].outcome, Ok(Outcome::AlreadyPresent));
        assert!(g.mutating_calls().is_empty());
        // the no-op is recorded with no prior value so revert can't remove it
        let s = st.handle().snapshot().await.unwrap();
        assert!(s.applied.last().unwrap().prior.is_empty());
    }

    #[tokio::test]
    async fn retries_etag_conflicts_with_a_fresh_read() {
        let (g, (st, _d)) = (world(), store().await);
        g.inject_fault("set_iam", Error::new(ErrorKind::Conflict, "etag"));
        let r = execute(
            &g,
            &st.handle(),
            &[item("roles/viewer", "user:a@x.com")],
            &opts(IamFixMode::Project),
        )
        .await
        .unwrap();
        assert_eq!(r[0].outcome, Ok(Outcome::Applied));
        assert_eq!(g.calls_to("get_iam"), 2);
    }

    #[tokio::test]
    async fn gives_up_after_repeated_conflicts() {
        let (g, (st, _d)) = (world(), store().await);
        for _ in 0..10 {
            g.inject_fault("set_iam", Error::new(ErrorKind::Conflict, "etag"));
        }
        let r = execute(
            &g,
            &st.handle(),
            &[item("roles/viewer", "user:a@x.com")],
            &opts(IamFixMode::Project),
        )
        .await
        .unwrap();
        assert!(r[0].outcome.is_err());
        assert!(
            st.handle().snapshot().await.unwrap().applied.is_empty(),
            "nothing recorded for a failed write"
        );
    }

    #[tokio::test]
    async fn dry_run_changes_nothing() {
        let (g, (st, _d)) = (world(), store().await);
        let mut o = opts(IamFixMode::Project);
        o.dry_run = true;
        let r = execute(
            &g,
            &st.handle(),
            &[item("roles/viewer", "user:a@x.com")],
            &o,
        )
        .await
        .unwrap();
        assert_eq!(r[0].outcome, Ok(Outcome::WouldApply));
        assert!(r[0]
            .description
            .contains("grant roles/viewer to user:a@x.com on projects/proj-aaaa"));
        assert!(g.mutating_calls().is_empty());
        assert!(st.handle().snapshot().await.unwrap().applied.is_empty());
    }

    #[tokio::test]
    async fn folder_mode_needs_consent_then_grants_on_the_landing_folder() {
        let (g, (st, _d)) = (world(), store().await);
        let it = item("roles/viewer", "user:a@x.com");
        let e = execute(
            &g,
            &st.handle(),
            std::slice::from_ref(&it),
            &opts(IamFixMode::Folder),
        )
        .await
        .unwrap_err();
        assert_eq!(e.exit_code(), 2);
        assert!(e.message.contains("--yes-widen-access"));
        assert!(g.mutating_calls().is_empty());

        let mut o = opts(IamFixMode::Folder);
        o.widen_access = true;
        let r = execute(&g, &st.handle(), &[it], &o).await.unwrap();
        assert_eq!(r[0].outcome, Ok(Outcome::Applied));
        assert!(g
            .iam_at("folders/20")
            .bindings
            .iter()
            .any(|b| b.role.as_str() == "roles/viewer"));
        assert!(!g
            .iam_at("projects/proj-aaaa")
            .bindings
            .iter()
            .any(|b| b.role.as_str() == "roles/viewer"));
        let s = st.handle().snapshot().await.unwrap();
        match &s.applied[0].remediation {
            Remediation::AddIamBinding { scope, .. } => assert_eq!(scope.to_string(), "folders/20"),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn folder_mode_never_widens_to_the_organization() {
        let (g, (st, _d)) = (world(), store().await);
        let mut it = item("roles/viewer", "user:a@x.com");
        it.landing = "organizations/222".parse().unwrap();
        let mut o = opts(IamFixMode::Folder);
        o.widen_access = true;
        execute(&g, &st.handle(), &[it], &o).await.unwrap();
        assert!(g.iam_at("organizations/222").bindings.is_empty());
        assert!(g
            .iam_at("projects/proj-aaaa")
            .bindings
            .iter()
            .any(|b| b.role.as_str() == "roles/viewer"));
    }

    #[tokio::test]
    async fn off_and_manual_are_skipped_not_executed() {
        let (g, (st, _d)) = (world(), store().await);
        let r = execute(
            &g,
            &st.handle(),
            &[item("roles/viewer", "user:a@x.com")],
            &opts(IamFixMode::Off),
        )
        .await
        .unwrap();
        assert!(matches!(&r[0].outcome, Ok(Outcome::Skipped(_))));
        let mut manual = item("x", "y");
        manual.remediation = Remediation::Manual {
            instructions: "ask the network team".into(),
        };
        let r = execute(&g, &st.handle(), &[manual], &opts(IamFixMode::Project))
            .await
            .unwrap();
        assert!(matches!(&r[0].outcome, Ok(Outcome::Skipped(m)) if m.contains("network team")));
        assert!(g.mutating_calls().is_empty());
    }

    #[tokio::test]
    async fn one_failure_does_not_stop_the_rest() {
        let (g, (st, _d)) = (world(), store().await);
        g.inject_fault("get_iam", Error::new(ErrorKind::PermissionDenied, "no"));
        let items = [
            item("roles/viewer", "user:a@x.com"),
            item("roles/editor", "user:b@x.com"),
        ];
        let r = execute(&g, &st.handle(), &items, &opts(IamFixMode::Project))
            .await
            .unwrap();
        assert!(r[0].outcome.is_err());
        assert_eq!(r[1].outcome, Ok(Outcome::Applied));
    }

    #[test]
    fn resulting_policy_is_always_a_superset() {
        use proptest::prelude::*;
        proptest!(|(existing in proptest::collection::vec(("[a-c]", "[x-z]"), 0..6), add in ("[a-c]", "[x-z]"))| {
            let mut p = IamPolicy::default();
            for (r, m) in &existing {
                p.add_binding(&Binding { role: gcp_orgmove_core::RoleName::new(format!("roles/{r}")), members: [format!("user:{m}")].into(), condition: None });
            }
            let before = p.clone();
            p.add_binding(&Binding { role: gcp_orgmove_core::RoleName::new(format!("roles/{}", add.0)), members: [format!("user:{}", add.1)].into(), condition: None });
            prop_assert!(before.is_subset_of(&p));
        });
    }

    #[tokio::test]
    async fn revert_removes_exactly_what_was_added() {
        let (g, (st, _d)) = (world(), store().await);
        g.grant("projects/proj-aaaa", "roles/viewer", "user:keep@x.com"); // pre-existing, same role
        let it = item("roles/viewer", "group:eng@x.com");
        execute(
            &g,
            &st.handle(),
            std::slice::from_ref(&it),
            &opts(IamFixMode::Project),
        )
        .await
        .unwrap();
        let set: std::collections::BTreeSet<ProjectId> = [pid("proj-aaaa")].into();
        let r = revert(&g, &st.handle(), &set, false).await.unwrap();
        assert_eq!(r[0].outcome, Ok(RevertOutcome::Removed));
        let pol = g.iam_at("projects/proj-aaaa");
        let viewers = pol
            .bindings
            .iter()
            .find(|b| b.role.as_str() == "roles/viewer")
            .unwrap();
        assert!(
            viewers.members.contains("user:keep@x.com")
                && !viewers.members.contains("group:eng@x.com")
        );
        assert!(pol
            .bindings
            .iter()
            .any(|b| b.role.as_str() == "roles/owner"));
        assert!(st.handle().snapshot().await.unwrap().applied[0].reverted);
        // idempotent: nothing left to revert
        assert!(revert(&g, &st.handle(), &set, false)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn revert_never_removes_access_that_predated_the_tool() {
        let (g, (st, _d)) = (world(), store().await);
        g.grant("projects/proj-aaaa", "roles/viewer", "group:eng@x.com");
        execute(
            &g,
            &st.handle(),
            &[item("roles/viewer", "group:eng@x.com")],
            &opts(IamFixMode::Project),
        )
        .await
        .unwrap();
        g.clear_calls();
        let set: std::collections::BTreeSet<ProjectId> = [pid("proj-aaaa")].into();
        let r = revert(&g, &st.handle(), &set, false).await.unwrap();
        assert_eq!(r[0].outcome, Ok(RevertOutcome::NotAddedByTool));
        assert!(g.mutating_calls().is_empty());
        assert!(g
            .iam_at("projects/proj-aaaa")
            .bindings
            .iter()
            .any(|b| b.members.contains("group:eng@x.com")));
    }

    #[tokio::test]
    async fn revert_dry_run_and_other_projects_are_untouched() {
        let (g, (st, _d)) = (world(), store().await);
        execute(
            &g,
            &st.handle(),
            &[item("roles/viewer", "group:eng@x.com")],
            &opts(IamFixMode::Project),
        )
        .await
        .unwrap();
        g.clear_calls();
        let set: std::collections::BTreeSet<ProjectId> = [pid("proj-aaaa")].into();
        let r = revert(&g, &st.handle(), &set, true).await.unwrap();
        assert_eq!(r[0].outcome, Ok(RevertOutcome::WouldRemove));
        assert!(g.mutating_calls().is_empty());
        let other: std::collections::BTreeSet<ProjectId> = [pid("proj-zzzz")].into();
        assert!(revert(&g, &st.handle(), &other, false)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn revert_handles_a_binding_someone_already_removed() {
        let (g, (st, _d)) = (world(), store().await);
        execute(
            &g,
            &st.handle(),
            &[item("roles/viewer", "group:eng@x.com")],
            &opts(IamFixMode::Project),
        )
        .await
        .unwrap();
        let r: Resource = "projects/proj-aaaa".parse().unwrap();
        let mut pol = gcp_orgmove_core::Gcp::get_iam(&g, &r).await.unwrap();
        pol.bindings.retain(|b| b.role.as_str() != "roles/viewer");
        gcp_orgmove_core::Gcp::set_iam(&g, &r, pol).await.unwrap();
        let set: std::collections::BTreeSet<ProjectId> = [pid("proj-aaaa")].into();
        let res = revert(&g, &st.handle(), &set, false).await.unwrap();
        assert_eq!(res[0].outcome, Ok(RevertOutcome::AlreadyGone));
    }

    fn role_def(org: &str) -> gcp_orgmove_core::CustomRole {
        gcp_orgmove_core::CustomRole {
            name: gcp_orgmove_core::RoleName::new(format!("organizations/{org}/roles/deployer")),
            title: "Deployer".into(),
            description: String::new(),
            permissions: ["compute.instances.get".to_string()].into(),
            stage: gcp_orgmove_core::RoleStage::Ga,
        }
    }

    fn create_item() -> FixItem {
        FixItem {
            finding: Some("F-create".into()),
            project: pid("proj-aaaa"),
            landing: "folders/20".parse().unwrap(),
            remediation: Remediation::CreateCustomRole {
                dest_org: "222".parse().unwrap(),
                role: role_def("222"),
            },
        }
    }

    fn rewrite_item() -> FixItem {
        FixItem {
            finding: Some("F-rewrite".into()),
            project: pid("proj-aaaa"),
            landing: "folders/20".parse().unwrap(),
            remediation: Remediation::RewriteBinding {
                project: pid("proj-aaaa"),
                from: gcp_orgmove_core::RoleName::new("organizations/111/roles/deployer"),
                to: gcp_orgmove_core::RoleName::new("organizations/222/roles/deployer"),
            },
        }
    }

    #[tokio::test]
    async fn creates_role_before_rewriting_even_if_listed_after() {
        let (g, (st, _d)) = (world(), store().await);
        g.grant(
            "projects/proj-aaaa",
            "organizations/111/roles/deployer",
            "user:a@x.com",
        );
        let r = execute(
            &g,
            &st.handle(),
            &[rewrite_item(), create_item()],
            &opts(IamFixMode::Project),
        )
        .await
        .unwrap();
        assert!(r.iter().all(|x| x.outcome == Ok(Outcome::Applied)), "{r:?}");
        assert_eq!(
            r[0].finding.as_deref(),
            Some("F-create"),
            "role is created first"
        );
        assert!(g.has_role("organizations/222/roles/deployer"));
        let pol = g.iam_at("projects/proj-aaaa");
        let new = pol
            .bindings
            .iter()
            .find(|b| b.role.as_str() == "organizations/222/roles/deployer")
            .unwrap();
        assert!(new.members.contains("user:a@x.com"));
        assert!(
            pol.bindings
                .iter()
                .any(|b| b.role.as_str() == "organizations/111/roles/deployer"),
            "the old binding stays until prune"
        );
    }

    #[tokio::test]
    async fn role_remediations_are_idempotent() {
        let (g, (st, _d)) = (world(), store().await);
        g.grant(
            "projects/proj-aaaa",
            "organizations/111/roles/deployer",
            "user:a@x.com",
        );
        let items = [create_item(), rewrite_item()];
        execute(&g, &st.handle(), &items, &opts(IamFixMode::Project))
            .await
            .unwrap();
        g.clear_calls();
        let r = execute(&g, &st.handle(), &items, &opts(IamFixMode::Project))
            .await
            .unwrap();
        assert!(
            r.iter().all(|x| x.outcome == Ok(Outcome::AlreadyPresent)),
            "{r:?}"
        );
        assert!(g.mutating_calls().is_empty());
    }

    #[tokio::test]
    async fn custom_roles_off_skips_with_an_actionable_message() {
        let (g, (st, _d)) = (world(), store().await);
        let mut o = opts(IamFixMode::Project);
        o.custom_roles = CustomRoleMode::Off;
        let r = execute(&g, &st.handle(), &[create_item(), rewrite_item()], &o)
            .await
            .unwrap();
        for x in r {
            assert!(
                matches!(&x.outcome, Ok(Outcome::Skipped(m)) if m.contains("custom_roles: recreate")),
                "{x:?}"
            );
        }
        assert!(g.mutating_calls().is_empty());
    }

    #[tokio::test]
    async fn revert_deletes_roles_it_created_and_removes_rewritten_bindings() {
        let (g, (st, _d)) = (world(), store().await);
        g.grant(
            "projects/proj-aaaa",
            "organizations/111/roles/deployer",
            "user:a@x.com",
        );
        execute(
            &g,
            &st.handle(),
            &[create_item(), rewrite_item()],
            &opts(IamFixMode::Project),
        )
        .await
        .unwrap();
        let set: std::collections::BTreeSet<ProjectId> = [pid("proj-aaaa")].into();
        let r = revert(&g, &st.handle(), &set, false).await.unwrap();
        assert!(
            r.iter()
                .all(|x| matches!(x.outcome, Ok(RevertOutcome::Removed))),
            "{r:?}"
        );
        assert!(!g.has_role("organizations/222/roles/deployer"));
        let pol = g.iam_at("projects/proj-aaaa");
        assert!(pol
            .bindings
            .iter()
            .all(|b| b.role.as_str() != "organizations/222/roles/deployer"));
        assert!(
            pol.bindings
                .iter()
                .any(|b| b.role.as_str() == "organizations/111/roles/deployer"),
            "original binding untouched"
        );
    }

    #[tokio::test]
    async fn revert_leaves_a_role_that_already_existed() {
        let (g, (st, _d)) = (world(), store().await);
        g.custom_role(role_def("222"));
        execute(
            &g,
            &st.handle(),
            &[create_item()],
            &opts(IamFixMode::Project),
        )
        .await
        .unwrap();
        let set: std::collections::BTreeSet<ProjectId> = [pid("proj-aaaa")].into();
        let r = revert(&g, &st.handle(), &set, false).await.unwrap();
        assert_eq!(r[0].outcome, Ok(RevertOutcome::NotAddedByTool));
        assert!(g.has_role("organizations/222/roles/deployer"));
    }

    const OS_LOGIN: &str = "constraints/compute.requireOsLogin";

    fn override_item(expires: &str) -> FixItem {
        let mut policy = OrgPolicy::empty(OS_LOGIN);
        policy.rules.push(gcp_orgmove_core::PolicyRule {
            enforce: Some(false),
            ..Default::default()
        });
        FixItem {
            finding: Some("F-pol".into()),
            project: pid("proj-aaaa"),
            landing: "folders/20".parse().unwrap(),
            remediation: Remediation::SetPolicyOverride {
                project: pid("proj-aaaa"),
                policy,
                expires: expires.into(),
            },
        }
    }

    fn override_opts() -> FixOptions {
        let mut o = opts(IamFixMode::Project);
        o.policy_fix = PolicyFixMode::ProjectOverride;
        o.allow_policy_overrides = true;
        o
    }

    #[tokio::test]
    async fn overrides_need_both_the_mode_and_the_explicit_flag() {
        let (g, (st, _d)) = (world(), store().await);
        for (mode, allow) in [
            (PolicyFixMode::Off, true),
            (PolicyFixMode::ProjectOverride, false),
            (PolicyFixMode::Off, false),
        ] {
            let mut o = opts(IamFixMode::Project);
            o.policy_fix = mode;
            o.allow_policy_overrides = allow;
            let r = execute(&g, &st.handle(), &[override_item("")], &o)
                .await
                .unwrap();
            assert!(
                matches!(&r[0].outcome, Ok(Outcome::Skipped(m)) if m.contains("--allow-policy-overrides")),
                "{r:?}"
            );
        }
        assert!(g.mutating_calls().is_empty());
    }

    #[tokio::test]
    async fn override_sets_the_policy_label_and_expiry() {
        let (g, (st, _d)) = (world(), store().await);
        let r = execute(&g, &st.handle(), &[override_item("")], &override_opts())
            .await
            .unwrap();
        assert_eq!(r[0].outcome, Ok(Outcome::Applied));
        let p = g
            .policy_at("projects/proj-aaaa", OS_LOGIN)
            .expect("project policy set");
        assert_eq!(p.rules[0].enforce, Some(false));
        assert!(!p.inherit_from_parent);
        let proj = gcp_orgmove_core::Gcp::get_project(&g, &pid("proj-aaaa"))
            .await
            .unwrap();
        assert_eq!(proj.labels[OVERRIDE_LABEL], "20261104", "now + 30d");
        let s = st.handle().snapshot().await.unwrap();
        match &s.applied[0].remediation {
            Remediation::SetPolicyOverride { expires, .. } => assert_eq!(expires, "2026-11-04"),
            other => panic!("{other:?}"),
        }
        assert_eq!(s.applied[0].prior.len(), 2);
    }

    #[tokio::test]
    async fn override_is_idempotent_and_dry_run_is_inert() {
        let (g, (st, _d)) = (world(), store().await);
        let mut dry = override_opts();
        dry.dry_run = true;
        assert_eq!(
            execute(&g, &st.handle(), &[override_item("")], &dry)
                .await
                .unwrap()[0]
                .outcome,
            Ok(Outcome::WouldApply)
        );
        assert!(g.mutating_calls().is_empty());
        execute(&g, &st.handle(), &[override_item("")], &override_opts())
            .await
            .unwrap();
        g.clear_calls();
        let r = execute(&g, &st.handle(), &[override_item("")], &override_opts())
            .await
            .unwrap();
        assert_eq!(r[0].outcome, Ok(Outcome::AlreadyPresent));
        assert!(g.mutating_calls().is_empty());
    }

    #[tokio::test]
    async fn the_label_keeps_the_earliest_expiry() {
        let (g, (st, _d)) = (world(), store().await);
        execute(
            &g,
            &st.handle(),
            &[override_item("2026-11-04")],
            &override_opts(),
        )
        .await
        .unwrap();
        let mut second = override_item("2027-01-01");
        if let Remediation::SetPolicyOverride { policy, .. } = &mut second.remediation {
            policy.constraint = "constraints/iam.disableServiceAccountKeyCreation".into();
        }
        execute(&g, &st.handle(), &[second], &override_opts())
            .await
            .unwrap();
        let proj = gcp_orgmove_core::Gcp::get_project(&g, &pid("proj-aaaa"))
            .await
            .unwrap();
        assert_eq!(proj.labels[OVERRIDE_LABEL], "20261104");
    }

    #[tokio::test]
    async fn revert_restores_the_prior_policy_and_removes_the_label_with_the_last_override() {
        let (g, (st, _d)) = (world(), store().await);
        let mut prior = OrgPolicy::empty(OS_LOGIN);
        prior.rules.push(gcp_orgmove_core::PolicyRule {
            enforce: Some(true),
            ..Default::default()
        });
        g.policy("projects/proj-aaaa", prior.clone());
        execute(&g, &st.handle(), &[override_item("")], &override_opts())
            .await
            .unwrap();
        assert_eq!(
            g.policy_at("projects/proj-aaaa", OS_LOGIN).unwrap().rules[0].enforce,
            Some(false)
        );
        let set: std::collections::BTreeSet<ProjectId> = [pid("proj-aaaa")].into();
        let r = revert(&g, &st.handle(), &set, false).await.unwrap();
        assert_eq!(r[0].outcome, Ok(RevertOutcome::Removed));
        assert_eq!(
            g.policy_at("projects/proj-aaaa", OS_LOGIN).unwrap().rules,
            prior.rules,
            "back to what it was"
        );
        let proj = gcp_orgmove_core::Gcp::get_project(&g, &pid("proj-aaaa"))
            .await
            .unwrap();
        assert!(!proj.labels.contains_key(OVERRIDE_LABEL));
    }

    #[tokio::test]
    async fn revert_deletes_a_policy_that_did_not_exist_before() {
        let (g, (st, _d)) = (world(), store().await);
        execute(&g, &st.handle(), &[override_item("")], &override_opts())
            .await
            .unwrap();
        let set: std::collections::BTreeSet<ProjectId> = [pid("proj-aaaa")].into();
        revert(&g, &st.handle(), &set, false).await.unwrap();
        assert!(g.policy_at("projects/proj-aaaa", OS_LOGIN).is_none());
    }

    #[tokio::test]
    async fn execute_reports_one_tick_per_item_but_previews_are_silent() {
        use gcp_orgmove_core::progress::Recorder;
        let (g, (st, _d)) = (world(), store().await);
        let items = [
            item("roles/viewer", "user:a@x.com"),
            item("roles/editor", "user:b@x.com"),
        ];
        let rec = Recorder::new();
        let obs: SharedObserver = rec.clone();
        let mut dry = opts(IamFixMode::Project);
        dry.dry_run = true;
        execute_with(&g, &st.handle(), &items, &dry, &obs)
            .await
            .unwrap();
        assert!(rec.events().is_empty(), "previews draw nothing");
        execute_with(&g, &st.handle(), &items, &opts(IamFixMode::Project), &obs)
            .await
            .unwrap();
        assert_eq!(rec.phases(), vec![("Applying changes".to_string(), 2)]);
        assert_eq!((rec.ticks(), rec.ends()), (2, 1));
    }

    #[tokio::test]
    async fn execute_ticks_failures_too() {
        use gcp_orgmove_core::progress::Recorder;
        let (g, (st, _d)) = (world(), store().await);
        g.inject_fault("get_iam", Error::new(ErrorKind::PermissionDenied, "no"));
        let rec = Recorder::new();
        let obs: SharedObserver = rec.clone();
        execute_with(
            &g,
            &st.handle(),
            &[item("roles/viewer", "user:a@x.com")],
            &opts(IamFixMode::Project),
            &obs,
        )
        .await
        .unwrap();
        assert!(rec.events().iter().any(
            |e| matches!(e, gcp_orgmove_core::progress::Event::Tick(t) if t.contains("FAILED"))
        ));
        assert_eq!(rec.ends(), 1);
    }
}
