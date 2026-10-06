//! `parity prune` (§6.4.7): the only command that removes access.
//!
//! Only access this tool added (or superseded) is ever eligible:
//! * **superseded custom-role bindings**: the project's binding to
//!   `organizations/<SRC>/roles/X` whose members `parity fix` also granted
//!   under the recreated `organizations/<DEST>/roles/X`;
//! * **redundant project bindings**: bindings `parity fix` added that the
//!   destination ancestry now grants identically.
//!
//! Conditional bindings are never pruned. A project must have passed
//! `parity verify`. Everything removed is recorded so `rollback
//! --revert-remediations` can restore it.

use std::collections::BTreeSet;
use std::time::Duration;

use chrono::{DateTime, Utc};
use gcp_orgmove_core::progress::{silent, ObserverExt, PhaseGuard, SharedObserver};
use gcp_orgmove_core::{
    Binding, Error, ErrorKind, Gcp, Manifest, ProjectId, PrunedRecord, Remediation, Resource,
    Result, State, StateHandle,
};

const CONFLICT_RETRIES: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneCandidate {
    pub project: ProjectId,
    /// Index into `State::applied` of the remediation this supersedes.
    pub entry: usize,
    pub scope: Resource,
    /// Exactly what would be removed (the members of one binding).
    pub binding: Binding,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct Eligibility {
    pub candidates: Vec<PruneCandidate>,
    /// Projects that cannot be pruned yet, with the reason.
    pub refused: Vec<(ProjectId, String)>,
}

/// Work out what is prunable for `projects` (empty = every project with state).
pub async fn eligible(
    gcp: &dyn Gcp,
    state: &State,
    manifest: &Manifest,
    projects: &[ProjectId],
    older_than: Option<Duration>,
    now: DateTime<Utc>,
) -> Result<Eligibility> {
    let cutoff = older_than.map(|d| {
        now - chrono::Duration::from_std(d).unwrap_or_else(|_| chrono::Duration::days(36500))
    });
    // Every project this tool has changed (not merely every project in state).
    let wanted: Vec<ProjectId> = if projects.is_empty() {
        state
            .applied
            .iter()
            .map(|a| a.project.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    } else {
        projects.to_vec()
    };
    let mut out = Eligibility::default();
    for project in wanted {
        let has_entries = state
            .applied
            .iter()
            .any(|a| a.project == project && !a.reverted && !a.pruned && !a.prior.is_empty());
        if !has_entries {
            continue;
        }
        match state.parity_verify.get(&project) {
            Some(v) if v.passed => {}
            Some(_) => {
                out.refused.push((
                    project,
                    "the last `parity verify` failed; fix the problems and re-verify first".into(),
                ));
                continue;
            }
            None => {
                out.refused.push((
                    project,
                    "run `gcp-orgmove parity verify` successfully first".into(),
                ));
                continue;
            }
        }
        let me = Resource::Project(project.clone());
        let live = gcp.get_iam(&me).await?;
        let effective = gcp.get_effective_iam(&me).await?;

        for (idx, a) in state.applied.iter().enumerate() {
            if a.project != project || a.reverted || a.pruned || a.prior.is_empty() {
                continue;
            }
            if cutoff.is_some_and(|c| a.applied_at > c) {
                continue; // still inside the soak period
            }
            let Remediation::AddIamBinding { scope, binding } = &a.remediation else {
                continue;
            };
            if scope != &me || binding.condition.is_some() {
                continue;
            }

            // A: superseded source custom-role binding.
            if let Some((org, _)) = binding.role.org_custom() {
                if org == manifest.destination_org {
                    let old = binding
                        .role
                        .rehomed(&manifest.source_org)
                        .expect("has a short name");
                    let present: BTreeSet<String> = live
                        .bindings
                        .iter()
                        .filter(|b| b.role == old && b.condition.is_none())
                        .flat_map(|b| b.members.iter().cloned())
                        .collect();
                    let members: BTreeSet<String> =
                        binding.members.intersection(&present).cloned().collect();
                    if !members.is_empty() {
                        out.candidates.push(PruneCandidate {
                            project: project.clone(),
                            entry: idx,
                            scope: me.clone(),
                            binding: Binding {
                                role: old.clone(),
                                members,
                                condition: None,
                            },
                            reason: format!("superseded by {}", binding.role),
                        });
                    }
                    continue;
                }
            }

            // B: now granted identically by the destination ancestry.
            let inherited: BTreeSet<&str> = effective
                .grants
                .iter()
                .filter(|g| {
                    g.from != me && g.grant.role == binding.role && g.grant.condition.is_none()
                })
                .map(|g| g.grant.member.as_str())
                .collect();
            let present: BTreeSet<&String> = live
                .bindings
                .iter()
                .filter(|b| b.role == binding.role && b.condition.is_none())
                .flat_map(|b| b.members.iter())
                .collect();
            let members: BTreeSet<String> = binding
                .members
                .iter()
                .filter(|m| inherited.contains(m.as_str()) && present.contains(m))
                .cloned()
                .collect();
            if !members.is_empty() {
                out.candidates.push(PruneCandidate {
                    project: project.clone(),
                    entry: idx,
                    scope: me.clone(),
                    binding: Binding {
                        role: binding.role.clone(),
                        members,
                        condition: None,
                    },
                    reason: "now granted identically by the destination hierarchy".into(),
                });
            }
        }
    }
    Ok(out)
}

pub fn describe(c: &PruneCandidate) -> String {
    format!(
        "remove {} from {} on {} ({})",
        c.binding
            .members
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
        c.binding.role,
        c.scope,
        c.reason
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PruneOutcome {
    Removed,
    AlreadyGone,
    WouldRemove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneResult {
    pub project: ProjectId,
    pub description: String,
    pub outcome: std::result::Result<PruneOutcome, String>,
}

async fn remove(gcp: &dyn Gcp, c: &PruneCandidate) -> Result<bool> {
    for _ in 0..=CONFLICT_RETRIES {
        let mut policy = gcp.get_iam(&c.scope).await?;
        let mut changed = false;
        for b in policy
            .bindings
            .iter_mut()
            .filter(|b| b.role == c.binding.role && b.condition.is_none())
        {
            let before = b.members.len();
            b.members.retain(|m| !c.binding.members.contains(m));
            changed |= b.members.len() != before;
        }
        if !changed {
            return Ok(false);
        }
        policy.bindings.retain(|b| !b.members.is_empty());
        match gcp.set_iam(&c.scope, policy).await {
            Ok(_) => return Ok(true),
            Err(e) if e.kind == ErrorKind::Conflict => continue,
            Err(e) => return Err(e),
        }
    }
    Err(Error::new(
        ErrorKind::Conflict,
        format!(
            "IAM policy on {} kept changing; gave up after retries",
            c.scope
        ),
    )
    .with_resource(&c.scope))
}

/// Remove the candidates. Each removal is recorded (for restore on revert)
/// and the superseding remediation is marked pruned.
pub async fn prune(
    gcp: &dyn Gcp,
    state: &StateHandle,
    candidates: &[PruneCandidate],
    dry_run: bool,
) -> Result<Vec<PruneResult>> {
    prune_with(gcp, state, candidates, dry_run, &silent()).await
}

/// [`prune`] reporting progress (previews report nothing).
pub async fn prune_with(
    gcp: &dyn Gcp,
    state: &StateHandle,
    candidates: &[PruneCandidate],
    dry_run: bool,
    observer: &SharedObserver,
) -> Result<Vec<PruneResult>> {
    let _phase =
        (!dry_run).then(|| PhaseGuard::start(observer, "Pruning access", candidates.len()));
    let mut out = vec![];
    for c in candidates {
        let description = describe(c);
        if !dry_run {
            observer.working(description.clone());
        }
        if dry_run {
            out.push(PruneResult {
                project: c.project.clone(),
                description,
                outcome: Ok(PruneOutcome::WouldRemove),
            });
            continue;
        }
        let outcome = match remove(gcp, c).await {
            Ok(removed) => {
                let (idx, rec) = (
                    c.entry,
                    PrunedRecord {
                        project: c.project.clone(),
                        scope: c.scope.clone(),
                        binding: c.binding.clone(),
                        reason: c.reason.clone(),
                        at: Utc::now(),
                        restored: false,
                    },
                );
                state
                    .update(move |s| {
                        if removed {
                            s.pruned.push(rec);
                        }
                        if let Some(a) = s.applied.get_mut(idx) {
                            a.pruned = true;
                        }
                        Ok(())
                    })
                    .await?;
                Ok(if removed {
                    PruneOutcome::Removed
                } else {
                    PruneOutcome::AlreadyGone
                })
            }
            Err(e) => Err(e.message),
        };
        observer.tick(&c.project);
        out.push(PruneResult {
            project: c.project.clone(),
            description,
            outcome,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::{execute, FixItem, FixOptions};
    use gcp_orgmove_core::fake::FakeGcp;
    use gcp_orgmove_core::{
        CustomRole, CustomRoleMode, IamFixMode, PolicyFixMode, RoleName, RoleStage, StateStore,
        VerifyResult,
    };

    fn pid() -> ProjectId {
        "proj-aaaa".parse().unwrap()
    }

    fn manifest() -> Manifest {
        Manifest::parse("version: 1\nsource_org: \"111\"\ndestination_org: \"222\"\nprojects:\n  - id: proj-aaaa\n").unwrap().manifest
    }

    fn now() -> DateTime<Utc> {
        Utc::now() + chrono::Duration::days(1)
    }

    fn world() -> FakeGcp {
        let f = FakeGcp::new();
        f.org("111").org("222");
        f.folder("20", "organizations/222");
        f.project("proj-aaaa", "1001", "folders/20");
        f
    }

    fn opts() -> FixOptions {
        FixOptions {
            iam_fix: IamFixMode::Project,
            custom_roles: CustomRoleMode::Recreate,
            policy_fix: PolicyFixMode::Off,
            allow_policy_overrides: false,
            override_expiry: Duration::from_secs(86_400),
            now: Utc::now(),
            widen_access: false,
            dry_run: false,
        }
    }

    fn add_item(role: &str, member: &str) -> FixItem {
        FixItem {
            finding: Some("F-x".into()),
            project: pid(),
            landing: "folders/20".parse().unwrap(),
            remediation: Remediation::AddIamBinding {
                scope: "projects/proj-aaaa".parse().unwrap(),
                binding: Binding {
                    role: RoleName::new(role),
                    members: [member.to_string()].into(),
                    condition: None,
                },
            },
        }
    }

    async fn store() -> (StateStore, tempfile::TempDir) {
        let d = tempfile::tempdir().unwrap();
        (StateStore::open(&d.path().join("s.json")).await.unwrap(), d)
    }

    async fn mark_verified(st: &StateStore, passed: bool) {
        st.handle()
            .update(move |s| {
                s.parity_verify.insert(
                    pid(),
                    VerifyResult {
                        passed,
                        detail: String::new(),
                        at: Utc::now(),
                    },
                );
                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn nothing_is_eligible_without_a_passing_parity_verify() {
        let (g, (st, _d)) = (world(), store().await);
        g.grant("folders/20", "roles/viewer", "user:a@x.com");
        execute(
            &g,
            &st.handle(),
            &[add_item("roles/viewer", "user:a@x.com")],
            &opts(),
        )
        .await
        .unwrap();
        let s = st.handle().snapshot().await.unwrap();
        let e = eligible(&g, &s, &manifest(), &[], None, now())
            .await
            .unwrap();
        assert!(e.candidates.is_empty());
        assert!(e.refused[0].1.contains("parity verify"));

        mark_verified(&st, false).await;
        let s = st.handle().snapshot().await.unwrap();
        let e = eligible(&g, &s, &manifest(), &[], None, now())
            .await
            .unwrap();
        assert!(e.refused[0].1.contains("failed"));
    }

    #[tokio::test]
    async fn project_binding_now_covered_by_the_destination_is_prunable() {
        let (g, (st, _d)) = (world(), store().await);
        g.grant("folders/20", "roles/viewer", "user:a@x.com"); // destination grants it
        execute(
            &g,
            &st.handle(),
            &[
                add_item("roles/viewer", "user:a@x.com"),
                add_item("roles/editor", "user:b@x.com"),
            ],
            &opts(),
        )
        .await
        .unwrap();
        mark_verified(&st, true).await;
        let s = st.handle().snapshot().await.unwrap();
        let e = eligible(&g, &s, &manifest(), &[], None, now())
            .await
            .unwrap();
        assert_eq!(
            e.candidates.len(),
            1,
            "editor is not covered, so it must stay"
        );
        assert_eq!(e.candidates[0].binding.role.as_str(), "roles/viewer");
        assert!(e.candidates[0].reason.contains("destination hierarchy"));

        let r = prune(&g, &st.handle(), &e.candidates, false).await.unwrap();
        assert_eq!(r[0].outcome, Ok(PruneOutcome::Removed));
        let pol = g.iam_at("projects/proj-aaaa");
        assert!(pol
            .bindings
            .iter()
            .all(|b| b.role.as_str() != "roles/viewer"));
        assert!(
            pol.bindings
                .iter()
                .any(|b| b.role.as_str() == "roles/editor"),
            "uncovered access untouched"
        );
        let s = st.handle().snapshot().await.unwrap();
        assert_eq!(s.pruned.len(), 1);
        assert!(s.applied.iter().any(|a| a.pruned));
        // idempotent
        let again = eligible(&g, &s, &manifest(), &[], None, now())
            .await
            .unwrap();
        assert!(again.candidates.is_empty());
    }

    fn role(org: &str) -> CustomRole {
        CustomRole {
            name: RoleName::new(format!("organizations/{org}/roles/deployer")),
            title: "d".into(),
            description: String::new(),
            permissions: ["a.b.c".to_string()].into(),
            stage: RoleStage::Ga,
        }
    }

    #[tokio::test]
    async fn superseded_source_role_bindings_are_prunable() {
        let (g, (st, _d)) = (world(), store().await);
        g.grant(
            "projects/proj-aaaa",
            "organizations/111/roles/deployer",
            "user:a@x.com",
        );
        g.grant(
            "projects/proj-aaaa",
            "organizations/111/roles/deployer",
            "user:untouched@x.com",
        );
        let create = FixItem {
            finding: Some("F-c".into()),
            project: pid(),
            landing: "folders/20".parse().unwrap(),
            remediation: Remediation::CreateCustomRole {
                dest_org: "222".parse().unwrap(),
                role: role("222"),
            },
        };
        let rewrite = FixItem {
            finding: Some("F-r".into()),
            project: pid(),
            landing: "folders/20".parse().unwrap(),
            remediation: Remediation::RewriteBinding {
                project: pid(),
                from: RoleName::new("organizations/111/roles/deployer"),
                to: RoleName::new("organizations/222/roles/deployer"),
            },
        };
        execute(&g, &st.handle(), &[create, rewrite], &opts())
            .await
            .unwrap();
        mark_verified(&st, true).await;
        let s = st.handle().snapshot().await.unwrap();
        let e = eligible(&g, &s, &manifest(), &[], None, now())
            .await
            .unwrap();
        assert_eq!(e.candidates.len(), 1);
        let c = &e.candidates[0];
        assert_eq!(c.binding.role.as_str(), "organizations/111/roles/deployer");
        assert!(c
            .reason
            .contains("superseded by organizations/222/roles/deployer"));
        assert_eq!(
            c.binding.members.len(),
            2,
            "both members were copied to the new role"
        );
        prune(&g, &st.handle(), &e.candidates, false).await.unwrap();
        let pol = g.iam_at("projects/proj-aaaa");
        assert!(pol
            .bindings
            .iter()
            .all(|b| b.role.as_str() != "organizations/111/roles/deployer"));
        assert!(
            pol.bindings
                .iter()
                .any(|b| b.role.as_str() == "organizations/222/roles/deployer"
                    && b.members.len() == 2)
        );
    }

    #[tokio::test]
    async fn the_soak_period_filters_recent_changes() {
        let (g, (st, _d)) = (world(), store().await);
        g.grant("folders/20", "roles/viewer", "user:a@x.com");
        execute(
            &g,
            &st.handle(),
            &[add_item("roles/viewer", "user:a@x.com")],
            &opts(),
        )
        .await
        .unwrap();
        mark_verified(&st, true).await;
        let s = st.handle().snapshot().await.unwrap();
        let soak = Some(Duration::from_secs(7 * 86_400));
        assert!(eligible(&g, &s, &manifest(), &[], soak, Utc::now())
            .await
            .unwrap()
            .candidates
            .is_empty());
        let later = Utc::now() + chrono::Duration::days(8);
        assert_eq!(
            eligible(&g, &s, &manifest(), &[], soak, later)
                .await
                .unwrap()
                .candidates
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn dry_run_changes_nothing_and_pre_existing_access_is_never_eligible() {
        let (g, (st, _d)) = (world(), store().await);
        g.grant("folders/20", "roles/viewer", "user:a@x.com");
        g.grant("projects/proj-aaaa", "roles/viewer", "user:a@x.com"); // existed before the tool ran
        execute(
            &g,
            &st.handle(),
            &[add_item("roles/viewer", "user:a@x.com")],
            &opts(),
        )
        .await
        .unwrap();
        mark_verified(&st, true).await;
        let s = st.handle().snapshot().await.unwrap();
        assert!(
            eligible(&g, &s, &manifest(), &[], None, now())
                .await
                .unwrap()
                .candidates
                .is_empty(),
            "no prior => not ours to remove"
        );

        let (g2, (st2, _d2)) = (world(), store().await);
        g2.grant("folders/20", "roles/viewer", "user:a@x.com");
        execute(
            &g2,
            &st2.handle(),
            &[add_item("roles/viewer", "user:a@x.com")],
            &opts(),
        )
        .await
        .unwrap();
        mark_verified(&st2, true).await;
        let s2 = st2.handle().snapshot().await.unwrap();
        let e = eligible(&g2, &s2, &manifest(), &[], None, now())
            .await
            .unwrap();
        g2.clear_calls();
        let r = prune(&g2, &st2.handle(), &e.candidates, true)
            .await
            .unwrap();
        assert_eq!(r[0].outcome, Ok(PruneOutcome::WouldRemove));
        assert!(g2.mutating_calls().is_empty());
        assert!(st2.handle().snapshot().await.unwrap().pruned.is_empty());
    }

    #[tokio::test]
    async fn conditional_bindings_are_never_pruned() {
        let (g, (st, _d)) = (world(), store().await);
        g.grant("folders/20", "roles/viewer", "user:a@x.com");
        let mut item = add_item("roles/viewer", "user:a@x.com");
        if let Remediation::AddIamBinding { binding, .. } = &mut item.remediation {
            binding.condition = Some(gcp_orgmove_core::Condition {
                title: "t".into(),
                description: String::new(),
                expression: "true".into(),
            });
        }
        execute(&g, &st.handle(), &[item], &opts()).await.unwrap();
        mark_verified(&st, true).await;
        let s = st.handle().snapshot().await.unwrap();
        assert!(eligible(&g, &s, &manifest(), &[], None, now())
            .await
            .unwrap()
            .candidates
            .is_empty());
    }

    #[tokio::test]
    async fn prune_reports_progress_only_when_it_really_removes() {
        use gcp_orgmove_core::progress::Recorder;
        let (g, (st, _d)) = (world(), store().await);
        g.grant("folders/20", "roles/viewer", "user:a@x.com");
        execute(
            &g,
            &st.handle(),
            &[add_item("roles/viewer", "user:a@x.com")],
            &opts(),
        )
        .await
        .unwrap();
        mark_verified(&st, true).await;
        let s = st.handle().snapshot().await.unwrap();
        let e = eligible(&g, &s, &manifest(), &[], None, now())
            .await
            .unwrap();
        let rec = Recorder::new();
        let obs: SharedObserver = rec.clone();
        prune_with(&g, &st.handle(), &e.candidates, true, &obs)
            .await
            .unwrap();
        assert!(rec.events().is_empty());
        prune_with(&g, &st.handle(), &e.candidates, false, &obs)
            .await
            .unwrap();
        assert_eq!(rec.phases(), vec![("Pruning access".to_string(), 1)]);
        assert_eq!((rec.ticks(), rec.ends()), (1, 1));
    }
}
