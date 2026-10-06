//! Planner (§6.3): preflights, move analysis, groups, parity checks, ordering.
//!
//! Read-only against GCP. Output is a [`Plan`] that has been normalized, so
//! equal inputs give a byte-identical file (apart from `generated_at`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::stream::{self, StreamExt};

use crate::error::{Error, ErrorKind, Result};
use crate::finding::{Category, CheckCtx, Finding, ParityCheck, Severity};
use crate::gcp::Gcp;
use crate::ids::*;
use crate::manifest::{CustomRoleMode, LoadedManifest, Manifest};
use crate::model::{
    AnalysisLevel, LifecycleState, OrgPolicy, Project, EXPORT_CONSTRAINT, IMPORT_CONSTRAINT,
};
use crate::plan::*;
use crate::progress::{ObserverExt, SharedObserver, Stages};

#[derive(Debug, Clone)]
pub struct PlanOptions {
    pub concurrency: usize,
    /// Parity check IDs to skip.
    pub skip: BTreeSet<String>,
    /// Restrict planning to these projects (empty = all).
    pub only: Vec<ProjectId>,
    /// Treat warnings as blockers.
    pub strict: bool,
    pub now: DateTime<Utc>,
    /// Receives progress events; silent by default.
    pub observer: SharedObserver,
}

impl PlanOptions {
    pub fn new(now: DateTime<Utc>) -> Self {
        Self {
            concurrency: 4,
            skip: BTreeSet::new(),
            only: vec![],
            strict: false,
            now,
            observer: crate::progress::silent(),
        }
    }
}

/// One project being planned.
#[derive(Debug, Clone)]
pub struct Target {
    pub project: Project,
    pub landing: Parent,
}

// ------------------------------------------------------------------ resolve

/// Resolve manifest projects, folder selections and group members into
/// concrete targets with landing parents. An explicit `projects:` entry wins
/// over a selection match; group members are pulled in so groups stay whole.
pub async fn resolve_targets(
    gcp: &dyn Gcp,
    m: &Manifest,
    only: &[ProjectId],
    concurrency: usize,
) -> Result<Vec<Target>> {
    let mut landing: BTreeMap<ProjectId, Parent> = BTreeMap::new();
    let mut known: BTreeMap<ProjectId, Project> = BTreeMap::new();

    for e in &m.projects {
        landing.insert(
            e.id.clone(),
            m.landing_parent(e.destination_folder.as_ref()),
        );
    }

    for folder in &m.selection.source_folders {
        for p in gcp.list_projects(&Parent::Folder(folder.clone())).await? {
            if p.state != LifecycleState::Active {
                continue;
            }
            if m.selection
                .exclude_labels
                .iter()
                .any(|(k, v)| p.labels.get(k) == Some(v))
            {
                continue;
            }
            landing
                .entry(p.id.clone())
                .or_insert_with(|| m.landing_parent(None));
            known.insert(p.id.clone(), p);
        }
    }

    let group_members: BTreeSet<&ProjectId> =
        m.groups.iter().flat_map(|g| g.projects.iter()).collect();
    if !only.is_empty() {
        landing.retain(|id, _| only.contains(id));
    }
    for id in group_members {
        landing
            .entry(id.clone())
            .or_insert_with(|| m.landing_parent(None));
    }

    let ids: Vec<ProjectId> = landing.keys().cloned().collect();
    let fetched: Vec<Result<Project>> = stream::iter(ids.iter().cloned())
        .map(|id| {
            let cached = known.get(&id).cloned();
            async move {
                match cached {
                    Some(p) => Ok(p),
                    None => gcp.get_project(&id).await,
                }
            }
        })
        .buffered(concurrency.max(1))
        .collect()
        .await;

    let mut out = vec![];
    for (id, res) in ids.into_iter().zip(fetched) {
        let project = res.map_err(|e| {
            if e.kind == ErrorKind::NotFound {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("project {id} was not found"),
                )
                .with_resource(format!("projects/{id}"))
            } else {
                e
            }
        })?;
        let landing = landing.remove(&id).expect("id came from landing");
        out.push(Target { project, landing });
    }
    Ok(out)
}

// ------------------------------------------------------------------- groups

/// Union overlapping groups (manifest groups and, later, Shared VPC links).
/// Returns `(name, members)` sorted by name; an merged group keeps the
/// lexicographically smallest of its input names.
pub fn merge_groups(groups: &[(String, Vec<ProjectId>)]) -> Vec<(String, BTreeSet<ProjectId>)> {
    let mut merged: Vec<(String, BTreeSet<ProjectId>)> = vec![];
    for (name, members) in groups {
        let mut set: BTreeSet<ProjectId> = members.iter().cloned().collect();
        let mut best = name.clone();
        let mut i = 0;
        while i < merged.len() {
            if merged[i].1.iter().any(|p| set.contains(p)) {
                let (n, s) = merged.remove(i);
                best = best.min(n);
                set.extend(s);
            } else {
                i += 1;
            }
        }
        merged.push((best, set));
    }
    merged.sort_by(|a, b| a.0.cmp(&b.0));
    merged
}

// ----------------------------------------------------------------- ordering

/// Pack units (move groups stay whole) into sequential batches of at most
/// `batch_size`. Deterministic: units are ordered by their smallest member.
/// Fails if a single group is larger than `batch_size`.
pub fn order_batches(
    projects: &BTreeSet<ProjectId>,
    groups: &[(String, BTreeSet<ProjectId>)],
    batch_size: usize,
) -> Result<Vec<Vec<ProjectId>>> {
    let mut units: Vec<BTreeSet<ProjectId>> = vec![];
    let mut grouped: BTreeSet<&ProjectId> = BTreeSet::new();
    for (name, g) in groups {
        let members: BTreeSet<ProjectId> = g
            .iter()
            .filter(|p| projects.contains(*p))
            .cloned()
            .collect();
        if members.len() > batch_size {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!("group {name:?} has {} projects but batch_size is {batch_size}; a group cannot be split", members.len()),
            ));
        }
        grouped.extend(g.iter());
        if !members.is_empty() {
            units.push(members);
        }
    }
    for p in projects {
        if !grouped.contains(p) {
            units.push(BTreeSet::from([p.clone()]));
        }
    }
    units.sort_by(|a, b| a.iter().next().cmp(&b.iter().next()));

    let mut batches: Vec<Vec<ProjectId>> = vec![];
    for u in units {
        match batches.last_mut() {
            Some(b) if b.len() + u.len() <= batch_size => b.extend(u),
            _ => batches.push(u.into_iter().collect()),
        }
    }
    Ok(batches)
}

// --------------------------------------------------------------- preflights

type Findings = BTreeMap<ProjectId, Vec<Finding>>;
type PolicyKey = (Resource, String);
/// Permissions granted per (resource, checked-as-the-mover).
type Granted = BTreeMap<(Resource, bool), BTreeSet<String>>;
type GrantedEntry = ((Resource, bool), BTreeSet<String>);
type PolicyLookup = BTreeMap<PolicyKey, Option<OrgPolicy>>;

fn push(f: &mut Findings, fi: Finding) {
    f.entry(fi.project.clone()).or_default().push(fi);
}

/// Permissions needed on one resource and the role that grants them.
struct Need {
    resource: Resource,
    perms: &'static [&'static str],
    role: &'static str,
    /// `None` = applies to every project.
    only_for: Option<ProjectId>,
    /// Checked as the identity that performs the move (not the org's own admin).
    mover: bool,
}

async fn granted_permissions(gcp: &dyn Gcp, needs: &[Need], concurrency: usize) -> Result<Granted> {
    let mut by_res: BTreeMap<(&Resource, bool), BTreeSet<&str>> = BTreeMap::new();
    for n in needs {
        by_res
            .entry((&n.resource, n.mover))
            .or_default()
            .extend(n.perms.iter().copied());
    }
    let results: Vec<Result<GrantedEntry>> = stream::iter(by_res)
        .map(|((r, mover), perms)| async move {
            let perms: Vec<String> = perms.into_iter().map(String::from).collect();
            let got = if mover {
                gcp.test_move_permissions(r, &perms).await?
            } else {
                gcp.test_permissions(r, &perms).await?
            };
            Ok(((r.clone(), mover), got.into_iter().collect()))
        })
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await;
    results.into_iter().collect()
}

fn permission_findings(targets: &[Target], needs: &[Need], granted: &Granted, out: &mut Findings) {
    for n in needs {
        let got = &granted[&(n.resource.clone(), n.mover)];
        for perm in n.perms.iter().filter(|p| !got.contains(**p)) {
            for t in targets
                .iter()
                .filter(|t| n.only_for.as_ref().is_none_or(|p| p == &t.project.id))
            {
                out_push(out, t, &n.resource, perm, n.role);
            }
        }
    }
}

fn out_push(out: &mut Findings, t: &Target, resource: &Resource, perm: &str, role: &str) {
    push(
        out,
        Finding::new(
            t.project.id.clone(),
            "permissions",
            Category::Preflight,
            Severity::Blocker,
            &format!("{resource}|{perm}"),
            format!("missing permission {perm} on {resource}; grant {role}"),
        ),
    );
}

fn permission_needs(targets: &[Target], m: &Manifest, changed_scopes: &[Resource]) -> Vec<Need> {
    let mut needs = vec![];
    for t in targets {
        let id = &t.project.id;
        needs.push(Need {
            resource: Resource::Project(id.clone()),
            perms: &[
                "resourcemanager.projects.get",
                "resourcemanager.projects.getIamPolicy",
            ],
            role: "roles/iam.securityReviewer",
            only_for: Some(id.clone()),
            mover: false,
        });
        needs.push(Need {
            resource: Resource::Project(id.clone()),
            perms: &["resourcemanager.projects.move"],
            role: "roles/resourcemanager.projectMover",
            only_for: Some(id.clone()),
            mover: true,
        });
        needs.push(Need {
            resource: Resource::from_parent(&t.project.parent),
            perms: &["resourcemanager.projects.move"],
            role: "roles/resourcemanager.projectMover",
            only_for: Some(id.clone()),
            mover: true,
        });
        needs.push(Need {
            resource: Resource::from_parent(&t.landing),
            perms: &["resourcemanager.projects.create"],
            role: "roles/resourcemanager.projectCreator",
            only_for: Some(id.clone()),
            mover: true,
        });
    }
    for scope in changed_scopes {
        needs.push(Need {
            resource: scope.clone(),
            perms: &["orgpolicy.policies.create", "orgpolicy.policies.update"],
            role: "roles/orgpolicy.policyAdmin",
            only_for: None,
            mover: false,
        });
    }
    if m.parity.custom_roles == CustomRoleMode::Recreate {
        needs.push(Need {
            resource: Resource::Org(m.destination_org.clone()),
            perms: &["iam.roles.create"],
            role: "roles/iam.organizationRoleAdmin",
            only_for: None,
            mover: false,
        });
    }
    needs
}

/// A required org-policy change, or a reason it cannot be made.
pub enum ConstraintPlan {
    Change(PolicyChange),
    AlreadyAllowed,
    Blocked(String),
}

pub fn plan_constraint(
    scope: Resource,
    constraint: &str,
    value: String,
    direct: Option<OrgPolicy>,
) -> ConstraintPlan {
    if let Some(p) = &direct {
        if p.allows(&value) {
            return ConstraintPlan::AlreadyAllowed;
        }
        if p.rules.iter().any(|r| r.condition.is_none() && r.deny_all) {
            return ConstraintPlan::Blocked(format!(
                "{constraint} on {scope} is set to deny all values; adding {value} would not take effect. Change that policy deliberately and re-plan"
            ));
        }
    }
    let backup_ref = format!("policy-backups/{scope}/{constraint}");
    ConstraintPlan::Change(PolicyChange {
        scope,
        constraint: constraint.to_string(),
        action: "allow-value".into(),
        value,
        backup_ref,
    })
}

/// Policies set below the organization that would override the org-level
/// change (a non-inheriting list policy that doesn't allow the value).
fn overriding_policies(
    chain: &[Resource],
    policies: &PolicyLookup,
    constraint: &str,
    value: &str,
) -> Vec<Resource> {
    chain
        .iter()
        .filter(|r| !matches!(r, Resource::Org(_)))
        .filter(|r| {
            policies
                .get(&((*r).clone(), constraint.to_string()))
                .and_then(Option::as_ref)
                .is_some_and(|p| !p.inherit_from_parent && !p.reset && !p.allows(value))
        })
        .cloned()
        .collect()
}

// -------------------------------------------------------------------- build

pub async fn build_plan(
    gcp: &dyn Gcp,
    loaded: &LoadedManifest,
    checks: &[Box<dyn ParityCheck>],
    opts: &PlanOptions,
) -> Result<Plan> {
    let m = &loaded.manifest;
    let conc = opts.concurrency.clamp(1, 16);
    let obs = &opts.observer;
    let stages = Stages::new(obs);
    stages.begin("Resolving projects", 0);
    let targets = resolve_targets(gcp, m, &opts.only, conc).await?;
    if targets.is_empty() {
        return Err(Error::invalid(
            "no projects to plan (check `projects`, `selection` and `--only`)",
        ));
    }
    let mut findings: Findings = Findings::new();

    // --- hierarchy: source org and landing parent org
    stages.begin("Checking hierarchy", targets.len());
    let ancestry: Vec<Result<Vec<Parent>>> = stream::iter(targets.iter())
        .map(|t| async move {
            let r = gcp.get_ancestry(&t.project.id).await;
            obs.tick(&t.project.id);
            r
        })
        .buffered(conc)
        .collect()
        .await;
    let mut ancestry_by_project: BTreeMap<ProjectId, Vec<Parent>> = BTreeMap::new();
    for (t, a) in targets.iter().zip(ancestry) {
        let a = a?;
        if a.last() != Some(&Parent::Org(m.source_org.clone())) {
            push(
                &mut findings,
                Finding::new(
                    t.project.id.clone(),
                    "hierarchy",
                    Category::Preflight,
                    Severity::Blocker,
                    "source-org",
                    format!(
                        "project is not in source organization {} (found under {:?})",
                        m.source_org,
                        a.last().map(ToString::to_string)
                    ),
                ),
            );
        }
        ancestry_by_project.insert(t.project.id.clone(), a);
    }
    let landings: BTreeSet<&Parent> = targets.iter().map(|t| &t.landing).collect();
    let mut landing_chain: BTreeMap<Parent, Vec<Parent>> = BTreeMap::new();
    for l in landings {
        let chain = match l {
            Parent::Org(_) => vec![l.clone()],
            Parent::Folder(f) => {
                let mut c = vec![l.clone()];
                c.extend(gcp.get_folder_ancestry(f).await?);
                c
            }
        };
        landing_chain.insert(l.clone(), chain);
    }
    for t in &targets {
        if landing_chain[&t.landing].last() != Some(&Parent::Org(m.destination_org.clone())) {
            push(
                &mut findings,
                Finding::new(
                    t.project.id.clone(),
                    "hierarchy",
                    Category::Preflight,
                    Severity::Blocker,
                    "dest-org",
                    format!(
                        "landing parent {} is not in destination organization {}",
                        t.landing, m.destination_org
                    ),
                ),
            );
        }
    }

    // --- constraint preflight
    stages.begin("Checking organization policy constraints", 0);
    let src_scope = Resource::Org(m.source_org.clone());
    let dst_scope = Resource::Org(m.destination_org.clone());
    let export_value = format!("under:organizations/{}", m.destination_org);
    let import_value = format!("under:organizations/{}", m.source_org);
    let (export_direct, import_direct) = (
        gcp.get_policy(&src_scope, EXPORT_CONSTRAINT).await?,
        gcp.get_policy(&dst_scope, IMPORT_CONSTRAINT).await?,
    );
    let mut policy_changes = vec![];
    let mut changed_scopes = vec![];
    for (scope, constraint, value, direct) in [
        (
            src_scope.clone(),
            EXPORT_CONSTRAINT,
            export_value.clone(),
            export_direct,
        ),
        (
            dst_scope.clone(),
            IMPORT_CONSTRAINT,
            import_value.clone(),
            import_direct,
        ),
    ] {
        match plan_constraint(scope.clone(), constraint, value, direct) {
            ConstraintPlan::AlreadyAllowed => {}
            ConstraintPlan::Change(c) => {
                changed_scopes.push(scope);
                policy_changes.push(c);
            }
            ConstraintPlan::Blocked(why) => {
                for t in &targets {
                    push(
                        &mut findings,
                        Finding::new(
                            t.project.id.clone(),
                            "constraints",
                            Category::Preflight,
                            Severity::Blocker,
                            &format!("{scope}|{constraint}"),
                            why.clone(),
                        ),
                    );
                }
            }
        }
    }

    // lower-level policies that would override the org-level change
    let mut wanted: BTreeSet<(Resource, String)> = BTreeSet::new();
    for t in &targets {
        for p in &ancestry_by_project[&t.project.id] {
            wanted.insert((Resource::from_parent(p), EXPORT_CONSTRAINT.to_string()));
        }
        wanted.insert((
            Resource::Project(t.project.id.clone()),
            EXPORT_CONSTRAINT.to_string(),
        ));
        for p in &landing_chain[&t.landing] {
            wanted.insert((Resource::from_parent(p), IMPORT_CONSTRAINT.to_string()));
        }
    }
    let fetched: Vec<Result<(PolicyKey, Option<OrgPolicy>)>> = stream::iter(wanted)
        .map(|(r, c)| async move {
            let p = gcp.get_policy(&r, &c).await?;
            Ok(((r, c), p))
        })
        .buffer_unordered(conc)
        .collect()
        .await;
    let policies: BTreeMap<_, _> = fetched.into_iter().collect::<Result<_>>()?;
    for t in &targets {
        let mut src_chain = vec![Resource::Project(t.project.id.clone())];
        src_chain.extend(
            ancestry_by_project[&t.project.id]
                .iter()
                .map(Resource::from_parent),
        );
        let dst_chain: Vec<Resource> = landing_chain[&t.landing]
            .iter()
            .map(Resource::from_parent)
            .collect();
        for (chain, constraint, value) in [
            (&src_chain, EXPORT_CONSTRAINT, &export_value),
            (&dst_chain, IMPORT_CONSTRAINT, &import_value),
        ] {
            for r in overriding_policies(chain, &policies, constraint, value) {
                push(
                    &mut findings,
                    Finding::new(
                        t.project.id.clone(),
                        "constraints",
                        Category::Preflight,
                        Severity::Blocker,
                        &format!("{r}|{constraint}"),
                        format!("{constraint} set on {r} does not allow {value} and does not inherit; the move would be rejected"),
                    ),
                );
            }
        }
    }

    // --- permission preflight
    stages.begin("Checking permissions", 0);
    let needs = permission_needs(&targets, m, &changed_scopes);
    let granted = granted_permissions(gcp, &needs, conc).await?;
    permission_findings(&targets, &needs, &granted, &mut findings);

    // --- analyzeMove
    stages.begin("Analyzing moves", targets.len());
    let analyses: Vec<_> = stream::iter(targets.iter())
        .map(|t| async move {
            let r = gcp.analyze_move(&t.project.id, &t.landing).await;
            obs.tick(&t.project.id);
            r
        })
        .buffered(conc)
        .collect()
        .await;
    let mut analysis_by_project: BTreeMap<ProjectId, Analysis> = BTreeMap::new();
    for (t, a) in targets.iter().zip(analyses) {
        let a = a?;
        let mut an = Analysis::default();
        for item in &a.items {
            let (bucket, sev) = match item.level {
                AnalysisLevel::Blocker => (&mut an.blockers, Some(Severity::Blocker)),
                AnalysisLevel::Warning => (&mut an.warnings, Some(Severity::Warning)),
                AnalysisLevel::Info => (&mut an.info, None),
            };
            bucket.push(item.message.clone());
            if let Some(sev) = sev {
                push(
                    &mut findings,
                    Finding::new(
                        t.project.id.clone(),
                        "analyze-move",
                        Category::Analysis,
                        sev,
                        &item.message,
                        item.message.clone(),
                    ),
                );
            }
        }
        an.blockers.sort();
        an.warnings.sort();
        an.info.sort();
        analysis_by_project.insert(t.project.id.clone(), an);
    }

    // --- groups
    let in_scope: BTreeSet<ProjectId> = targets.iter().map(|t| t.project.id.clone()).collect();
    let mut group_inputs: Vec<(String, Vec<ProjectId>)> = m
        .groups
        .iter()
        .map(|g| (g.name.clone(), g.projects.clone()))
        .collect();
    if !opts.skip.contains(SHARED_VPC_CHECK) {
        stages.begin("Detecting Shared VPC", in_scope.len());
        let (vpc_groups, vpc_findings) = shared_vpc_groups(gcp, &in_scope, conc, obs).await?;
        group_inputs.extend(vpc_groups);
        for (_, fs) in vpc_findings {
            for f in fs {
                push(&mut findings, f);
            }
        }
    }
    let groups = merge_groups(&group_inputs);
    let group_of: BTreeMap<&ProjectId, &str> = groups
        .iter()
        .flat_map(|(n, s)| s.iter().map(move |p| (p, n.as_str())))
        .collect();

    // --- parity checks
    let parity = run_parity_checks(gcp, m, &targets, checks, &opts.skip, conc, obs).await?;
    for (_, fs) in parity {
        for f in fs {
            push(&mut findings, f);
        }
    }

    // --- ordering
    stages.begin("Ordering batches", 0);
    // A group larger than a batch can never be moved whole: block its members
    // (rather than failing the whole plan) and order them as singletons.
    let batch_size = m.limits.batch_size;
    let mut orderable = vec![];
    for (name, members) in &groups {
        let live: Vec<&ProjectId> = members.iter().filter(|p| in_scope.contains(*p)).collect();
        if live.len() > batch_size {
            for id in live {
                push(
                    &mut findings,
                    Finding::new(
                        id.clone(),
                        "groups",
                        Category::Preflight,
                        Severity::Blocker,
                        &format!("group-too-large|{name}"),
                        format!("group {name:?} has {} projects but limits.batch_size is {batch_size}; raise batch_size so the group moves as one unit", members.len()),
                    ),
                );
            }
        } else {
            orderable.push((name.clone(), members.clone()));
        }
    }
    let order = order_batches(&in_scope, &orderable, batch_size)?;

    // --- assemble
    let mut projects = vec![];
    for t in &targets {
        let id = &t.project.id;
        let mut fs = findings.remove(id).unwrap_or_default();
        let mut analysis = analysis_by_project.remove(id).unwrap_or_default();
        if opts.strict {
            for f in fs.iter_mut().filter(|f| f.severity == Severity::Warning) {
                f.severity = Severity::Blocker;
            }
            analysis.blockers.append(&mut analysis.warnings);
            analysis.blockers.sort();
        }
        projects.push(PlanProject {
            id: id.clone(),
            number: t.project.number.clone(),
            current_parent: t.project.parent.clone(),
            landing_parent: t.landing.clone(),
            group: group_of.get(id).map(|s| s.to_string()),
            analysis,
            findings: fs,
            remediations: vec![],
            live_parent_at_plan_time: t.project.parent.clone(),
            etag: t.project.etag.clone(),
        });
    }

    let mut plan = Plan {
        version: PLAN_VERSION,
        generated_at: opts.now,
        manifest_sha256: loaded.sha256.clone(),
        source_org: m.source_org.clone(),
        destination_org: m.destination_org.clone(),
        policy_changes,
        projects,
        order,
        summary: Summary::default(),
    };
    plan.normalize();
    Ok(plan)
}

pub const SHARED_VPC_CHECK: &str = "shared-vpc";

/// Detect Shared VPC host/service relationships among the projects in scope.
///
/// Both sides in scope: they are merged into one move group. One side out of
/// scope: a `Blocker` on the in-scope project, since moving half of a Shared
/// VPC breaks the network.
pub async fn shared_vpc_groups(
    gcp: &dyn Gcp,
    in_scope: &BTreeSet<ProjectId>,
    concurrency: usize,
    obs: &SharedObserver,
) -> Result<(Vec<(String, Vec<ProjectId>)>, Findings)> {
    let fetched: Vec<Result<Vec<crate::model::SharedVpcLink>>> = stream::iter(in_scope.iter())
        .map(|id| async move {
            let r = gcp.shared_vpc_relationships(id).await;
            obs.tick(id);
            r
        })
        .buffered(concurrency.max(1))
        .collect()
        .await;
    let mut links: BTreeSet<(ProjectId, ProjectId)> = BTreeSet::new();
    for r in fetched {
        for l in r? {
            links.insert((l.host, l.service));
        }
    }

    let mut groups: Vec<(String, Vec<ProjectId>)> = vec![];
    let mut findings = Findings::new();
    for (host, service) in &links {
        let (host_in, service_in) = (in_scope.contains(host), in_scope.contains(service));
        if host_in && service_in {
            groups.push((
                format!("shared-vpc-{host}"),
                vec![host.clone(), service.clone()],
            ));
        } else if host_in {
            push(
                &mut findings,
                Finding::new(
                    host.clone(),
                    SHARED_VPC_CHECK,
                    Category::SharedVpc,
                    Severity::Blocker,
                    &format!("service-out-of-scope|{service}"),
                    format!("Shared VPC host has service project {service} outside this migration; add it to the manifest (it will move as one group) or detach it first"),
                ),
            );
        } else if service_in {
            push(
                &mut findings,
                Finding::new(
                    service.clone(),
                    SHARED_VPC_CHECK,
                    Category::SharedVpc,
                    Severity::Blocker,
                    &format!("host-out-of-scope|{host}"),
                    format!("project uses Shared VPC host {host}, which is outside this migration; add the host to the manifest (it will move as one group) or detach the project first"),
                ),
            );
        }
    }
    for (name, members) in merge_groups(&groups) {
        if name.starts_with("shared-vpc-") {
            for m in &members {
                push(
                    &mut findings,
                    Finding::new(
                        m.clone(),
                        SHARED_VPC_CHECK,
                        Category::SharedVpc,
                        Severity::Info,
                        &format!("grouped|{name}"),
                        format!(
                            "part of Shared VPC group {name}; its {} projects move together",
                            members.len()
                        ),
                    ),
                );
            }
        }
    }
    Ok((groups, findings))
}

/// Run every enabled parity check for every target. A check that cannot run
/// becomes a `Blocker` finding (unknown is not safe) unless it is an auth
/// failure, which aborts.
pub async fn run_parity_checks(
    gcp: &dyn Gcp,
    m: &Manifest,
    targets: &[Target],
    checks: &[Box<dyn ParityCheck>],
    skip: &BTreeSet<String>,
    concurrency: usize,
    obs: &SharedObserver,
) -> Result<Findings> {
    let manifest = Arc::new(m.clone());
    let active: Vec<&Box<dyn ParityCheck>> =
        checks.iter().filter(|c| !skip.contains(c.id())).collect();
    let jobs: Vec<(&Target, &Box<dyn ParityCheck>)> = targets
        .iter()
        .flat_map(|t| active.iter().map(move |c| (t, *c)))
        .collect();
    obs.phase("Running parity checks", jobs.len());
    let results: Vec<_> = stream::iter(jobs)
        .map(|(t, c)| {
            let ctx = CheckCtx {
                manifest: manifest.clone(),
                project: t.project.clone(),
                landing_parent: t.landing.clone(),
            };
            async move {
                let r = c.run(&ctx, gcp).await;
                obs.tick(format!("{} {}", t.project.id, c.id()));
                (t.project.id.clone(), c.id(), r)
            }
        })
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await;
    let mut out = Findings::new();
    for (id, check_id, res) in results {
        match res {
            Ok(fs) => fs.into_iter().for_each(|f| push(&mut out, f)),
            Err(e) if e.kind == ErrorKind::Unauthenticated => return Err(e),
            Err(e) => push(
                &mut out,
                Finding::new(
                    id,
                    check_id,
                    Category::Preflight,
                    Severity::Blocker,
                    "check-failed",
                    format!("check {check_id} could not run: {e}; fix the cause or pass --skip {check_id}"),
                ),
            ),
        }
    }
    Ok(out)
}

/// What `parity check` refreshes and how.
#[derive(Debug, Clone)]
pub struct RefreshOptions {
    /// Projects to refresh (empty = every project in the plan).
    pub only: Vec<ProjectId>,
    pub skip: BTreeSet<String>,
    pub concurrency: usize,
    pub observer: SharedObserver,
}

impl RefreshOptions {
    pub fn new(concurrency: usize) -> Self {
        Self {
            only: vec![],
            skip: BTreeSet::new(),
            concurrency,
            observer: crate::progress::silent(),
        }
    }
}

/// `parity check`: recompute parity findings for `only` (empty = all plan
/// projects) against live state and merge them into the plan. Preflight and
/// analysis findings are untouched. Read-only against GCP.
pub async fn refresh_parity(
    gcp: &dyn Gcp,
    plan: &mut Plan,
    m: &Manifest,
    checks: &[Box<dyn ParityCheck>],
    opts: &RefreshOptions,
) -> Result<()> {
    let RefreshOptions {
        only,
        skip,
        concurrency,
        observer,
    } = opts;
    let stages = Stages::new(observer);
    stages.begin("Reading projects", 0);
    let wanted: Vec<ProjectId> = if only.is_empty() {
        plan.projects.iter().map(|p| p.id.clone()).collect()
    } else {
        for id in only {
            if plan.project(id).is_none() {
                return Err(Error::invalid(format!("project {id} is not in the plan")));
            }
        }
        only.to_vec()
    };
    let mut targets = vec![];
    for id in &wanted {
        let landing = plan
            .project(id)
            .expect("checked above")
            .landing_parent
            .clone();
        targets.push(Target {
            project: gcp.get_project(id).await?,
            landing,
        });
    }
    let refreshed_ids: BTreeSet<&str> = checks
        .iter()
        .filter(|c| !skip.contains(c.id()))
        .map(|c| c.id())
        .collect();
    let fresh = run_parity_checks(gcp, m, &targets, checks, skip, *concurrency, observer).await?;
    for p in plan.projects.iter_mut().filter(|p| wanted.contains(&p.id)) {
        p.findings
            .retain(|f| !refreshed_ids.contains(f.check.as_str()));
        p.findings
            .extend(fresh.get(&p.id).cloned().unwrap_or_default());
    }
    plan.normalize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeGcp;
    use crate::manifest::Manifest;
    use crate::model::{AnalysisItem, MoveAnalysis};
    use proptest::prelude::*;

    fn pid(s: &str) -> ProjectId {
        s.parse().unwrap()
    }

    fn now() -> DateTime<Utc> {
        "2026-10-05T12:00:00Z".parse().unwrap()
    }

    const MANIFEST: &str = r#"
version: 1
source_org: "111"
destination_org: "222"
default_destination_folder: "20"
projects:
  - id: my-app-prod
  - id: my-app-dev
    destination_folder: "21"
limits:
  batch_size: 2
"#;

    fn world() -> FakeGcp {
        let f = FakeGcp::new();
        f.org("111").org("222");
        f.folder("10", "organizations/111");
        f.folder("20", "organizations/222");
        f.folder("21", "organizations/222");
        f.project("my-app-prod", "1001", "folders/10");
        f.project("my-app-dev", "1002", "organizations/111");
        f
    }

    async fn plan(f: &FakeGcp, text: &str, opts: PlanOptions) -> Result<Plan> {
        let m = Manifest::parse(text).unwrap();
        build_plan(f, &m, &[], &opts).await
    }

    #[tokio::test]
    async fn resolves_landing_parent_precedence() {
        let f = world();
        let p = plan(&f, MANIFEST, PlanOptions::new(now())).await.unwrap();
        assert_eq!(
            p.project(&pid("my-app-prod"))
                .unwrap()
                .landing_parent
                .to_string(),
            "folders/20"
        );
        assert_eq!(
            p.project(&pid("my-app-dev"))
                .unwrap()
                .landing_parent
                .to_string(),
            "folders/21"
        );
        assert!(!p.has_blockers());
    }

    #[tokio::test]
    async fn plan_is_read_only() {
        let f = world();
        plan(&f, MANIFEST, PlanOptions::new(now())).await.unwrap();
        assert!(f.mutating_calls().is_empty(), "{:?}", f.mutating_calls());
    }

    #[tokio::test]
    async fn plan_is_deterministic() {
        let a = plan(&world(), MANIFEST, PlanOptions::new(now()))
            .await
            .unwrap();
        let b = plan(&world(), MANIFEST, PlanOptions::new(now()))
            .await
            .unwrap();
        assert_eq!(a.to_json_bytes().unwrap(), b.to_json_bytes().unwrap());
    }

    #[tokio::test]
    async fn selection_excludes_labels_and_explicit_wins() {
        let f = world();
        f.project("sel-one-aaa", "2001", "folders/10");
        f.project("sel-two-bbb", "2002", "folders/10");
        // label sel-two-bbb out
        f.set_project_labels(
            &pid("sel-two-bbb"),
            BTreeMap::from([("migrate".into(), "false".into())]),
        )
        .await
        .unwrap();
        let text = r#"
version: 1
source_org: "111"
destination_org: "222"
default_destination_folder: "20"
projects:
  - id: sel-one-aaa
    destination_folder: "21"
selection:
  source_folders: ["10"]
  exclude_labels: { migrate: "false" }
"#;
        let p = plan(&f, text, PlanOptions::new(now())).await.unwrap();
        let ids: Vec<_> = p.projects.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["my-app-prod", "sel-one-aaa"]);
        // explicit entry's folder wins over selection default
        assert_eq!(
            p.project(&pid("sel-one-aaa"))
                .unwrap()
                .landing_parent
                .to_string(),
            "folders/21"
        );
    }

    #[tokio::test]
    async fn only_restricts_projects() {
        let f = world();
        let mut o = PlanOptions::new(now());
        o.only = vec![pid("my-app-dev")];
        let p = plan(&f, MANIFEST, o).await.unwrap();
        assert_eq!(p.projects.len(), 1);
    }

    #[tokio::test]
    async fn missing_permissions_become_blockers_naming_the_role() {
        let f = world();
        f.deny_caller("projects/my-app-prod", "resourcemanager.projects.move");
        let p = plan(&f, MANIFEST, PlanOptions::new(now())).await.unwrap();
        let prod = p.project(&pid("my-app-prod")).unwrap();
        let blocker = prod
            .findings
            .iter()
            .find(|f| f.severity == Severity::Blocker)
            .unwrap();
        assert!(blocker.summary.contains("resourcemanager.projects.move"));
        assert!(blocker
            .summary
            .contains("roles/resourcemanager.projectMover"));
        assert!(!p.project(&pid("my-app-dev")).unwrap().has_blocker());
        assert!(p.has_blockers());
    }

    #[tokio::test]
    async fn org_policy_admin_needed_only_when_constraint_changes() {
        let f = world();
        f.deny_caller("organizations/111", "orgpolicy.policies.update");
        let p = plan(&f, MANIFEST, PlanOptions::new(now())).await.unwrap();
        assert!(p.has_blockers());
        // already allowed => no change needed => permission not required
        let f = world();
        f.allow_moves("111", "222");
        f.deny_caller("organizations/111", "orgpolicy.policies.update");
        let p = plan(&f, MANIFEST, PlanOptions::new(now())).await.unwrap();
        assert!(!p.has_blockers());
        assert!(p.policy_changes.is_empty());
    }

    #[tokio::test]
    async fn constraint_changes_are_planned_with_backup_refs() {
        let f = world();
        let p = plan(&f, MANIFEST, PlanOptions::new(now())).await.unwrap();
        assert_eq!(p.policy_changes.len(), 2);
        let export = p
            .policy_changes
            .iter()
            .find(|c| c.constraint == EXPORT_CONSTRAINT)
            .unwrap();
        assert_eq!(export.scope.to_string(), "organizations/111");
        assert_eq!(export.value, "under:organizations/222");
        assert_eq!(
            export.backup_ref,
            format!("policy-backups/organizations/111/{EXPORT_CONSTRAINT}")
        );
        let import = p
            .policy_changes
            .iter()
            .find(|c| c.constraint == IMPORT_CONSTRAINT)
            .unwrap();
        assert_eq!(import.value, "under:organizations/111");
    }

    #[tokio::test]
    async fn deny_all_constraint_is_a_blocker() {
        let f = world();
        let mut pol = OrgPolicy::empty(EXPORT_CONSTRAINT);
        pol.rules.push(crate::model::PolicyRule {
            deny_all: true,
            ..Default::default()
        });
        f.policy("organizations/111", pol);
        let p = plan(&f, MANIFEST, PlanOptions::new(now())).await.unwrap();
        assert!(p.has_blockers());
        assert!(p
            .policy_changes
            .iter()
            .all(|c| c.constraint != EXPORT_CONSTRAINT));
    }

    #[tokio::test]
    async fn lower_level_non_inheriting_policy_is_a_blocker() {
        let f = world();
        let mut pol = OrgPolicy::empty(EXPORT_CONSTRAINT);
        pol.allow_value("under:organizations/999");
        f.policy("folders/10", pol);
        let p = plan(&f, MANIFEST, PlanOptions::new(now())).await.unwrap();
        let prod = p.project(&pid("my-app-prod")).unwrap();
        assert!(prod
            .findings
            .iter()
            .any(|f| f.severity == Severity::Blocker && f.summary.contains("folders/10")));
        assert!(!p.project(&pid("my-app-dev")).unwrap().has_blocker());
    }

    #[tokio::test]
    async fn landing_parent_must_be_in_destination_org() {
        let f = world();
        // folder 10 is in the SOURCE org
        let text = MANIFEST.replace(
            "default_destination_folder: \"20\"",
            "default_destination_folder: \"10\"",
        );
        let p = plan(&f, &text, PlanOptions::new(now())).await.unwrap();
        let prod = p.project(&pid("my-app-prod")).unwrap();
        assert!(prod
            .findings
            .iter()
            .any(|f| f.summary.contains("not in destination")));
    }

    #[tokio::test]
    async fn project_must_be_in_source_org() {
        let f = world();
        f.folder("30", "organizations/222");
        f.project("elsewhere-proj", "3001", "folders/30");
        let text = MANIFEST.replace(
            "  - id: my-app-dev",
            "  - id: elsewhere-proj\n  - id: my-app-dev",
        );
        let p = plan(&f, &text, PlanOptions::new(now())).await.unwrap();
        assert!(p.project(&pid("elsewhere-proj")).unwrap().has_blocker());
    }

    #[tokio::test]
    async fn analyze_move_results_are_classified() {
        let f = world();
        f.set_analysis(
            "my-app-prod",
            MoveAnalysis {
                items: vec![
                    AnalysisItem {
                        level: AnalysisLevel::Blocker,
                        message: "Shared VPC host".into(),
                    },
                    AnalysisItem {
                        level: AnalysisLevel::Warning,
                        message: "org policy differs".into(),
                    },
                    AnalysisItem {
                        level: AnalysisLevel::Info,
                        message: "fyi".into(),
                    },
                ],
            },
        );
        let p = plan(&f, MANIFEST, PlanOptions::new(now())).await.unwrap();
        let prod = p.project(&pid("my-app-prod")).unwrap();
        assert_eq!(prod.analysis.blockers, ["Shared VPC host"]);
        assert_eq!(prod.analysis.warnings, ["org policy differs"]);
        assert_eq!(prod.analysis.info, ["fyi"]);
        assert_eq!(p.summary.blockers, 2); // analysis entry + its finding
    }

    #[tokio::test]
    async fn strict_promotes_warnings() {
        let f = world();
        f.set_analysis(
            "my-app-dev",
            MoveAnalysis {
                items: vec![AnalysisItem {
                    level: AnalysisLevel::Warning,
                    message: "w".into(),
                }],
            },
        );
        let relaxed = plan(&f, MANIFEST, PlanOptions::new(now())).await.unwrap();
        assert!(!relaxed.has_blockers());
        let mut o = PlanOptions::new(now());
        o.strict = true;
        let strict = plan(&f, MANIFEST, o).await.unwrap();
        assert!(strict.has_blockers());
    }

    #[tokio::test]
    async fn group_members_are_pulled_in_and_kept_in_one_batch() {
        let f = world();
        f.project("net-host-aa", "4001", "folders/10");
        f.project("app-svc-aaa", "4002", "folders/10");
        let text = r#"
version: 1
source_org: "111"
destination_org: "222"
default_destination_folder: "20"
projects:
  - id: my-app-prod
  - id: my-app-dev
groups:
  - name: vpc
    projects: [net-host-aa, app-svc-aaa]
limits:
  batch_size: 3
"#;
        let p = plan(&f, text, PlanOptions::new(now())).await.unwrap();
        assert_eq!(p.projects.len(), 4);
        let batch_of = |id: &str| p.order.iter().position(|b| b.contains(&pid(id))).unwrap();
        assert_eq!(batch_of("net-host-aa"), batch_of("app-svc-aaa"));
        assert_eq!(
            p.project(&pid("net-host-aa")).unwrap().group.as_deref(),
            Some("vpc")
        );
        assert!(p.order.iter().all(|b| b.len() <= 3));
    }

    struct Failing;
    #[async_trait::async_trait]
    impl ParityCheck for Failing {
        fn id(&self) -> &'static str {
            "boom"
        }
        async fn run(&self, _: &CheckCtx, _: &dyn Gcp) -> Result<Vec<Finding>> {
            Err(Error::new(ErrorKind::PermissionDenied, "nope"))
        }
    }

    #[tokio::test]
    async fn failing_check_blocks_unless_skipped() {
        let f = world();
        let m = Manifest::parse(MANIFEST).unwrap();
        let checks: Vec<Box<dyn ParityCheck>> = vec![Box::new(Failing)];
        let p = build_plan(&f, &m, &checks, &PlanOptions::new(now()))
            .await
            .unwrap();
        assert!(p.has_blockers());
        let mut o = PlanOptions::new(now());
        o.skip.insert("boom".into());
        let p = build_plan(&f, &m, &checks, &o).await.unwrap();
        assert!(!p.has_blockers());
    }

    #[test]
    fn merge_groups_unions_overlaps() {
        let g =
            |n: &str, ps: &[&str]| (n.to_string(), ps.iter().map(|p| pid(p)).collect::<Vec<_>>());
        let merged = merge_groups(&[
            g("b", &["aaaaaa", "bbbbbb"]),
            g("a", &["bbbbbb", "cccccc"]),
            g("z", &["dddddd"]),
        ]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].0, "a");
        assert_eq!(merged[0].1.len(), 3);
    }

    #[test]
    fn oversized_group_is_an_error() {
        let ids: BTreeSet<_> = ["aaaaaa", "bbbbbb", "cccccc"]
            .iter()
            .map(|s| pid(s))
            .collect();
        let groups = vec![("g".to_string(), ids.clone())];
        assert!(order_batches(&ids, &groups, 2).is_err());
    }

    fn vpc_world() -> FakeGcp {
        let f = world();
        f.project("net-host-aa", "5001", "folders/10");
        f.project("app-svc-aaa", "5002", "folders/10");
        f.project("app-svc-bbb", "5003", "folders/10");
        f.shared_vpc("net-host-aa", "app-svc-aaa");
        f.shared_vpc("net-host-aa", "app-svc-bbb");
        f
    }

    fn vpc_manifest(projects: &[&str], batch: usize) -> String {
        let list: String = projects.iter().map(|p| format!("  - id: {p}\n")).collect();
        format!(
            "version: 1\nsource_org: \"111\"\ndestination_org: \"222\"\ndefault_destination_folder: \"20\"\nprojects:\n{list}limits:\n  batch_size: {batch}\n"
        )
    }

    #[tokio::test]
    async fn shared_vpc_host_and_services_become_one_group() {
        let f = vpc_world();
        let text = vpc_manifest(
            &["net-host-aa", "app-svc-aaa", "app-svc-bbb", "my-app-dev"],
            3,
        );
        let p = plan(&f, &text, PlanOptions::new(now())).await.unwrap();
        assert!(
            !p.has_blockers(),
            "{:?}",
            p.projects
                .iter()
                .flat_map(|x| &x.findings)
                .collect::<Vec<_>>()
        );
        let host = p.project(&pid("net-host-aa")).unwrap();
        assert_eq!(host.group.as_deref(), Some("shared-vpc-net-host-aa"));
        assert_eq!(p.project(&pid("app-svc-bbb")).unwrap().group, host.group);
        assert_eq!(p.project(&pid("my-app-dev")).unwrap().group, None);
        let batch_of = |id: &str| p.order.iter().position(|b| b.contains(&pid(id))).unwrap();
        assert_eq!(batch_of("net-host-aa"), batch_of("app-svc-aaa"));
        assert_eq!(batch_of("net-host-aa"), batch_of("app-svc-bbb"));
        assert!(host
            .findings
            .iter()
            .any(|x| x.severity == Severity::Info && x.summary.contains("move together")));
    }

    #[tokio::test]
    async fn shared_vpc_half_in_scope_is_a_blocker_on_either_side() {
        let f = vpc_world();
        let p = plan(
            &f,
            &vpc_manifest(&["net-host-aa", "app-svc-aaa"], 5),
            PlanOptions::new(now()),
        )
        .await
        .unwrap();
        let host = p.project(&pid("net-host-aa")).unwrap();
        assert!(host
            .findings
            .iter()
            .any(|x| x.severity == Severity::Blocker && x.summary.contains("app-svc-bbb")));
        assert!(p.has_blockers());

        let p = plan(
            &f,
            &vpc_manifest(&["app-svc-aaa"], 5),
            PlanOptions::new(now()),
        )
        .await
        .unwrap();
        let svc = p.project(&pid("app-svc-aaa")).unwrap();
        assert!(svc
            .findings
            .iter()
            .any(|x| x.severity == Severity::Blocker && x.summary.contains("net-host-aa")));
    }

    #[tokio::test]
    async fn skipping_shared_vpc_disables_detection() {
        let f = vpc_world();
        let mut o = PlanOptions::new(now());
        o.skip.insert(SHARED_VPC_CHECK.into());
        let p = plan(&f, &vpc_manifest(&["net-host-aa"], 5), o)
            .await
            .unwrap();
        assert!(!p.has_blockers());
        assert_eq!(f.calls_to("shared_vpc_relationships"), 0);
    }

    #[tokio::test]
    async fn oversized_vpc_group_blocks_its_members_instead_of_failing_the_plan() {
        let f = vpc_world();
        let text = vpc_manifest(&["net-host-aa", "app-svc-aaa", "app-svc-bbb"], 2);
        let p = plan(&f, &text, PlanOptions::new(now())).await.unwrap();
        for id in ["net-host-aa", "app-svc-aaa", "app-svc-bbb"] {
            let pr = p.project(&pid(id)).unwrap();
            assert!(
                pr.findings
                    .iter()
                    .any(|x| x.severity == Severity::Blocker && x.summary.contains("batch_size")),
                "{id}"
            );
        }
        assert_eq!(p.order.iter().map(Vec::len).sum::<usize>(), 3);
    }

    #[tokio::test]
    async fn vpc_groups_merge_with_overlapping_manifest_groups() {
        let f = vpc_world();
        let text = format!(
            "{}groups:\n  - name: zeta\n    projects: [app-svc-bbb, my-app-dev]\n",
            vpc_manifest(
                &["net-host-aa", "app-svc-aaa", "app-svc-bbb", "my-app-dev"],
                4
            )
        );
        let p = plan(&f, &text, PlanOptions::new(now())).await.unwrap();
        let g = p.project(&pid("net-host-aa")).unwrap().group.clone();
        assert_eq!(
            g.as_deref(),
            Some("shared-vpc-net-host-aa"),
            "smallest name wins"
        );
        for id in ["net-host-aa", "app-svc-aaa", "app-svc-bbb", "my-app-dev"] {
            assert_eq!(p.project(&pid(id)).unwrap().group, g, "{id}");
        }
        assert_eq!(p.order.len(), 1);
    }

    #[tokio::test]
    async fn plan_reports_its_phases_in_order_and_always_ends() {
        use crate::progress::Recorder;
        let f = world();
        let rec = Recorder::new();
        let mut o = PlanOptions::new(now());
        o.observer = rec.clone();
        plan(&f, MANIFEST, o).await.unwrap();
        let names: Vec<String> = rec.phases().into_iter().map(|(n, _)| n).collect();
        let pos = |n: &str| {
            names
                .iter()
                .position(|x| x == n)
                .unwrap_or_else(|| panic!("missing phase {n}: {names:?}"))
        };
        assert!(pos("Resolving projects") < pos("Checking hierarchy"));
        assert!(pos("Checking hierarchy") < pos("Analyzing moves"));
        assert!(pos("Analyzing moves") < pos("Detecting Shared VPC"));
        assert!(pos("Detecting Shared VPC") < pos("Ordering batches"));
        let analyze_total = rec
            .phases()
            .into_iter()
            .find(|(n, _)| n == "Analyzing moves")
            .unwrap()
            .1;
        assert_eq!(analyze_total, 2, "one unit per project");
        assert_eq!(rec.ends(), 1, "a single End closes the last phase");
    }

    #[tokio::test]
    async fn plan_ends_the_phase_when_it_fails_early() {
        use crate::progress::Recorder;
        let f = world();
        f.inject_fault("get_project", Error::new(ErrorKind::PermissionDenied, "no"));
        let rec = Recorder::new();
        let mut o = PlanOptions::new(now());
        o.observer = rec.clone();
        assert!(plan(&f, MANIFEST, o).await.is_err());
        assert_eq!(rec.ends(), 1);
    }

    #[tokio::test]
    async fn move_permissions_are_asked_of_the_mover_and_org_permissions_of_the_org_admin() {
        let f = world();
        plan(&f, MANIFEST, PlanOptions::new(now())).await.unwrap();
        let calls = f.calls();
        let has = |c: &str| calls.iter().any(|x| x == c);
        // projects.move / projects.create: the identity that performs the move
        assert!(
            has("test_move_permissions(projects/my-app-prod)"),
            "{calls:?}"
        );
        assert!(has("test_move_permissions(folders/10)"));
        assert!(
            has("test_move_permissions(folders/20)"),
            "landing parent: projects.create"
        );
        // org-policy permissions: whoever administers that organization
        assert!(has("test_permissions(organizations/111)"));
        assert!(has("test_permissions(organizations/222)"));
        // reads on the project itself belong to its own org's login
        assert!(has("test_permissions(projects/my-app-prod)"));
        assert!(
            !has("test_permissions(folders/20)"),
            "the landing folder is checked as the mover only"
        );
    }

    proptest! {
        #[test]
        fn batches_keep_groups_whole_and_respect_size(
            n in 1usize..30,
            batch in 3usize..8,
            group_sizes in proptest::collection::vec(2usize..4, 0..5),
        ) {
            let ids: Vec<ProjectId> = (0..n).map(|i| pid(&format!("proj-{i:04}"))).collect();
            let all: BTreeSet<ProjectId> = ids.iter().cloned().collect();
            let mut groups = vec![];
            let mut next = 0;
            for (gi, sz) in group_sizes.iter().enumerate() {
                if next + sz <= n {
                    groups.push((format!("g{gi}"), ids[next..next + sz].iter().cloned().collect::<BTreeSet<_>>()));
                    next += sz;
                }
            }
            let batches = order_batches(&all, &groups, batch).unwrap();
            // deterministic
            prop_assert_eq!(&batches, &order_batches(&all, &groups, batch).unwrap());
            // every project exactly once
            let flat: Vec<_> = batches.iter().flatten().cloned().collect();
            prop_assert_eq!(flat.len(), n);
            prop_assert_eq!(flat.iter().cloned().collect::<BTreeSet<_>>(), all);
            // size bound and groups whole
            for b in &batches {
                prop_assert!(b.len() <= batch);
            }
            for (_, g) in &groups {
                let homes: BTreeSet<_> = g.iter().map(|p| batches.iter().position(|b| b.contains(p)).unwrap()).collect();
                prop_assert_eq!(homes.len(), 1);
            }
        }
    }
}
