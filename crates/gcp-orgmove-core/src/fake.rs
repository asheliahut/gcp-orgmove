//! In-memory `Gcp` implementation for tests (no network).
//!
//! Models an org/folder/project tree with IAM, org policies, custom roles and
//! friends, with real semantics where tests depend on them:
//! * etag-checked `set_iam`/`set_policy` (stale etag -> `Conflict`);
//! * `move_project` enforces the export/import org-policy constraints, so a
//!   missing constraint setup fails exactly like the real API;
//! * long-running operations that complete after N polls, applying the move
//!   on completion;
//! * per-method fault injection and a call log for assertions.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;

use crate::error::{Error, ErrorKind, Result};
use crate::gcp::*;
use crate::ids::*;
use crate::model::*;

const MUTATING: &[&str] = &[
    "move_project",
    "set_project_labels",
    "set_iam",
    "create_custom_role",
    "delete_custom_role",
    "set_policy",
    "delete_policy",
];

#[derive(Debug, Clone)]
struct PendingOp {
    project: ProjectId,
    dest: Parent,
    polls_left: u32,
    fail: Option<String>,
}

#[derive(Default)]
struct Inner {
    orgs: BTreeSet<OrgId>,
    folders: BTreeMap<FolderId, Parent>,
    projects: BTreeMap<ProjectId, Project>,
    iam: BTreeMap<Resource, IamPolicy>,
    etag_counter: u64,
    policies: BTreeMap<(Resource, String), OrgPolicy>,
    roles: BTreeMap<RoleName, CustomRole>,
    deny: BTreeMap<Resource, Vec<DenyPolicy>>,
    firewall: BTreeMap<Resource, Vec<FirewallPolicy>>,
    shared_vpc: Vec<SharedVpcLink>,
    groups: BTreeSet<String>,
    perimeters: Vec<Perimeter>,
    org_scoped: BTreeMap<ProjectId, Vec<OrgScopedItem>>,
    analysis: BTreeMap<ProjectId, MoveAnalysis>,
    caller_denied: BTreeSet<(Resource, String)>,
    principal_perms: BTreeMap<String, BTreeSet<String>>,
    ops: BTreeMap<String, PendingOp>,
    op_counter: u64,
    op_polls: u32,
    fail_next_op: Option<String>,
    faults: BTreeMap<String, VecDeque<Error>>,
    calls: Vec<String>,
}

/// Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct FakeGcp {
    inner: Arc<Mutex<Inner>>,
}

impl FakeGcp {
    pub fn new() -> Self {
        let f = Self::default();
        f.lock().op_polls = 1;
        f
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap()
    }

    // ------------------------------------------------------------ builders

    pub fn org(&self, id: &str) -> &Self {
        self.lock().orgs.insert(id.parse().unwrap());
        self
    }

    pub fn folder(&self, id: &str, parent: &str) -> &Self {
        self.lock()
            .folders
            .insert(id.parse().unwrap(), parent.parse().unwrap());
        self
    }

    pub fn project(&self, id: &str, number: &str, parent: &str) -> &Self {
        let mut g = self.lock();
        g.etag_counter += 1;
        let etag = format!("p{}", g.etag_counter);
        let p = Project {
            id: id.parse().unwrap(),
            number: number.parse().unwrap(),
            parent: parent.parse().unwrap(),
            state: LifecycleState::Active,
            labels: BTreeMap::new(),
            etag,
        };
        g.projects.insert(p.id.clone(), p);
        self
    }

    pub fn grant(&self, resource: &str, role: &str, member: &str) -> &Self {
        let r: Resource = resource.parse().unwrap();
        let mut g = self.lock();
        let pol = g.iam.entry(r).or_default();
        pol.add_binding(&Binding {
            role: RoleName::new(role),
            members: BTreeSet::from([member.to_string()]),
            condition: None,
        });
        g.etag_counter += 1;
        let etag = format!("e{}", g.etag_counter);
        for p in g.iam.values_mut() {
            if p.etag.is_empty() {
                p.etag = etag.clone();
            }
        }
        self
    }

    pub fn policy(&self, scope: &str, policy: OrgPolicy) -> &Self {
        self.lock()
            .policies
            .insert((scope.parse().unwrap(), policy.constraint.clone()), policy);
        self
    }

    /// Allow `under:organizations/<dest>` for export on `src` and
    /// `under:organizations/<src>` for import on `dest` (what `apply` does).
    pub fn allow_moves(&self, src: &str, dest: &str) -> &Self {
        let mut e = OrgPolicy::empty(EXPORT_CONSTRAINT);
        e.allow_value(&format!("under:organizations/{dest}"));
        let mut i = OrgPolicy::empty(IMPORT_CONSTRAINT);
        i.allow_value(&format!("under:organizations/{src}"));
        self.policy(&format!("organizations/{src}"), e);
        self.policy(&format!("organizations/{dest}"), i);
        self
    }

    pub fn custom_role(&self, role: CustomRole) -> &Self {
        self.lock().roles.insert(role.name.clone(), role);
        self
    }

    pub fn deny_policy(&self, at: &str, p: DenyPolicy) -> &Self {
        self.lock()
            .deny
            .entry(at.parse().unwrap())
            .or_default()
            .push(p);
        self
    }

    pub fn firewall_policy(&self, at: &str, p: FirewallPolicy) -> &Self {
        self.lock()
            .firewall
            .entry(at.parse().unwrap())
            .or_default()
            .push(p);
        self
    }

    pub fn shared_vpc(&self, host: &str, service: &str) -> &Self {
        self.lock().shared_vpc.push(SharedVpcLink {
            host: host.parse().unwrap(),
            service: service.parse().unwrap(),
        });
        self
    }

    pub fn group(&self, email: &str) -> &Self {
        self.lock().groups.insert(email.to_string());
        self
    }

    pub fn perimeter(&self, p: Perimeter) -> &Self {
        self.lock().perimeters.push(p);
        self
    }

    pub fn org_scoped_item(&self, project: &str, item: OrgScopedItem) -> &Self {
        self.lock()
            .org_scoped
            .entry(project.parse().unwrap())
            .or_default()
            .push(item);
        self
    }

    pub fn set_analysis(&self, project: &str, a: MoveAnalysis) -> &Self {
        self.lock().analysis.insert(project.parse().unwrap(), a);
        self
    }

    /// The caller lacks `perm` on `resource` (affects `test_permissions`).
    pub fn deny_caller(&self, resource: &str, perm: &str) -> &Self {
        self.lock()
            .caller_denied
            .insert((resource.parse().unwrap(), perm.to_string()));
        self
    }

    pub fn principal_can(&self, principal: &str, perms: &[&str]) -> &Self {
        self.lock()
            .principal_perms
            .entry(principal.to_string())
            .or_default()
            .extend(perms.iter().map(|s| s.to_string()));
        self
    }

    /// LROs report `Running` for `n` polls, then complete.
    pub fn set_op_polls(&self, n: u32) -> &Self {
        self.lock().op_polls = n;
        self
    }

    /// The next started operation fails with `message` when it completes.
    pub fn fail_next_operation(&self, message: &str) -> &Self {
        self.lock().fail_next_op = Some(message.to_string());
        self
    }

    /// Queue an error returned by the next call to `method` (FIFO per method).
    pub fn inject_fault(&self, method: &str, err: Error) -> &Self {
        self.lock()
            .faults
            .entry(method.to_string())
            .or_default()
            .push_back(err);
        self
    }

    // ----------------------------------------------------------- inspection

    pub fn calls(&self) -> Vec<String> {
        self.lock().calls.clone()
    }

    pub fn calls_to(&self, method: &str) -> usize {
        let prefix = format!("{method}(");
        self.lock()
            .calls
            .iter()
            .filter(|c| c.starts_with(&prefix))
            .count()
    }

    pub fn mutating_calls(&self) -> Vec<String> {
        self.lock()
            .calls
            .iter()
            .filter(|c| MUTATING.iter().any(|m| c.starts_with(&format!("{m}("))))
            .cloned()
            .collect()
    }

    pub fn parent_of(&self, project: &str) -> Parent {
        self.lock().projects[&project.parse::<ProjectId>().unwrap()]
            .parent
            .clone()
    }

    pub fn policy_at(&self, scope: &str, constraint: &str) -> Option<OrgPolicy> {
        self.lock()
            .policies
            .get(&(scope.parse().unwrap(), constraint.to_string()))
            .cloned()
    }

    pub fn iam_at(&self, resource: &str) -> IamPolicy {
        self.lock()
            .iam
            .get(&resource.parse().unwrap())
            .cloned()
            .unwrap_or_default()
    }

    pub fn has_role(&self, name: &str) -> bool {
        self.lock().roles.contains_key(&RoleName::new(name))
    }

    pub fn clear_calls(&self) {
        self.lock().calls.clear();
    }

    // --------------------------------------------------------------- helpers

    /// Log the call and pop an injected fault, if any.
    fn enter(&self, method: &str, args: &str) -> Result<MutexGuard<'_, Inner>> {
        let mut g = self.lock();
        g.calls.push(format!("{method}({args})"));
        if let Some(e) = g.faults.get_mut(method).and_then(VecDeque::pop_front) {
            return Err(e);
        }
        Ok(g)
    }
}

impl Inner {
    fn parent_of_folder(&self, f: &FolderId) -> Result<&Parent> {
        self.folders.get(f).ok_or_else(|| {
            Error::new(ErrorKind::NotFound, format!("folder {f} not found"))
                .with_resource(format!("folders/{f}"))
        })
    }

    fn project_ref(&self, id: &ProjectId) -> Result<&Project> {
        self.projects.get(id).ok_or_else(|| {
            Error::new(ErrorKind::NotFound, format!("project {id} not found"))
                .with_resource(format!("projects/{id}"))
        })
    }

    /// Immediate parent first, ending at the org.
    fn ancestors_of_parent(&self, parent: &Parent) -> Result<Vec<Parent>> {
        let mut out = vec![parent.clone()];
        let mut cur = parent.clone();
        while let Parent::Folder(f) = &cur {
            cur = self.parent_of_folder(f)?.clone();
            out.push(cur.clone());
        }
        Ok(out)
    }

    fn org_of(&self, parent: &Parent) -> Result<OrgId> {
        match self.ancestors_of_parent(parent)?.pop() {
            Some(Parent::Org(o)) => Ok(o),
            _ => Err(Error::internal("hierarchy does not end at an organization")),
        }
    }

    /// The resource itself followed by its ancestors.
    fn chain(&self, r: &Resource) -> Result<Vec<Resource>> {
        let mut out = vec![r.clone()];
        let start = match r {
            Resource::Project(p) => self.project_ref(p)?.parent.clone(),
            Resource::Folder(f) => self.parent_of_folder(f)?.clone(),
            Resource::Org(_) => return Ok(out),
        };
        out.extend(
            self.ancestors_of_parent(&start)?
                .iter()
                .map(Resource::from_parent),
        );
        Ok(out)
    }

    fn effective_policy(&self, scope: &Resource, constraint: &str) -> Result<OrgPolicy> {
        let chain = self.chain(scope)?;
        // Walk from the root down, merging.
        let mut eff = OrgPolicy::empty(constraint);
        for r in chain.iter().rev() {
            let Some(p) = self.policies.get(&(r.clone(), constraint.to_string())) else {
                continue;
            };
            if p.reset {
                eff = OrgPolicy::empty(constraint);
            } else if p.inherit_from_parent {
                let mut merged = eff.clone();
                merged.rules.extend(p.rules.clone());
                merged.inherit_from_parent = true;
                eff = merged;
            } else {
                eff = p.clone();
            }
        }
        eff.etag = String::new();
        Ok(eff)
    }

    fn next_etag(&mut self) -> String {
        self.etag_counter += 1;
        format!("e{}", self.etag_counter)
    }
}

fn ok_or_perm(cond: bool, what: &str) -> Result<()> {
    if cond {
        Ok(())
    } else {
        Err(Error::new(ErrorKind::PolicyViolation, what.to_string()))
    }
}

#[async_trait]
impl Gcp for FakeGcp {
    async fn list_projects(&self, parent: &Parent) -> Result<Vec<Project>> {
        let g = self.enter("list_projects", &parent.to_string())?;
        let mut out = vec![];
        for p in g.projects.values() {
            if g.ancestors_of_parent(&p.parent)?.contains(parent) {
                out.push(p.clone());
            }
        }
        Ok(out)
    }

    async fn get_project(&self, id: &ProjectId) -> Result<Project> {
        let g = self.enter("get_project", id.as_str())?;
        g.project_ref(id).cloned()
    }

    async fn get_ancestry(&self, id: &ProjectId) -> Result<Vec<Parent>> {
        let g = self.enter("get_ancestry", id.as_str())?;
        g.ancestors_of_parent(&g.project_ref(id)?.parent)
    }

    async fn get_folder_ancestry(&self, folder: &FolderId) -> Result<Vec<Parent>> {
        let g = self.enter("get_folder_ancestry", folder.as_str())?;
        g.ancestors_of_parent(g.parent_of_folder(folder)?)
    }

    async fn move_project(&self, id: &ProjectId, dest: &Parent) -> Result<Operation> {
        let mut g = self.enter("move_project", &format!("{id}, {dest}"))?;
        let project = g.project_ref(id)?.clone();
        let src_org = g.org_of(&project.parent)?;
        let dest_org = g.org_of(dest)?;
        if src_org != dest_org {
            let export = g.effective_policy(&Resource::Org(src_org.clone()), EXPORT_CONSTRAINT)?;
            ok_or_perm(
                export.allows(&format!("under:organizations/{dest_org}")),
                &format!("{EXPORT_CONSTRAINT} on organizations/{src_org} does not allow under:organizations/{dest_org}"),
            )?;
            let import = g.effective_policy(&Resource::Org(dest_org.clone()), IMPORT_CONSTRAINT)?;
            ok_or_perm(
                import.allows(&format!("under:organizations/{src_org}")),
                &format!("{IMPORT_CONSTRAINT} on organizations/{dest_org} does not allow under:organizations/{src_org}"),
            )?;
        }
        g.op_counter += 1;
        let name = format!("operations/cp.{}", g.op_counter);
        let fail = g.fail_next_op.take();
        let polls = g.op_polls;
        g.ops.insert(
            name.clone(),
            PendingOp {
                project: id.clone(),
                dest: dest.clone(),
                polls_left: polls,
                fail,
            },
        );
        Ok(Operation { name })
    }

    async fn poll_operation(&self, op: &Operation) -> Result<OperationStatus> {
        let mut g = self.enter("poll_operation", &op.name)?;
        let Some(pending) = g.ops.get_mut(&op.name) else {
            return Err(Error::new(
                ErrorKind::NotFound,
                format!("operation {} not found", op.name),
            ));
        };
        if pending.polls_left > 0 {
            pending.polls_left -= 1;
            return Ok(OperationStatus::Running);
        }
        let pending = g.ops.remove(&op.name).unwrap();
        if let Some(message) = pending.fail {
            return Ok(OperationStatus::Failed { code: 9, message });
        }
        let etag = g.next_etag();
        let p = g.projects.get_mut(&pending.project).unwrap();
        p.parent = pending.dest;
        p.etag = etag;
        Ok(OperationStatus::Done)
    }

    async fn set_project_labels(
        &self,
        id: &ProjectId,
        labels: BTreeMap<String, String>,
    ) -> Result<Project> {
        let mut g = self.enter("set_project_labels", id.as_str())?;
        g.project_ref(id)?;
        let etag = g.next_etag();
        let p = g.projects.get_mut(id).unwrap();
        p.labels = labels;
        p.etag = etag;
        Ok(p.clone())
    }

    async fn analyze_move(&self, id: &ProjectId, dest: &Parent) -> Result<MoveAnalysis> {
        let g = self.enter("analyze_move", &format!("{id}, {dest}"))?;
        g.project_ref(id)?;
        g.ancestors_of_parent(dest)?;
        Ok(g.analysis.get(id).cloned().unwrap_or_default())
    }

    async fn get_iam(&self, r: &Resource) -> Result<IamPolicy> {
        let g = self.enter("get_iam", &r.to_string())?;
        g.chain(r)?;
        Ok(g.iam.get(r).cloned().unwrap_or_else(|| IamPolicy {
            bindings: vec![],
            etag: "0".into(),
        }))
    }

    async fn set_iam(&self, r: &Resource, p: IamPolicy) -> Result<IamPolicy> {
        let mut g = self.enter("set_iam", &r.to_string())?;
        g.chain(r)?;
        let current = g
            .iam
            .get(r)
            .map(|c| c.etag.clone())
            .unwrap_or_else(|| "0".into());
        if p.etag != current {
            return Err(
                Error::new(ErrorKind::Conflict, format!("etag mismatch on {r}")).with_resource(r),
            );
        }
        let mut stored = p;
        stored.etag = g.next_etag();
        g.iam.insert(r.clone(), stored.clone());
        Ok(stored)
    }

    async fn get_effective_iam(&self, r: &Resource) -> Result<EffectiveIam> {
        let g = self.enter("get_effective_iam", &r.to_string())?;
        let mut grants = vec![];
        for res in g.chain(r)? {
            if let Some(pol) = g.iam.get(&res) {
                for grant in pol.flatten() {
                    grants.push(EffectiveGrant {
                        grant,
                        from: res.clone(),
                    });
                }
            }
        }
        Ok(EffectiveIam { grants })
    }

    async fn test_permissions(&self, r: &Resource, perms: &[String]) -> Result<Vec<String>> {
        let g = self.enter("test_permissions", &r.to_string())?;
        g.chain(r)?;
        Ok(perms
            .iter()
            .filter(|p| !g.caller_denied.contains(&(r.clone(), (*p).clone())))
            .cloned()
            .collect())
    }

    async fn test_move_permissions(&self, r: &Resource, perms: &[String]) -> Result<Vec<String>> {
        let g = self.enter("test_move_permissions", &r.to_string())?;
        g.chain(r)?;
        Ok(perms
            .iter()
            .filter(|p| !g.caller_denied.contains(&(r.clone(), (*p).clone())))
            .cloned()
            .collect())
    }

    async fn troubleshoot_access(
        &self,
        r: &Resource,
        principal: &str,
        perms: &[String],
    ) -> Result<Vec<AccessVerdict>> {
        let g = self.enter("troubleshoot_access", &format!("{r}, {principal}"))?;
        g.chain(r)?;
        let have = g.principal_perms.get(principal);
        Ok(perms
            .iter()
            .map(|p| AccessVerdict {
                permission: p.clone(),
                granted: have.is_some_and(|h| h.contains(p)),
            })
            .collect())
    }

    async fn list_custom_roles(&self, org: &OrgId) -> Result<Vec<CustomRole>> {
        let g = self.enter("list_custom_roles", org.as_str())?;
        Ok(g.roles
            .values()
            .filter(|r| r.name.org_custom().is_some_and(|(o, _)| &o == org))
            .cloned()
            .collect())
    }

    async fn get_custom_role(&self, name: &RoleName) -> Result<Option<CustomRole>> {
        let g = self.enter("get_custom_role", name.as_str())?;
        Ok(g.roles.get(name).cloned())
    }

    async fn create_custom_role(&self, org: &OrgId, role: CustomRole) -> Result<CustomRole> {
        let mut g = self.enter("create_custom_role", role.name.as_str())?;
        match role.name.org_custom() {
            Some((o, _)) if &o == org => {}
            _ => {
                return Err(Error::invalid(format!(
                    "role {} does not belong to organization {org}",
                    role.name
                )))
            }
        }
        match g.roles.get(&role.name) {
            Some(existing) if *existing == role => Ok(role),
            Some(_) => Err(Error::new(
                ErrorKind::Conflict,
                format!(
                    "role {} already exists with a different definition",
                    role.name
                ),
            )),
            None => {
                g.roles.insert(role.name.clone(), role.clone());
                Ok(role)
            }
        }
    }

    async fn delete_custom_role(&self, name: &RoleName) -> Result<()> {
        let mut g = self.enter("delete_custom_role", name.as_str())?;
        g.roles.remove(name);
        Ok(())
    }

    async fn list_deny_policies(&self, r: &Resource) -> Result<Vec<DenyPolicy>> {
        let g = self.enter("list_deny_policies", &r.to_string())?;
        Ok(g.deny.get(r).cloned().unwrap_or_default())
    }

    async fn get_policy(&self, scope: &Scope, constraint: &str) -> Result<Option<OrgPolicy>> {
        let g = self.enter("get_policy", &format!("{scope}, {constraint}"))?;
        g.chain(scope)?;
        Ok(g.policies
            .get(&(scope.clone(), constraint.to_string()))
            .cloned())
    }

    async fn get_effective_policy(&self, scope: &Scope, constraint: &str) -> Result<OrgPolicy> {
        let g = self.enter("get_effective_policy", &format!("{scope}, {constraint}"))?;
        g.effective_policy(scope, constraint)
    }

    async fn list_policies(&self, scope: &Scope) -> Result<Vec<OrgPolicy>> {
        let g = self.enter("list_policies", &scope.to_string())?;
        Ok(g.policies
            .iter()
            .filter(|((s, _), _)| s == scope)
            .map(|(_, p)| p.clone())
            .collect())
    }

    async fn set_policy(&self, scope: &Scope, policy: OrgPolicy) -> Result<()> {
        let mut g = self.enter("set_policy", &format!("{scope}, {}", policy.constraint))?;
        g.chain(scope)?;
        let key = (scope.clone(), policy.constraint.clone());
        let current = g.policies.get(&key).map(|p| p.etag.clone());
        if let Some(cur) = &current {
            if !policy.etag.is_empty() && &policy.etag != cur {
                return Err(Error::new(
                    ErrorKind::Conflict,
                    format!("etag mismatch on {scope} {}", policy.constraint),
                ));
            }
        }
        let mut stored = policy;
        stored.etag = g.next_etag();
        g.policies.insert(key, stored);
        Ok(())
    }

    async fn delete_policy(&self, scope: &Scope, constraint: &str) -> Result<()> {
        let mut g = self.enter("delete_policy", &format!("{scope}, {constraint}"))?;
        g.policies.remove(&(scope.clone(), constraint.to_string()));
        Ok(())
    }

    async fn list_firewall_policies(&self, r: &Resource) -> Result<Vec<FirewallPolicy>> {
        let g = self.enter("list_firewall_policies", &r.to_string())?;
        Ok(g.firewall.get(r).cloned().unwrap_or_default())
    }

    async fn shared_vpc_relationships(&self, project: &ProjectId) -> Result<Vec<SharedVpcLink>> {
        let g = self.enter("shared_vpc_relationships", project.as_str())?;
        Ok(g.shared_vpc
            .iter()
            .filter(|l| &l.host == project || &l.service == project)
            .cloned()
            .collect())
    }

    async fn group_exists(&self, email: &str) -> Result<bool> {
        let g = self.enter("group_exists", email)?;
        Ok(g.groups.contains(email))
    }

    async fn list_vpc_sc_perimeters(&self, org: &OrgId) -> Result<Vec<Perimeter>> {
        let g = self.enter("list_vpc_sc_perimeters", org.as_str())?;
        Ok(g.perimeters.clone())
    }

    async fn list_org_scoped(
        &self,
        org: &OrgId,
        project: &ProjectId,
    ) -> Result<Vec<OrgScopedItem>> {
        let g = self.enter("list_org_scoped", &format!("{org}, {project}"))?;
        Ok(g.org_scoped.get(project).cloned().unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn world() -> FakeGcp {
        let f = FakeGcp::new();
        f.org("111").org("222");
        f.folder("10", "organizations/111");
        f.folder("20", "organizations/222");
        f.project("my-app-prod", "1001", "folders/10");
        f.project("my-app-dev", "1002", "organizations/111");
        f
    }

    fn pid(s: &str) -> ProjectId {
        s.parse().unwrap()
    }

    async fn run_move(f: &FakeGcp, p: &str, dest: &str) -> Result<OperationStatus> {
        let op = f.move_project(&pid(p), &dest.parse().unwrap()).await?;
        loop {
            match f.poll_operation(&op).await? {
                OperationStatus::Running => continue,
                done => return Ok(done),
            }
        }
    }

    #[tokio::test]
    async fn move_requires_constraints_on_both_sides() {
        let f = world();
        let err = run_move(&f, "my-app-prod", "folders/20").await.unwrap_err();
        assert!(
            err.message.contains("allowedExportDestinations"),
            "{}",
            err.message
        );
        f.allow_moves("111", "222");
        assert_eq!(
            run_move(&f, "my-app-prod", "folders/20").await.unwrap(),
            OperationStatus::Done
        );
        assert_eq!(f.parent_of("my-app-prod").to_string(), "folders/20");
    }

    #[tokio::test]
    async fn move_applies_on_completion_not_start() {
        let f = world();
        f.allow_moves("111", "222").set_op_polls(2);
        let op = f
            .move_project(&pid("my-app-dev"), &"organizations/222".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(f.parent_of("my-app-dev").to_string(), "organizations/111");
        assert_eq!(
            f.poll_operation(&op).await.unwrap(),
            OperationStatus::Running
        );
        assert_eq!(
            f.poll_operation(&op).await.unwrap(),
            OperationStatus::Running
        );
        assert_eq!(f.poll_operation(&op).await.unwrap(), OperationStatus::Done);
        assert_eq!(f.parent_of("my-app-dev").to_string(), "organizations/222");
    }

    #[tokio::test]
    async fn failed_operation_does_not_move() {
        let f = world();
        f.allow_moves("111", "222").fail_next_operation("quota");
        let st = run_move(&f, "my-app-dev", "organizations/222")
            .await
            .unwrap();
        assert!(matches!(st, OperationStatus::Failed { .. }));
        assert_eq!(f.parent_of("my-app-dev").to_string(), "organizations/111");
    }

    #[tokio::test]
    async fn set_iam_is_etag_checked() {
        let f = world();
        f.grant("projects/my-app-prod", "roles/viewer", "user:a@x.com");
        let r: Resource = "projects/my-app-prod".parse().unwrap();
        let mut p = f.get_iam(&r).await.unwrap();
        let stale = p.clone();
        p.add_binding(&Binding {
            role: RoleName::new("roles/editor"),
            members: BTreeSet::from(["user:b@x.com".to_string()]),
            condition: None,
        });
        f.set_iam(&r, p).await.unwrap();
        let err = f.set_iam(&r, stale).await.unwrap_err();
        assert_eq!(err.kind, ErrorKind::Conflict);
    }

    #[tokio::test]
    async fn effective_iam_walks_ancestors() {
        let f = world();
        f.grant("organizations/111", "roles/viewer", "group:eng@x.com");
        f.grant("folders/10", "roles/editor", "group:eng@x.com");
        f.grant("projects/my-app-prod", "roles/owner", "user:o@x.com");
        let eff = f
            .get_effective_iam(&"projects/my-app-prod".parse().unwrap())
            .await
            .unwrap();
        let from: Vec<String> = eff.grants.iter().map(|g| g.from.to_string()).collect();
        assert_eq!(
            from,
            ["projects/my-app-prod", "folders/10", "organizations/111"]
        );
    }

    #[tokio::test]
    async fn faults_are_fifo_and_logged() {
        let f = world();
        f.inject_fault("get_project", Error::new(ErrorKind::QuotaExceeded, "429"));
        assert_eq!(
            f.get_project(&pid("my-app-dev")).await.unwrap_err().kind,
            ErrorKind::QuotaExceeded
        );
        assert!(f.get_project(&pid("my-app-dev")).await.is_ok());
        assert_eq!(f.calls_to("get_project"), 2);
        assert!(f.mutating_calls().is_empty());
    }

    #[tokio::test]
    async fn list_projects_is_recursive() {
        let f = world();
        let all = f
            .list_projects(&"organizations/111".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(all.len(), 2);
        let in_folder = f
            .list_projects(&"folders/10".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(in_folder.len(), 1);
    }

    #[tokio::test]
    async fn effective_policy_merges_inherit() {
        let f = world();
        let mut org = OrgPolicy::empty("constraints/x");
        org.allow_value("a");
        f.policy("organizations/111", org);
        let mut folder = OrgPolicy::empty("constraints/x");
        folder.inherit_from_parent = true;
        folder.allow_value("b");
        f.policy("folders/10", folder);
        let eff = f
            .get_effective_policy(&"projects/my-app-prod".parse().unwrap(), "constraints/x")
            .await
            .unwrap();
        assert!(eff.allows("a") && eff.allows("b"));
    }

    #[tokio::test]
    async fn custom_role_create_is_idempotent_but_rejects_conflict() {
        let f = world();
        let role = CustomRole {
            name: RoleName::new("organizations/222/roles/r"),
            title: "r".into(),
            description: String::new(),
            permissions: BTreeSet::from(["a.b.c".to_string()]),
            stage: RoleStage::Ga,
        };
        let org: OrgId = "222".parse().unwrap();
        f.create_custom_role(&org, role.clone()).await.unwrap();
        f.create_custom_role(&org, role.clone()).await.unwrap();
        let mut other = role;
        other.permissions.insert("d.e.f".into());
        assert_eq!(
            f.create_custom_role(&org, other).await.unwrap_err().kind,
            ErrorKind::Conflict
        );
    }
}
