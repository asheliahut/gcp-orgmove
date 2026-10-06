//! `Gcp` implemented on the official Google Cloud Rust SDK.
//!
//! * SDK clients are built lazily (an unused API never needs to be enabled
//!   or reachable) and share one retry policy (`retry`).
//! * Every call passes through the AIMD [`Limiter`].
//! * Cloud Identity Groups has no SDK client, so it uses `reqwest`
//!   (`identity.rs`) with the same credentials.
//!
//! # Two logins
//!
//! The source and destination organizations may use different logins. There is
//! one set of SDK clients per side ([`View`]); the `Gcp` implementation on
//! [`RealGcp`] routes each call to the side that owns the resource:
//!
//! * which side owns an org, folder or project is *learned*: try the
//!   preferred side (the learned one, else the source), and on
//!   `PermissionDenied`/`NotFound` try the other, remembering whichever works;
//!   [`RealGcp::hint_org`] and friends seed this from the manifest so common
//!   cases cost no extra calls;
//! * `projects.move`, `analyzeMove` and the move-permission preflight use the
//!   **mover**'s login ([`Config::move_side`]): the move needs rights on both
//!   sides, so one login has to hold them;
//! * with a single login (`destination: None`) there is exactly one side and
//!   nothing is routed.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use gcp_orgmove_core::*;
use google_cloud_asset_v1::client::AssetService;
use google_cloud_auth::credentials::Credentials;
use google_cloud_compute_v1::client::{FirewallPolicies, Projects as ComputeProjects};
use google_cloud_gax::paginator::ItemPaginator;
use google_cloud_iam_admin_v1::client::Iam;
use google_cloud_iam_v1::model as iam;
use google_cloud_iam_v2::client::Policies;
use google_cloud_identity_accesscontextmanager_v1::client::AccessContextManager;
use google_cloud_logging_v2::client::ConfigServiceV2;
use google_cloud_lro::Poller;
use google_cloud_orgpolicy_v2::client::OrgPolicy as OrgPolicyClient;
use google_cloud_policytroubleshooter_v1::client::IamChecker;
use google_cloud_resourcemanager_v3::client::TagBindings;
use google_cloud_resourcemanager_v3::client::{Folders, Organizations, Projects};
use google_cloud_resourcemanager_v3::model as rm;
use tokio::sync::OnceCell;

use crate::convert;
use crate::error::map_err;
use crate::identity;
use crate::limiter::Limiter;
use crate::retry;

/// Which organization's login.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Side {
    Source,
    Destination,
}

impl Side {
    pub fn other(self) -> Side {
        match self {
            Side::Source => Side::Destination,
            Side::Destination => Side::Source,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Side::Source => "source",
            Side::Destination => "destination",
        }
    }
}

impl std::str::FromStr for Side {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "source" => Ok(Side::Source),
            "destination" | "dest" => Ok(Side::Destination),
            other => Err(Error::invalid(format!(
                "expected source or destination, got {other:?}"
            ))),
        }
    }
}

/// One login's connection settings. `endpoint` overrides every service
/// endpoint (tests).
#[derive(Clone)]
pub struct SideConfig {
    pub credentials: Credentials,
    pub endpoint: Option<String>,
}

#[derive(Clone)]
pub struct Config {
    pub source: SideConfig,
    /// `None`: the same login is used for both organizations.
    pub destination: Option<SideConfig>,
    /// Which login calls `projects.move` (and `analyzeMove`).
    pub move_side: Side,
    pub concurrency: usize,
    /// Retry timing for the plain-HTTP Cloud Identity calls.
    pub identity_backoff: identity::Backoff,
}

impl Config {
    /// One login for everything.
    pub fn single(credentials: Credentials, concurrency: usize, endpoint: Option<String>) -> Self {
        Self {
            source: SideConfig {
                credentials,
                endpoint,
            },
            destination: None,
            move_side: Side::Source,
            concurrency,
            identity_backoff: Default::default(),
        }
    }
}

macro_rules! lazy_clients {
    ($($field:ident: $ty:ty),* $(,)?) => {
        #[derive(Default)]
        struct Clients { $($field: OnceCell<$ty>,)* }
    };
}

lazy_clients! {
    projects: Projects,
    folders: Folders,
    orgs: Organizations,
    asset: AssetService,
    org_policy: OrgPolicyClient,
    iam_admin: Iam,
    deny: Policies,
    checker: IamChecker,
    acm: AccessContextManager,
    firewall: FirewallPolicies,
    compute_projects: ComputeProjects,
    logging: ConfigServiceV2,
    tag_bindings: TagBindings,
}

/// Build one SDK client with our credentials, retry policy and optional endpoint.
macro_rules! build_client {
    ($cfg:expr, $ty:ty) => {{
        let mut b = <$ty>::builder()
            .with_credentials($cfg.credentials.clone())
            .with_retry_policy(retry::policy())
            .with_backoff_policy(retry::backoff());
        if let Some(e) = &$cfg.endpoint {
            b = b.with_endpoint(e.clone());
        }
        b.build()
            .await
            .map_err(|e| Error::internal(format!("cannot create {} client: {e}", stringify!($ty))))
    }};
}

/// Everything one side needs to make calls: its clients and credentials.
struct View<'a> {
    cfg: &'a SideConfig,
    clients: &'a Clients,
    limiter: &'a Limiter,
    http: &'a reqwest::Client,
    identity_backoff: identity::Backoff,
}

/// What a routed call is about, for remembering which side owns it.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
enum Key {
    Org(OrgId),
    Folder(FolderId),
    Project(ProjectId),
    Op(String),
    Group,
}

fn key_res(r: &Resource) -> Key {
    match r {
        Resource::Org(o) => Key::Org(o.clone()),
        Resource::Folder(f) => Key::Folder(f.clone()),
        Resource::Project(p) => Key::Project(p.clone()),
    }
}

fn key_parent(p: &Parent) -> Key {
    match p {
        Parent::Org(o) => Key::Org(o.clone()),
        Parent::Folder(f) => Key::Folder(f.clone()),
    }
}

fn key_role(name: &RoleName) -> Key {
    if let Some((org, _)) = name.org_custom() {
        Key::Org(org)
    } else if let Some(p) = name
        .as_str()
        .strip_prefix("projects/")
        .and_then(|r| r.split('/').next())
    {
        p.parse().map(Key::Project).unwrap_or(Key::Group)
    } else {
        Key::Group
    }
}

/// Errors that mean "this login can't see that resource", so try the other one.
const WRONG_SIDE: &[ErrorKind] = &[ErrorKind::PermissionDenied, ErrorKind::NotFound];
/// For calls where "not found" is a real answer (a group that doesn't exist).
const ONLY_DENIED: &[ErrorKind] = &[ErrorKind::PermissionDenied];

/// A long-running operation we started, so polling uses the same login.
struct OpInfo {
    side: Side,
    project: ProjectId,
    /// The side the project lands on, when known.
    target: Option<Side>,
}

struct Shared {
    cfg: Config,
    http: reqwest::Client,
    limiter: Limiter,
    clients: [Clients; 2],
    learned: Mutex<HashMap<Key, Side>>,
    ops: Mutex<HashMap<String, OpInfo>>,
}

#[derive(Clone)]
pub struct RealGcp {
    shared: Arc<Shared>,
}

impl RealGcp {
    pub fn new(cfg: Config) -> Self {
        let limiter = Limiter::new(cfg.concurrency);
        Self {
            shared: Arc::new(Shared {
                cfg,
                http: reqwest::Client::new(),
                limiter,
                clients: [Clients::default(), Clients::default()],
                learned: Mutex::new(HashMap::new()),
                ops: Mutex::new(HashMap::new()),
            }),
        }
    }

    pub fn limiter(&self) -> &Limiter {
        &self.shared.limiter
    }

    /// Whether the two organizations use different logins.
    pub fn is_split(&self) -> bool {
        self.shared.cfg.destination.is_some()
    }

    /// Tell the router which login owns a resource, so the first call goes to
    /// the right place. Wrong or missing hints are harmless: routing corrects itself.
    pub fn hint(&self, r: &Resource, side: Side) {
        self.learn(key_res(r), side);
    }

    pub fn hint_org(&self, org: &OrgId, side: Side) {
        self.learn(Key::Org(org.clone()), side);
    }

    fn mover(&self) -> Side {
        if self.is_split() {
            self.shared.cfg.move_side
        } else {
            Side::Source
        }
    }

    fn view(&self, side: Side) -> View<'_> {
        let sh = &*self.shared;
        let (cfg, idx) = match (&sh.cfg.destination, side) {
            (Some(d), Side::Destination) => (d, 1),
            _ => (&sh.cfg.source, 0),
        };
        View {
            cfg,
            clients: &sh.clients[idx],
            limiter: &sh.limiter,
            http: &sh.http,
            identity_backoff: sh.cfg.identity_backoff,
        }
    }

    fn known(&self, key: &Key) -> Option<Side> {
        self.shared.learned.lock().unwrap().get(key).copied()
    }

    fn learn(&self, key: Key, side: Side) {
        self.shared.learned.lock().unwrap().insert(key, side);
    }

    /// Run `f` as the login that owns `key`; if that login can't see it, try
    /// the other and remember which one worked.
    async fn routed<T, F, Fut>(&self, key: Key, fallback: &[ErrorKind], f: F) -> Result<T>
    where
        F: Fn(Side) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        if !self.is_split() {
            return f(Side::Source).await;
        }
        let owner = self.known(&key);
        let first = owner.unwrap_or(Side::Source);
        match f(first).await {
            Ok(v) => {
                self.learn(key, first);
                Ok(v)
            }
            Err(e1) if fallback.contains(&e1.kind) => {
                let second = first.other();
                match f(second).await {
                    Ok(v) => {
                        self.learn(key, second);
                        Ok(v)
                    }
                    Err(e2) => Err(combine(owner.is_some(), first, e1, second, e2)),
                }
            }
            Err(e) => Err(e),
        }
    }

    // ------------------------------------------------ hierarchy (routed)

    async fn folder_parent(&self, f: &FolderId) -> Result<Parent> {
        self.routed(Key::Folder(f.clone()), WRONG_SIDE, |s| async move {
            self.view(s).folder_parent(f).await
        })
        .await
    }

    async fn project_parent(&self, id: &ProjectId) -> Result<Parent> {
        self.routed(Key::Project(id.clone()), WRONG_SIDE, |s| async move {
            convert_parent(&self.view(s).sdk_project(id).await?)
        })
        .await
    }

    /// The resource followed by its ancestors up to the organization; each
    /// step is read with the login that owns that step.
    async fn chain(&self, r: &Resource) -> Result<Vec<Resource>> {
        let mut out = vec![r.clone()];
        let mut next = match r {
            Resource::Org(_) => return Ok(out),
            Resource::Folder(f) => self.folder_parent(f).await?,
            Resource::Project(p) => self.project_parent(p).await?,
        };
        loop {
            out.push(Resource::from_parent(&next));
            match next {
                Parent::Org(_) => return Ok(out),
                Parent::Folder(f) => next = self.folder_parent(&f).await?,
            }
        }
    }
}

/// Merge the two attempts' errors. When we knew the owner its error is the
/// real one; otherwise differing "can't see it" answers are reported as a
/// permission problem, since that is the one worth acting on.
fn combine(owner_known: bool, s1: Side, e1: Error, s2: Side, e2: Error) -> Error {
    let kind = if owner_known || e1.kind == e2.kind {
        e1.kind
    } else {
        ErrorKind::PermissionDenied
    };
    let mut out = Error::new(
        kind,
        format!(
            "{} (tried the {} login, then the {} login: {})",
            e1.message,
            s1.name(),
            s2.name(),
            e2.message
        ),
    );
    out.resource = e1.resource;
    out.hint = e1.hint.or(e2.hint);
    if kind == ErrorKind::PermissionDenied && out.hint.is_none() {
        out.hint = Some("neither login can reach it; check which login owns this resource and what it is allowed to do".into());
    }
    out
}

impl View<'_> {
    /// Like `get_policy` but a missing policy is an `Err(NotFound)`, so the
    /// router can tell "absent" from "this login can't see it".
    async fn get_policy_strict(&self, scope: &Scope, constraint: &str) -> Result<OrgPolicy> {
        let name = convert::policy_name(scope, constraint);
        let c = self.org_policy().await?;
        let p = self
            .limiter
            .run(async {
                c.get_policy()
                    .set_name(&name)
                    .send()
                    .await
                    .map_err(|e| map_err(e, &name))
            })
            .await?;
        Ok(convert::orgpolicy_from_sdk(constraint, p.spec))
    }

    async fn get_custom_role_strict(&self, name: &RoleName) -> Result<CustomRole> {
        let c = self.iam_admin().await?;
        let r = self
            .limiter
            .run(async {
                c.get_role()
                    .set_name(name.as_str())
                    .send()
                    .await
                    .map_err(|e| map_err(e, name))
            })
            .await?;
        Ok(convert::role_from_sdk(r))
    }

    async fn delete_policy_strict(&self, scope: &Scope, constraint: &str) -> Result<()> {
        let name = convert::policy_name(scope, constraint);
        let c = self.org_policy().await?;
        self.limiter
            .run(async {
                c.delete_policy()
                    .set_name(&name)
                    .send()
                    .await
                    .map_err(|e| map_err(e, &name))
            })
            .await
    }

    async fn projects(&self) -> Result<&Projects> {
        self.clients
            .projects
            .get_or_try_init(|| async { build_client!(self.cfg, Projects) })
            .await
    }
    async fn folders(&self) -> Result<&Folders> {
        self.clients
            .folders
            .get_or_try_init(|| async { build_client!(self.cfg, Folders) })
            .await
    }
    async fn orgs(&self) -> Result<&Organizations> {
        self.clients
            .orgs
            .get_or_try_init(|| async { build_client!(self.cfg, Organizations) })
            .await
    }

    async fn asset(&self) -> Result<&AssetService> {
        self.clients
            .asset
            .get_or_try_init(|| async { build_client!(self.cfg, AssetService) })
            .await
    }
    async fn org_policy(&self) -> Result<&OrgPolicyClient> {
        self.clients
            .org_policy
            .get_or_try_init(|| async { build_client!(self.cfg, OrgPolicyClient) })
            .await
    }
    async fn iam_admin(&self) -> Result<&Iam> {
        self.clients
            .iam_admin
            .get_or_try_init(|| async { build_client!(self.cfg, Iam) })
            .await
    }

    async fn deny(&self) -> Result<&Policies> {
        self.clients
            .deny
            .get_or_try_init(|| async { build_client!(self.cfg, Policies) })
            .await
    }
    async fn checker(&self) -> Result<&IamChecker> {
        self.clients
            .checker
            .get_or_try_init(|| async { build_client!(self.cfg, IamChecker) })
            .await
    }
    async fn acm(&self) -> Result<&AccessContextManager> {
        self.clients
            .acm
            .get_or_try_init(|| async { build_client!(self.cfg, AccessContextManager) })
            .await
    }
    async fn firewall(&self) -> Result<&FirewallPolicies> {
        self.clients
            .firewall
            .get_or_try_init(|| async { build_client!(self.cfg, FirewallPolicies) })
            .await
    }
    async fn compute_projects(&self) -> Result<&ComputeProjects> {
        self.clients
            .compute_projects
            .get_or_try_init(|| async { build_client!(self.cfg, ComputeProjects) })
            .await
    }

    async fn logging(&self) -> Result<&ConfigServiceV2> {
        self.clients
            .logging
            .get_or_try_init(|| async { build_client!(self.cfg, ConfigServiceV2) })
            .await
    }
    async fn tag_bindings(&self) -> Result<&TagBindings> {
        self.clients
            .tag_bindings
            .get_or_try_init(|| async { build_client!(self.cfg, TagBindings) })
            .await
    }

    // ---------------------------------------------------------- hierarchy

    async fn sdk_project(&self, id: &ProjectId) -> Result<rm::Project> {
        let name = format!("projects/{id}");
        let c = self.projects().await?;
        self.limiter
            .run(async {
                c.get_project()
                    .set_name(&name)
                    .send()
                    .await
                    .map_err(|e| map_err(e, &name))
            })
            .await
    }

    async fn folder_parent(&self, f: &FolderId) -> Result<Parent> {
        let name = format!("folders/{f}");
        let c = self.folders().await?;
        let folder = self
            .limiter
            .run(async {
                c.get_folder()
                    .set_name(&name)
                    .send()
                    .await
                    .map_err(|e| map_err(e, &name))
            })
            .await?;
        folder.parent.parse()
    }

    /// The resource followed by its ancestors up to the organization.
    async fn chain(&self, r: &Resource) -> Result<Vec<Resource>> {
        let mut out = vec![r.clone()];
        let mut next = match r {
            Resource::Org(_) => return Ok(out),
            Resource::Folder(f) => self.folder_parent(f).await?,
            Resource::Project(p) => convert_parent(&self.sdk_project(p).await?)?,
        };
        loop {
            out.push(Resource::from_parent(&next));
            match next {
                Parent::Org(_) => return Ok(out),
                Parent::Folder(f) => next = self.folder_parent(&f).await?,
            }
        }
    }

    // ---------------------------------------------------------------- IAM

    async fn sdk_get_iam(&self, r: &Resource) -> Result<iam::Policy> {
        let name = r.to_string();
        let req = iam::GetIamPolicyRequest::new()
            .set_resource(&name)
            .set_options(iam::GetPolicyOptions::new().set_requested_policy_version(3));
        self.limiter
            .run(async {
                match r {
                    Resource::Project(_) => {
                        self.projects()
                            .await?
                            .get_iam_policy()
                            .with_request(req)
                            .send()
                            .await
                    }
                    Resource::Folder(_) => {
                        self.folders()
                            .await?
                            .get_iam_policy()
                            .with_request(req)
                            .send()
                            .await
                    }
                    Resource::Org(_) => {
                        self.orgs()
                            .await?
                            .get_iam_policy()
                            .with_request(req)
                            .send()
                            .await
                    }
                }
                .map_err(|e| map_err(e, &name))
            })
            .await
    }
}

fn convert_parent(p: &rm::Project) -> Result<Parent> {
    p.parent.parse()
}

fn convert_project(p: rm::Project) -> Result<Project> {
    let number = p
        .name
        .strip_prefix("projects/")
        .ok_or_else(|| Error::internal(format!("unexpected project name {:?}", p.name)))?
        .parse()?;
    use rm::project::State;
    Ok(Project {
        id: p.project_id.parse()?,
        number,
        parent: p.parent.parse()?,
        state: match p.state {
            State::Active => LifecycleState::Active,
            State::DeleteRequested => LifecycleState::DeleteRequested,
            _ => LifecycleState::Unknown,
        },
        labels: p.labels.into_iter().collect::<BTreeMap<_, _>>(),
        etag: p.etag,
    })
}

#[async_trait]
impl Gcp for View<'_> {
    async fn list_projects(&self, parent: &Parent) -> Result<Vec<Project>> {
        let mut out = vec![];
        let mut stack = vec![parent.clone()];
        while let Some(p) = stack.pop() {
            let name = p.to_string();
            let c = self.projects().await?;
            let mut it = c.list_projects().set_parent(&name).by_item();
            while let Some(item) = self
                .limiter
                .run(async { it.next().await.transpose().map_err(|e| map_err(e, &name)) })
                .await?
            {
                out.push(convert_project(item)?);
            }
            let f = self.folders().await?;
            let mut it = f.list_folders().set_parent(&name).by_item();
            while let Some(item) = self
                .limiter
                .run(async { it.next().await.transpose().map_err(|e| map_err(e, &name)) })
                .await?
            {
                stack.push(item.name.parse()?);
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }

    async fn get_project(&self, id: &ProjectId) -> Result<Project> {
        convert_project(self.sdk_project(id).await?)
    }

    async fn get_ancestry(&self, id: &ProjectId) -> Result<Vec<Parent>> {
        let chain = self.chain(&Resource::Project(id.clone())).await?;
        chain
            .iter()
            .skip(1)
            .map(|r| r.to_string().parse())
            .collect()
    }

    async fn get_folder_ancestry(&self, folder: &FolderId) -> Result<Vec<Parent>> {
        let chain = self.chain(&Resource::Folder(folder.clone())).await?;
        chain
            .iter()
            .skip(1)
            .map(|r| r.to_string().parse())
            .collect()
    }

    async fn move_project(&self, id: &ProjectId, dest: &Parent) -> Result<Operation> {
        let name = format!("projects/{id}");
        let c = self.projects().await?;
        let op = self
            .limiter
            .run(async {
                c.move_project()
                    .set_name(&name)
                    .set_destination_parent(dest.to_string())
                    .send()
                    .await
                    .map_err(|e| map_err(e, &name))
            })
            .await?;
        Ok(Operation { name: op.name })
    }

    async fn poll_operation(&self, op: &Operation) -> Result<OperationStatus> {
        let c = self.projects().await?;
        let got = self
            .limiter
            .run(async {
                c.get_operation()
                    .set_name(&op.name)
                    .send()
                    .await
                    .map_err(|e| map_err(e, &op.name))
            })
            .await?;
        use google_cloud_longrunning::model::operation::Result as R;
        Ok(match (got.done, got.result) {
            (false, _) => OperationStatus::Running,
            (true, Some(R::Error(status))) => OperationStatus::Failed {
                code: status.code,
                message: status.message,
            },
            (true, _) => OperationStatus::Done,
        })
    }

    async fn set_project_labels(
        &self,
        id: &ProjectId,
        labels: BTreeMap<String, String>,
    ) -> Result<Project> {
        let label = format!("projects/{id}");
        let current = self.sdk_project(id).await?;
        // Update by the canonical numeric name returned by the API.
        let mut project = rm::Project::new()
            .set_name(&current.name)
            .set_etag(current.etag);
        project.labels = labels.into_iter().collect();
        let c = self.projects().await?;
        let updated = self
            .limiter
            .run(async {
                c.update_project()
                    .set_project(project)
                    .set_update_mask(google_cloud_wkt::FieldMask::default().set_paths(["labels"]))
                    .poller()
                    .until_done()
                    .await
                    .map_err(|e| map_err(e, &label))
            })
            .await?;
        convert_project(updated)
    }

    async fn analyze_move(&self, id: &ProjectId, dest: &Parent) -> Result<MoveAnalysis> {
        use google_cloud_asset_v1::model::analyze_move_request::AnalysisView;
        use google_cloud_asset_v1::model::move_analysis::Result as R;
        let name = format!("projects/{id}");
        let c = self.asset().await?;
        let resp = self
            .limiter
            .run(async {
                c.analyze_move()
                    .set_resource(&name)
                    .set_destination_parent(dest.to_string())
                    .set_view(AnalysisView::Full)
                    .send()
                    .await
                    .map_err(|e| map_err(e, &name))
            })
            .await?;
        let mut items = vec![];
        for a in resp.move_analysis {
            match a.result {
                Some(R::Analysis(r)) => {
                    items.extend(r.blockers.into_iter().map(|i| AnalysisItem {
                        level: AnalysisLevel::Blocker,
                        message: i.detail,
                    }));
                    items.extend(r.warnings.into_iter().map(|i| AnalysisItem {
                        level: AnalysisLevel::Warning,
                        message: i.detail,
                    }));
                }
                Some(R::Error(status)) => items.push(AnalysisItem {
                    level: AnalysisLevel::Blocker,
                    message: format!("{}: analysis failed: {}", a.display_name, status.message),
                }),
                _ => {}
            }
        }
        Ok(MoveAnalysis { items })
    }

    async fn get_iam(&self, r: &Resource) -> Result<IamPolicy> {
        Ok(convert::policy_from_sdk(self.sdk_get_iam(r).await?))
    }

    async fn set_iam(&self, r: &Resource, p: IamPolicy) -> Result<IamPolicy> {
        let name = r.to_string();
        let policy = convert::policy_to_sdk(&p, None);
        let req = iam::SetIamPolicyRequest::new()
            .set_resource(&name)
            .set_policy(policy);
        let stored = self
            .limiter
            .run(async {
                match r {
                    Resource::Project(_) => {
                        self.projects()
                            .await?
                            .set_iam_policy()
                            .with_request(req)
                            .send()
                            .await
                    }
                    Resource::Folder(_) => {
                        self.folders()
                            .await?
                            .set_iam_policy()
                            .with_request(req)
                            .send()
                            .await
                    }
                    Resource::Org(_) => {
                        self.orgs()
                            .await?
                            .set_iam_policy()
                            .with_request(req)
                            .send()
                            .await
                    }
                }
                .map_err(|e| map_err(e, &name))
            })
            .await?;
        Ok(convert::policy_from_sdk(stored))
    }

    async fn get_effective_iam(&self, r: &Resource) -> Result<EffectiveIam> {
        let mut grants = vec![];
        for res in self.chain(r).await? {
            for grant in self.get_iam(&res).await?.flatten() {
                grants.push(EffectiveGrant {
                    grant,
                    from: res.clone(),
                });
            }
        }
        Ok(EffectiveIam { grants })
    }

    async fn test_permissions(&self, r: &Resource, perms: &[String]) -> Result<Vec<String>> {
        let name = r.to_string();
        let req = iam::TestIamPermissionsRequest::new()
            .set_resource(&name)
            .set_permissions(perms.iter().cloned());
        let resp = self
            .limiter
            .run(async {
                match r {
                    Resource::Project(_) => {
                        self.projects()
                            .await?
                            .test_iam_permissions()
                            .with_request(req)
                            .send()
                            .await
                    }
                    Resource::Folder(_) => {
                        self.folders()
                            .await?
                            .test_iam_permissions()
                            .with_request(req)
                            .send()
                            .await
                    }
                    Resource::Org(_) => {
                        self.orgs()
                            .await?
                            .test_iam_permissions()
                            .with_request(req)
                            .send()
                            .await
                    }
                }
                .map_err(|e| map_err(e, &name))
            })
            .await?;
        Ok(resp.permissions)
    }

    async fn test_move_permissions(&self, r: &Resource, perms: &[String]) -> Result<Vec<String>> {
        // Within one side's login there is a single caller.
        self.test_permissions(r, perms).await
    }

    async fn troubleshoot_access(
        &self,
        r: &Resource,
        principal: &str,
        perms: &[String],
    ) -> Result<Vec<AccessVerdict>> {
        use google_cloud_policytroubleshooter_v1::model::{AccessState, AccessTuple};
        let full = format!("//cloudresourcemanager.googleapis.com/{r}");
        let c = self.checker().await?;
        let mut out = vec![];
        for perm in perms {
            let tuple = AccessTuple::new()
                .set_principal(principal)
                .set_full_resource_name(&full)
                .set_permission(perm);
            let resp = self
                .limiter
                .run(async {
                    c.troubleshoot_iam_policy()
                        .set_access_tuple(tuple)
                        .send()
                        .await
                        .map_err(|e| map_err(e, &full))
                })
                .await?;
            out.push(AccessVerdict {
                permission: perm.clone(),
                granted: resp.access == AccessState::Granted,
            });
        }
        Ok(out)
    }
    async fn list_custom_roles(&self, org: &OrgId) -> Result<Vec<CustomRole>> {
        use google_cloud_iam_admin_v1::model::RoleView;
        let parent = format!("organizations/{org}");
        let c = self.iam_admin().await?;
        let mut it = c
            .list_roles()
            .set_parent(&parent)
            .set_view(RoleView::Full)
            .by_item();
        let mut out = vec![];
        while let Some(r) = self
            .limiter
            .run(async { it.next().await.transpose().map_err(|e| map_err(e, &parent)) })
            .await?
        {
            out.push(convert::role_from_sdk(r));
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
    async fn get_custom_role(&self, name: &RoleName) -> Result<Option<CustomRole>> {
        match self.get_custom_role_strict(name).await {
            Ok(r) => Ok(Some(r)),
            Err(e) if e.kind == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    async fn create_custom_role(&self, org: &OrgId, role: CustomRole) -> Result<CustomRole> {
        use google_cloud_iam_admin_v1::model::Role;
        let (role_org, short) = role.name.org_custom().ok_or_else(|| {
            Error::invalid(format!("{} is not an organization custom role", role.name))
        })?;
        if &role_org != org {
            return Err(Error::invalid(format!(
                "role {} does not belong to organization {org}",
                role.name
            )));
        }
        let parent = format!("organizations/{org}");
        let sdk_role = Role::new()
            .set_title(role.title.clone())
            .set_description(role.description.clone())
            .set_included_permissions(role.permissions.iter().cloned())
            .set_stage(convert::stage_to_sdk(role.stage));
        let c = self.iam_admin().await?;
        let res = self
            .limiter
            .run(async {
                c.create_role()
                    .set_parent(&parent)
                    .set_role_id(short)
                    .set_role(sdk_role)
                    .send()
                    .await
                    .map_err(|e| map_err(e, &role.name))
            })
            .await;
        match res {
            Ok(r) => Ok(convert::role_from_sdk(r)),
            // Already there: fine if identical, otherwise a real conflict.
            Err(e) if e.kind == ErrorKind::Conflict => {
                match self.get_custom_role(&role.name).await? {
                    Some(existing) if existing == role => Ok(existing),
                    _ => Err(Error::new(
                        ErrorKind::Conflict,
                        format!(
                            "role {} already exists with a different definition",
                            role.name
                        ),
                    )
                    .with_resource(&role.name)),
                }
            }
            Err(e) => Err(e),
        }
    }
    async fn delete_custom_role(&self, name: &RoleName) -> Result<()> {
        let c = self.iam_admin().await?;
        self.limiter
            .run(async {
                c.delete_role()
                    .set_name(name.as_str())
                    .send()
                    .await
                    .map_err(|e| map_err(e, name))
                    .map(|_| ())
            })
            .await
    }
    async fn list_deny_policies(&self, r: &Resource) -> Result<Vec<DenyPolicy>> {
        use google_cloud_iam_v2::model::policy_rule::Kind;
        // Attachment point is the URL-encoded full resource name.
        let attachment = format!(
            "cloudresourcemanager.googleapis.com%2F{}",
            r.to_string().replace('/', "%2F")
        );
        let parent = format!("policies/{attachment}/denypolicies");
        let c = self.deny().await?;
        let mut it = c.list_policies().set_parent(&parent).by_item();
        let mut out = vec![];
        while let Some(p) = self
            .limiter
            .run(async { it.next().await.transpose().map_err(|e| map_err(e, r)) })
            .await?
        {
            let rules = p
                .rules
                .into_iter()
                .filter_map(|rule| match rule.kind {
                    Some(Kind::DenyRule(d)) => Some(DenyRule {
                        denied_principals: d.denied_principals.into_iter().collect(),
                        denied_permissions: d.denied_permissions.into_iter().collect(),
                        exception_principals: d.exception_principals.into_iter().collect(),
                        has_condition: d.denial_condition.is_some(),
                    }),
                    _ => None,
                })
                .collect();
            out.push(DenyPolicy {
                name: p.name,
                attached_to: r.clone(),
                rules,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
    async fn get_policy(&self, scope: &Scope, constraint: &str) -> Result<Option<OrgPolicy>> {
        match self.get_policy_strict(scope, constraint).await {
            Ok(p) => Ok(Some(p)),
            Err(e) if e.kind == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
    async fn get_effective_policy(&self, scope: &Scope, constraint: &str) -> Result<OrgPolicy> {
        let name = convert::policy_name(scope, constraint);
        let c = self.org_policy().await?;
        let p = self
            .limiter
            .run(async {
                c.get_effective_policy()
                    .set_name(&name)
                    .send()
                    .await
                    .map_err(|e| map_err(e, &name))
            })
            .await?;
        Ok(convert::orgpolicy_from_sdk(constraint, p.spec))
    }
    async fn list_policies(&self, scope: &Scope) -> Result<Vec<OrgPolicy>> {
        let parent = scope.to_string();
        let c = self.org_policy().await?;
        let mut it = c.list_policies().set_parent(&parent).by_item();
        let mut out = vec![];
        while let Some(p) = self
            .limiter
            .run(async { it.next().await.transpose().map_err(|e| map_err(e, &parent)) })
            .await?
        {
            let short = p
                .name
                .rsplit("/policies/")
                .next()
                .unwrap_or(&p.name)
                .to_string();
            out.push(convert::orgpolicy_from_sdk(
                &format!("constraints/{short}"),
                p.spec,
            ));
        }
        out.sort_by(|a, b| a.constraint.cmp(&b.constraint));
        Ok(out)
    }
    async fn set_policy(&self, scope: &Scope, policy: OrgPolicy) -> Result<()> {
        use google_cloud_wkt::FieldMask;
        let name = convert::policy_name(scope, &policy.constraint);
        let parent = scope.to_string();
        let exists = self.get_policy(scope, &policy.constraint).await?.is_some();
        let sdk = convert::orgpolicy_to_sdk(&name, &policy);
        let c = self.org_policy().await?;
        self.limiter
            .run(async {
                if exists {
                    c.update_policy()
                        .set_policy(sdk)
                        .set_update_mask(FieldMask::default().set_paths(["policy.spec"]))
                        .send()
                        .await
                        .map(|_| ())
                } else {
                    c.create_policy()
                        .set_parent(&parent)
                        .set_policy(sdk)
                        .send()
                        .await
                        .map(|_| ())
                }
                .map_err(|e| map_err(e, &name))
            })
            .await
    }
    async fn delete_policy(&self, scope: &Scope, constraint: &str) -> Result<()> {
        match self.delete_policy_strict(scope, constraint).await {
            Err(e) if e.kind == ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }
    async fn list_firewall_policies(&self, r: &Resource) -> Result<Vec<FirewallPolicy>> {
        let target = r.to_string();
        let c = self.firewall().await?;
        let resp = self
            .limiter
            .run(async {
                c.list_associations()
                    .set_target_resource(&target)
                    .send()
                    .await
                    .map_err(|e| map_err(e, &target))
            })
            .await?;
        let mut out: Vec<FirewallPolicy> = resp
            .associations
            .into_iter()
            .map(|a| FirewallPolicy {
                name: a
                    .short_name
                    .or(a.firewall_policy_id)
                    .or(a.name)
                    .unwrap_or_default(),
                attached_to: r.clone(),
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
    async fn shared_vpc_relationships(&self, project: &ProjectId) -> Result<Vec<SharedVpcLink>> {
        let c = self.compute_projects().await?;
        let host = self
            .limiter
            .run(async {
                c.get_xpn_host()
                    .set_project(project.as_str())
                    .send()
                    .await
                    .map_err(|e| map_err(e, project))
            })
            .await;
        match host {
            Ok(h) => {
                // A service project: link to its host.
                if let Some(name) = h.name.filter(|n| !n.is_empty()) {
                    return Ok(vec![SharedVpcLink {
                        host: name.parse()?,
                        service: project.clone(),
                    }]);
                }
            }
            Err(e) if e.kind == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        // Possibly a host: list its service projects.
        let mut it = c
            .get_xpn_resources()
            .set_project(project.as_str())
            .by_item();
        let mut links = vec![];
        let res = loop {
            match self
                .limiter
                .run(async { it.next().await.transpose().map_err(|e| map_err(e, project)) })
                .await
            {
                Ok(Some(r)) => {
                    if let Some(id) = r.id {
                        links.push(SharedVpcLink {
                            host: project.clone(),
                            service: id.parse()?,
                        });
                    }
                }
                Ok(None) => break Ok(()),
                Err(e) => break Err(e),
            }
        };
        match res {
            Ok(()) => {
                links.sort_by(|a, b| a.service.cmp(&b.service));
                Ok(links)
            }
            Err(e) if e.kind == ErrorKind::NotFound => Ok(vec![]),
            Err(e) => Err(e),
        }
    }
    async fn group_exists(&self, email: &str) -> Result<bool> {
        let base = self
            .cfg
            .endpoint
            .as_deref()
            .unwrap_or(identity::DEFAULT_BASE);
        self.limiter
            .run(identity::group_exists(
                self.http,
                &self.cfg.credentials,
                base,
                self.identity_backoff,
                email,
            ))
            .await
    }
    async fn list_vpc_sc_perimeters(&self, org: &OrgId) -> Result<Vec<Perimeter>> {
        let parent = format!("organizations/{org}");
        let c = self.acm().await?;
        let mut policies = vec![];
        let mut it = c.list_access_policies().set_parent(&parent).by_item();
        while let Some(p) = self
            .limiter
            .run(async { it.next().await.transpose().map_err(|e| map_err(e, &parent)) })
            .await?
        {
            policies.push(p.name);
        }
        let mut out = vec![];
        for policy in policies {
            let mut it = c.list_service_perimeters().set_parent(&policy).by_item();
            while let Some(p) = self
                .limiter
                .run(async { it.next().await.transpose().map_err(|e| map_err(e, &policy)) })
                .await?
            {
                let mut projects: Vec<ProjectNumber> = p
                    .status
                    .iter()
                    .chain(p.spec.iter())
                    .flat_map(|cfg| cfg.resources.iter())
                    .filter_map(|r| r.strip_prefix("projects/")?.parse().ok())
                    .collect();
                projects.sort();
                projects.dedup();
                out.push(Perimeter {
                    name: p.name,
                    projects,
                });
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
    async fn list_org_scoped(
        &self,
        org: &OrgId,
        project: &ProjectId,
    ) -> Result<Vec<OrgScopedItem>> {
        let mut out = vec![];

        // Organization log sinks that also capture child resources' logs.
        let parent = format!("organizations/{org}");
        let c = self.logging().await?;
        let mut it = c.list_sinks().set_parent(&parent).by_item();
        while let Some(sink) = self
            .limiter
            .run(async { it.next().await.transpose().map_err(|e| map_err(e, &parent)) })
            .await?
        {
            if sink.include_children && !sink.disabled {
                out.push(OrgScopedItem {
                    kind: "log_sink".into(),
                    name: sink.name,
                    detail: format!("destination={}; filter={:?}", sink.destination, sink.filter),
                });
            }
        }

        // Tags bound to the project: tag keys and values belong to an organization.
        let number = self.sdk_project(project).await?.name;
        let number = number
            .strip_prefix("projects/")
            .unwrap_or(&number)
            .to_string();
        let tag_parent = format!("//cloudresourcemanager.googleapis.com/projects/{number}");
        let t = self.tag_bindings().await?;
        let mut it = t.list_tag_bindings().set_parent(&tag_parent).by_item();
        while let Some(b) = self
            .limiter
            .run(async {
                it.next()
                    .await
                    .transpose()
                    .map_err(|e| map_err(e, &tag_parent))
            })
            .await?
        {
            out.push(OrgScopedItem {
                kind: "tag_binding".into(),
                name: b.tag_value,
                detail: b.tag_value_namespaced_name,
            });
        }

        // Organization-level asset feeds.
        let a = self.asset().await?;
        let feeds = self
            .limiter
            .run(async {
                a.list_feeds()
                    .set_parent(&parent)
                    .send()
                    .await
                    .map_err(|e| map_err(e, &parent))
            })
            .await?;
        for f in feeds.feeds {
            out.push(OrgScopedItem {
                kind: "asset_feed".into(),
                name: f.name,
                detail: format!("assetNames={:?}", f.asset_names),
            });
        }
        out.sort_by(|a, b| (&a.kind, &a.name).cmp(&(&b.kind, &b.name)));
        Ok(out)
    }
}

/// The public `Gcp`: every call goes to the login that owns the resource.
#[async_trait]
impl Gcp for RealGcp {
    async fn list_projects(&self, parent: &Parent) -> Result<Vec<Project>> {
        self.routed(key_parent(parent), WRONG_SIDE, |s| async move {
            self.view(s).list_projects(parent).await
        })
        .await
    }

    async fn get_project(&self, id: &ProjectId) -> Result<Project> {
        self.routed(Key::Project(id.clone()), WRONG_SIDE, |s| async move {
            self.view(s).get_project(id).await
        })
        .await
    }

    async fn get_ancestry(&self, id: &ProjectId) -> Result<Vec<Parent>> {
        let chain = self.chain(&Resource::Project(id.clone())).await?;
        chain
            .iter()
            .skip(1)
            .map(|r| r.to_string().parse())
            .collect()
    }

    async fn get_folder_ancestry(&self, folder: &FolderId) -> Result<Vec<Parent>> {
        let chain = self.chain(&Resource::Folder(folder.clone())).await?;
        chain
            .iter()
            .skip(1)
            .map(|r| r.to_string().parse())
            .collect()
    }

    async fn move_project(&self, id: &ProjectId, dest: &Parent) -> Result<Operation> {
        let side = self.mover();
        let op = self.view(side).move_project(id, dest).await?;
        self.shared.ops.lock().unwrap().insert(
            op.name.clone(),
            OpInfo {
                side,
                project: id.clone(),
                target: self.known(&key_parent(dest)),
            },
        );
        Ok(op)
    }

    async fn poll_operation(&self, op: &Operation) -> Result<OperationStatus> {
        let started_by = self
            .shared
            .ops
            .lock()
            .unwrap()
            .get(&op.name)
            .map(|i| i.side);
        let status = match started_by {
            Some(side) => self.view(side).poll_operation(op).await?,
            // Started by an earlier process: whichever login can see it.
            None => {
                self.routed(Key::Op(op.name.clone()), WRONG_SIDE, |s| async move {
                    self.view(s).poll_operation(op).await
                })
                .await?
            }
        };
        if status == OperationStatus::Done {
            if let Some(info) = self.shared.ops.lock().unwrap().remove(&op.name) {
                // The project now belongs to the side it moved to.
                if let Some(target) = info.target {
                    self.learn(Key::Project(info.project), target);
                }
            }
        } else if matches!(status, OperationStatus::Failed { .. }) {
            self.shared.ops.lock().unwrap().remove(&op.name);
        }
        Ok(status)
    }

    async fn set_project_labels(
        &self,
        id: &ProjectId,
        labels: BTreeMap<String, String>,
    ) -> Result<Project> {
        self.routed(Key::Project(id.clone()), WRONG_SIDE, |s| {
            let labels = labels.clone();
            async move { self.view(s).set_project_labels(id, labels).await }
        })
        .await
    }

    async fn analyze_move(&self, id: &ProjectId, dest: &Parent) -> Result<MoveAnalysis> {
        // Answers "would this move work?", so ask as the identity that will move it.
        self.view(self.mover()).analyze_move(id, dest).await
    }

    async fn get_iam(&self, r: &Resource) -> Result<IamPolicy> {
        self.routed(key_res(r), WRONG_SIDE, |s| async move {
            self.view(s).get_iam(r).await
        })
        .await
    }

    async fn set_iam(&self, r: &Resource, p: IamPolicy) -> Result<IamPolicy> {
        self.routed(key_res(r), WRONG_SIDE, |s| {
            let p = p.clone();
            async move { self.view(s).set_iam(r, p).await }
        })
        .await
    }

    async fn get_effective_iam(&self, r: &Resource) -> Result<EffectiveIam> {
        let mut grants = vec![];
        for res in self.chain(r).await? {
            for grant in self.get_iam(&res).await?.flatten() {
                grants.push(EffectiveGrant {
                    grant,
                    from: res.clone(),
                });
            }
        }
        Ok(EffectiveIam { grants })
    }

    async fn test_permissions(&self, r: &Resource, perms: &[String]) -> Result<Vec<String>> {
        self.routed(key_res(r), WRONG_SIDE, |s| async move {
            self.view(s).test_permissions(r, perms).await
        })
        .await
    }

    async fn test_move_permissions(&self, r: &Resource, perms: &[String]) -> Result<Vec<String>> {
        self.view(self.mover()).test_permissions(r, perms).await
    }

    async fn troubleshoot_access(
        &self,
        r: &Resource,
        principal: &str,
        perms: &[String],
    ) -> Result<Vec<AccessVerdict>> {
        self.routed(key_res(r), WRONG_SIDE, |s| async move {
            self.view(s).troubleshoot_access(r, principal, perms).await
        })
        .await
    }

    async fn list_custom_roles(&self, org: &OrgId) -> Result<Vec<CustomRole>> {
        self.routed(Key::Org(org.clone()), WRONG_SIDE, |s| async move {
            self.view(s).list_custom_roles(org).await
        })
        .await
    }

    async fn get_custom_role(&self, name: &RoleName) -> Result<Option<CustomRole>> {
        let res = self
            .routed(key_role(name), WRONG_SIDE, |s| async move {
                self.view(s).get_custom_role_strict(name).await
            })
            .await;
        match res {
            Ok(r) => Ok(Some(r)),
            Err(e) if e.kind == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn create_custom_role(&self, org: &OrgId, role: CustomRole) -> Result<CustomRole> {
        self.routed(Key::Org(org.clone()), ONLY_DENIED, |s| {
            let role = role.clone();
            async move { self.view(s).create_custom_role(org, role).await }
        })
        .await
    }

    async fn delete_custom_role(&self, name: &RoleName) -> Result<()> {
        self.routed(key_role(name), WRONG_SIDE, |s| async move {
            self.view(s).delete_custom_role(name).await
        })
        .await
    }

    async fn list_deny_policies(&self, r: &Resource) -> Result<Vec<DenyPolicy>> {
        self.routed(key_res(r), WRONG_SIDE, |s| async move {
            self.view(s).list_deny_policies(r).await
        })
        .await
    }

    async fn get_policy(&self, scope: &Scope, constraint: &str) -> Result<Option<OrgPolicy>> {
        let res = self
            .routed(key_res(scope), WRONG_SIDE, |s| async move {
                self.view(s).get_policy_strict(scope, constraint).await
            })
            .await;
        match res {
            Ok(p) => Ok(Some(p)),
            Err(e) if e.kind == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn get_effective_policy(&self, scope: &Scope, constraint: &str) -> Result<OrgPolicy> {
        self.routed(key_res(scope), WRONG_SIDE, |s| async move {
            self.view(s).get_effective_policy(scope, constraint).await
        })
        .await
    }

    async fn list_policies(&self, scope: &Scope) -> Result<Vec<OrgPolicy>> {
        self.routed(key_res(scope), WRONG_SIDE, |s| async move {
            self.view(s).list_policies(scope).await
        })
        .await
    }

    async fn set_policy(&self, scope: &Scope, policy: OrgPolicy) -> Result<()> {
        self.routed(key_res(scope), WRONG_SIDE, |s| {
            let policy = policy.clone();
            async move { self.view(s).set_policy(scope, policy).await }
        })
        .await
    }

    async fn delete_policy(&self, scope: &Scope, constraint: &str) -> Result<()> {
        let res = self
            .routed(key_res(scope), WRONG_SIDE, |s| async move {
                self.view(s).delete_policy_strict(scope, constraint).await
            })
            .await;
        match res {
            Err(e) if e.kind == ErrorKind::NotFound => Ok(()),
            other => other,
        }
    }

    async fn list_firewall_policies(&self, r: &Resource) -> Result<Vec<FirewallPolicy>> {
        self.routed(key_res(r), WRONG_SIDE, |s| async move {
            self.view(s).list_firewall_policies(r).await
        })
        .await
    }

    async fn shared_vpc_relationships(&self, project: &ProjectId) -> Result<Vec<SharedVpcLink>> {
        self.routed(Key::Project(project.clone()), WRONG_SIDE, |s| async move {
            self.view(s).shared_vpc_relationships(project).await
        })
        .await
    }

    async fn group_exists(&self, email: &str) -> Result<bool> {
        self.routed(Key::Group, ONLY_DENIED, |s| async move {
            self.view(s).group_exists(email).await
        })
        .await
    }

    async fn list_vpc_sc_perimeters(&self, org: &OrgId) -> Result<Vec<Perimeter>> {
        self.routed(Key::Org(org.clone()), WRONG_SIDE, |s| async move {
            self.view(s).list_vpc_sc_perimeters(org).await
        })
        .await
    }

    async fn list_org_scoped(
        &self,
        org: &OrgId,
        project: &ProjectId,
    ) -> Result<Vec<OrgScopedItem>> {
        self.routed(Key::Org(org.clone()), WRONG_SIDE, |s| async move {
            self.view(s).list_org_scoped(org, project).await
        })
        .await
    }
}
