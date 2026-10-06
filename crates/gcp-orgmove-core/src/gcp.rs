//! The `Gcp` trait: everything the tool needs from Google Cloud.
//!
//! Contract for implementors:
//! * Pagination is handled internally; callers receive complete lists.
//! * Transient failures (429, 5xx) are retried inside the implementation;
//!   only exhausted retries surface as [`ErrorKind::QuotaExceeded`]/[`ErrorKind::Internal`].
//! * `set_iam` and `set_policy` are etag-checked and surface a stale etag as
//!   [`ErrorKind::Conflict`]; callers own read-modify-write retry.
//! * Read methods are idempotent. `move_project`, `set_iam`, `set_policy`,
//!   `create_custom_role`, `delete_custom_role` and `set_project_labels` mutate.
//!
//! [`ErrorKind::QuotaExceeded`]: crate::ErrorKind::QuotaExceeded
//! [`ErrorKind::Internal`]: crate::ErrorKind::Internal
//! [`ErrorKind::Conflict`]: crate::ErrorKind::Conflict

use std::collections::BTreeMap;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::ids::*;
use crate::model::*;

/// An org-scoped resource relevant to a project move (log sink, tag, ...).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgScopedItem {
    /// e.g. `log_sink`, `tag_binding`, `essential_contact`, `billing_account`, `asset_feed`.
    pub kind: String,
    pub name: String,
    pub detail: String,
}

/// A VPC Service Controls perimeter and the projects it contains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Perimeter {
    pub name: String,
    pub projects: Vec<ProjectNumber>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessVerdict {
    pub permission: String,
    pub granted: bool,
}

#[async_trait]
pub trait Gcp: Send + Sync {
    // ---- Resource Manager
    /// All ACTIVE and non-active projects directly or transitively under `parent`.
    async fn list_projects(&self, parent: &Parent) -> Result<Vec<Project>>;
    async fn get_project(&self, id: &ProjectId) -> Result<Project>;
    /// Ancestors from the immediate parent up to the organization.
    async fn get_ancestry(&self, id: &ProjectId) -> Result<Vec<Parent>>;
    /// Ancestry of a folder, immediate parent first, ending at the organization.
    async fn get_folder_ancestry(&self, folder: &FolderId) -> Result<Vec<Parent>>;
    /// Mutating. Returns a long-running operation to poll.
    async fn move_project(&self, id: &ProjectId, dest: &Parent) -> Result<Operation>;
    async fn poll_operation(&self, op: &Operation) -> Result<OperationStatus>;
    /// Mutating. Replaces the project's labels (used for override audit labels).
    async fn set_project_labels(
        &self,
        id: &ProjectId,
        labels: BTreeMap<String, String>,
    ) -> Result<Project>;

    // ---- Cloud Asset
    async fn analyze_move(&self, id: &ProjectId, dest: &Parent) -> Result<MoveAnalysis>;

    // ---- IAM
    async fn get_iam(&self, r: &Resource) -> Result<IamPolicy>;
    /// Mutating, etag-checked. Returns the stored policy.
    async fn set_iam(&self, r: &Resource, p: IamPolicy) -> Result<IamPolicy>;
    /// Bindings that apply to `r`, including those inherited from ancestors.
    async fn get_effective_iam(&self, r: &Resource) -> Result<EffectiveIam>;
    /// The subset of `perms` that the identity *administering `r`* holds on it:
    /// the login for the organization `r` belongs to (with one login for both
    /// organizations this is simply the caller).
    async fn test_permissions(&self, r: &Resource, perms: &[String]) -> Result<Vec<String>>;
    /// The subset of `perms` that the identity which *performs the move* holds
    /// on `r`. `projects.move` needs rights on both sides, and one identity
    /// makes the call, so move and create permissions are checked as that identity.
    async fn test_move_permissions(&self, r: &Resource, perms: &[String]) -> Result<Vec<String>>;
    /// Whether `principal` holds each permission on `r` (Policy Troubleshooter).
    async fn troubleshoot_access(
        &self,
        r: &Resource,
        principal: &str,
        perms: &[String],
    ) -> Result<Vec<AccessVerdict>>;
    async fn list_custom_roles(&self, org: &OrgId) -> Result<Vec<CustomRole>>;
    async fn get_custom_role(&self, name: &RoleName) -> Result<Option<CustomRole>>;
    /// Mutating. Creating an identical existing role is a no-op success.
    async fn create_custom_role(&self, org: &OrgId, role: CustomRole) -> Result<CustomRole>;
    /// Mutating (soft delete).
    async fn delete_custom_role(&self, name: &RoleName) -> Result<()>;
    async fn list_deny_policies(&self, r: &Resource) -> Result<Vec<DenyPolicy>>;

    // ---- Org Policy
    /// Policy set directly on `scope`, if any.
    async fn get_policy(&self, scope: &Scope, constraint: &str) -> Result<Option<OrgPolicy>>;
    async fn get_effective_policy(&self, scope: &Scope, constraint: &str) -> Result<OrgPolicy>;
    /// Constraints that have a policy set directly on `scope`.
    async fn list_policies(&self, scope: &Scope) -> Result<Vec<OrgPolicy>>;
    /// Mutating, etag-checked create-or-update.
    async fn set_policy(&self, scope: &Scope, policy: OrgPolicy) -> Result<()>;
    /// Mutating. Removes the policy set directly on `scope`.
    async fn delete_policy(&self, scope: &Scope, constraint: &str) -> Result<()>;

    // ---- Networking / identity / org-scoped
    async fn list_firewall_policies(&self, r: &Resource) -> Result<Vec<FirewallPolicy>>;
    /// Shared VPC links involving `project`: if it is a host, one link per
    /// service project; if it is a service project, the link to its host.
    async fn shared_vpc_relationships(&self, project: &ProjectId) -> Result<Vec<SharedVpcLink>>;
    async fn group_exists(&self, email: &str) -> Result<bool>;
    async fn list_vpc_sc_perimeters(&self, org: &OrgId) -> Result<Vec<Perimeter>>;
    async fn list_org_scoped(&self, org: &OrgId, project: &ProjectId)
        -> Result<Vec<OrgScopedItem>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check that the trait is object-safe.
    #[allow(dead_code)]
    fn object_safe(_: &dyn Gcp) {}
}
