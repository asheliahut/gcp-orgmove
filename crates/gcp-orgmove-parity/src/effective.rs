//! Effective IAM before and after a move (§6.4.2 `inherited-iam`).
//!
//! A project's own bindings travel with it. Bindings inherited from source
//! ancestors do not: they are lost unless the destination ancestry (or the
//! project itself) grants the same thing.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use gcp_orgmove_core::{EffectiveGrant, Gcp, GrantKey, OrgId, Parent, ProjectId, Resource, Result};
use tokio::sync::Mutex;

/// Caches per-resource grants so a folder shared by many projects is read once.
#[derive(Default)]
pub struct GrantCache {
    inner: Mutex<BTreeMap<Resource, Arc<BTreeSet<GrantKey>>>>,
}

impl GrantCache {
    pub async fn grants(&self, gcp: &dyn Gcp, r: &Resource) -> Result<Arc<BTreeSet<GrantKey>>> {
        if let Some(hit) = self.inner.lock().await.get(r) {
            return Ok(hit.clone());
        }
        let fetched = Arc::new(gcp.get_iam(r).await?.flatten());
        self.inner.lock().await.insert(r.clone(), fetched.clone());
        Ok(fetched)
    }
}

/// The landing parent followed by its ancestors up to the organization.
pub async fn landing_chain(gcp: &dyn Gcp, landing: &Parent) -> Result<Vec<Resource>> {
    let mut chain = vec![Resource::from_parent(landing)];
    if let Parent::Folder(f) = landing {
        chain.extend(
            gcp.get_folder_ancestry(f)
                .await?
                .iter()
                .map(Resource::from_parent),
        );
    }
    Ok(chain)
}

/// Grants the project has today through its *source* ancestors that it will
/// not have after moving under `landing`.
pub async fn lost_grants(
    gcp: &dyn Gcp,
    cache: &GrantCache,
    project: &ProjectId,
    landing: &Parent,
) -> Result<Vec<EffectiveGrant>> {
    let me = Resource::Project(project.clone());
    let current = gcp.get_effective_iam(&me).await?;

    let mut retained: BTreeSet<GrantKey> = BTreeSet::new();
    retained.extend(
        current
            .grants
            .iter()
            .filter(|g| g.from == me)
            .map(|g| g.grant.clone()),
    );
    for res in landing_chain(gcp, landing).await? {
        retained.extend(cache.grants(gcp, &res).await?.iter().cloned());
    }

    Ok(current
        .grants
        .into_iter()
        .filter(|g| g.from != me && !retained.contains(&g.grant))
        .collect())
}

/// Roles that embed the *source* organization ID and therefore stop
/// resolving after the move; handled by the `custom-roles` check.
pub fn is_source_custom_role(role: &gcp_orgmove_core::RoleName, source: &OrgId) -> bool {
    role.org_custom().is_some_and(|(o, _)| &o == source)
}

pub fn is_primitive_role(role: &gcp_orgmove_core::RoleName) -> bool {
    matches!(
        role.as_str(),
        "roles/owner" | "roles/editor" | "roles/viewer"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use gcp_orgmove_core::fake::FakeGcp;

    fn world() -> FakeGcp {
        let f = FakeGcp::new();
        f.org("111").org("222");
        f.folder("10", "organizations/111");
        f.folder("20", "organizations/222");
        f.project("proj-aaaa", "1001", "folders/10");
        f
    }

    fn pid(s: &str) -> ProjectId {
        s.parse().unwrap()
    }

    async fn lost(f: &FakeGcp, landing: &str) -> Vec<(String, String, String)> {
        let cache = GrantCache::default();
        lost_grants(f, &cache, &pid("proj-aaaa"), &landing.parse().unwrap())
            .await
            .unwrap()
            .into_iter()
            .map(|g| (g.grant.member, g.grant.role.to_string(), g.from.to_string()))
            .collect()
    }

    #[tokio::test]
    async fn inherited_access_is_lost_unless_destination_grants_it() {
        let f = world();
        f.grant("organizations/111", "roles/viewer", "group:eng@x.com");
        f.grant("folders/10", "roles/editor", "group:eng@x.com");
        f.grant("projects/proj-aaaa", "roles/owner", "user:o@x.com"); // own: travels
        let l = lost(&f, "folders/20").await;
        assert_eq!(l.len(), 2);
        assert!(l.iter().all(|(_, _, from)| from != "projects/proj-aaaa"));

        // Destination folder grants one of them => only the other is lost.
        f.grant("folders/20", "roles/editor", "group:eng@x.com");
        let l = lost(&f, "folders/20").await;
        assert_eq!(
            l,
            vec![(
                "group:eng@x.com".into(),
                "roles/viewer".into(),
                "organizations/111".into()
            )]
        );
    }

    #[tokio::test]
    async fn destination_org_level_grants_count() {
        let f = world();
        f.grant("organizations/111", "roles/viewer", "group:eng@x.com");
        f.grant("organizations/222", "roles/viewer", "group:eng@x.com");
        assert!(lost(&f, "folders/20").await.is_empty());
        assert!(lost(&f, "organizations/222").await.is_empty());
    }

    #[tokio::test]
    async fn own_binding_covers_an_inherited_duplicate() {
        let f = world();
        f.grant("folders/10", "roles/viewer", "user:a@x.com");
        f.grant("projects/proj-aaaa", "roles/viewer", "user:a@x.com");
        assert!(lost(&f, "folders/20").await.is_empty());
    }

    #[tokio::test]
    async fn conditions_distinguish_grants() {
        use gcp_orgmove_core::{Binding, Condition, IamPolicy, RoleName};
        let f = world();
        let r: Resource = "folders/10".parse().unwrap();
        let mut p = IamPolicy {
            bindings: vec![],
            etag: "0".into(),
        };
        p.add_binding(&Binding {
            role: RoleName::new("roles/viewer"),
            members: ["user:a@x.com".to_string()].into(),
            condition: Some(Condition {
                title: "t".into(),
                description: String::new(),
                expression: "true".into(),
            }),
        });
        gcp_orgmove_core::Gcp::set_iam(&f, &r, p).await.unwrap();
        // Unconditional grant at destination does not cover the conditional one.
        f.grant("folders/20", "roles/viewer", "user:a@x.com");
        assert_eq!(lost(&f, "folders/20").await.len(), 1);
    }

    #[tokio::test]
    async fn shared_folder_is_read_once() {
        let f = world();
        f.project("proj-bbbb", "1002", "folders/10");
        let cache = GrantCache::default();
        for p in ["proj-aaaa", "proj-bbbb"] {
            lost_grants(&f, &cache, &pid(p), &"folders/20".parse().unwrap())
                .await
                .unwrap();
        }
        let per_resource = f
            .calls()
            .iter()
            .filter(|c| *c == "get_iam(folders/20)")
            .count();
        assert_eq!(per_resource, 1);
    }

    #[test]
    fn role_helpers() {
        use gcp_orgmove_core::RoleName;
        let src: OrgId = "111".parse().unwrap();
        assert!(is_source_custom_role(
            &RoleName::new("organizations/111/roles/x"),
            &src
        ));
        assert!(!is_source_custom_role(
            &RoleName::new("organizations/222/roles/x"),
            &src
        ));
        assert!(is_primitive_role(&RoleName::new("roles/editor")));
        assert!(!is_primitive_role(&RoleName::new("roles/compute.admin")));
    }
}
