//! `custom-roles` check: bindings that reference `organizations/<SRC>/roles/*`
//! stop resolving after the move, because the role name embeds the source
//! organization ID.
//!
//! For each such role the check proposes (in order): create an equivalent role
//! in the destination org, then add bindings to the new role name. The old
//! bindings stay until `parity prune`.

use std::collections::BTreeSet;

use async_trait::async_trait;
use gcp_orgmove_core::{
    Binding, Category, CheckCtx, CustomRole, Finding, Gcp, ParityCheck, Remediation, Resource,
    Result, RoleName, Severity,
};

use crate::effective::{is_source_custom_role, lost_grants, GrantCache};

pub const ID: &str = "custom-roles";

#[derive(Default)]
pub struct CustomRoles {
    cache: GrantCache,
}

/// A readable diff of two permission sets.
fn permission_diff(source: &BTreeSet<String>, dest: &BTreeSet<String>) -> String {
    let missing: Vec<&str> = source.difference(dest).map(String::as_str).collect();
    let extra: Vec<&str> = dest.difference(source).map(String::as_str).collect();
    let mut parts = vec![];
    if !missing.is_empty() {
        parts.push(format!("destination lacks {}", missing.join(", ")));
    }
    if !extra.is_empty() {
        parts.push(format!("destination also has {}", extra.join(", ")));
    }
    parts.join("; ")
}

#[async_trait]
impl ParityCheck for CustomRoles {
    fn id(&self) -> &'static str {
        ID
    }

    async fn run(&self, ctx: &CheckCtx, gcp: &dyn Gcp) -> Result<Vec<Finding>> {
        let src = &ctx.manifest.source_org;
        let dest = &ctx.manifest.destination_org;
        let project = &ctx.project.id;
        let me = Resource::Project(project.clone());

        // Bindings on the project itself: they travel, but the role won't resolve.
        let own = gcp.get_iam(&me).await?;
        let own_roles: BTreeSet<RoleName> = own
            .bindings
            .iter()
            .map(|b| b.role.clone())
            .filter(|r| is_source_custom_role(r, src))
            .collect();
        // Inherited bindings that will be lost *and* use a source custom role.
        let lost: Vec<_> = lost_grants(gcp, &self.cache, project, &ctx.landing_parent)
            .await?
            .into_iter()
            .filter(|g| {
                is_source_custom_role(&g.grant.role, src) && !g.grant.member.starts_with("deleted:")
            })
            .collect();

        let mut all_roles: BTreeSet<RoleName> = own_roles.clone();
        all_roles.extend(lost.iter().map(|g| g.grant.role.clone()));

        let mut out = vec![];
        for from in &all_roles {
            let to = from
                .rehomed(dest)
                .expect("source custom role has a short name");
            let Some(definition) = gcp.get_custom_role(from).await? else {
                out.push(Finding::new(
                    project.clone(),
                    ID,
                    Category::CustomRole,
                    Severity::Warning,
                    &format!("missing|{from}"),
                    format!("bindings reference {from}, which no longer exists in the source organization; they are already ineffective"),
                ));
                continue;
            };
            let new_role = CustomRole {
                name: to.clone(),
                ..definition.clone()
            };
            match gcp.get_custom_role(&to).await? {
                Some(existing) if existing.permissions != definition.permissions => {
                    out.push(Finding::new(
                        project.clone(),
                        ID,
                        Category::CustomRole,
                        Severity::Blocker,
                        &format!("conflict|{from}"),
                        format!(
                            "destination already has {to} with different permissions ({}); reconcile the two roles, then re-plan",
                            permission_diff(&definition.permissions, &existing.permissions)
                        ),
                    ));
                    continue;
                }
                Some(_) => {} // identical: nothing to create
                None => out.push(
                    Finding::new(
                        project.clone(),
                        ID,
                        Category::CustomRole,
                        Severity::Gap,
                        &format!("create|{from}"),
                        format!("{from} must exist in the destination organization as {to}"),
                    )
                    .with_remediation(Remediation::CreateCustomRole {
                        dest_org: dest.clone(),
                        role: new_role,
                    }),
                ),
            }
            if own_roles.contains(from) {
                out.push(
                    Finding::new(
                        project.clone(),
                        ID,
                        Category::CustomRole,
                        Severity::Gap,
                        &format!("rewrite|{from}"),
                        format!("project bindings to {from} stop resolving after the move; add the same members under {to}"),
                    )
                    .with_remediation(Remediation::RewriteBinding { project: project.clone(), from: from.clone(), to: to.clone() }),
                );
            }
            for eg in lost.iter().filter(|g| &g.grant.role == from) {
                let g = &eg.grant;
                let cond = g
                    .condition
                    .as_ref()
                    .map(|c| c.expression.as_str())
                    .unwrap_or("");
                out.push(
                    Finding::new(
                        project.clone(),
                        ID,
                        Category::CustomRole,
                        Severity::Gap,
                        &format!("inherited|{}|{from}|{cond}", g.member),
                        format!("{} has {from} via {} today; it will not apply after the move, so grant {to} on the project", g.member, eg.from),
                    )
                    .with_remediation(Remediation::AddIamBinding {
                        scope: me.clone(),
                        binding: Binding { role: to.clone(), members: [g.member.clone()].into(), condition: g.condition.clone() },
                    }),
                );
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gcp_orgmove_core::fake::FakeGcp;
    use gcp_orgmove_core::{Manifest, Project, RoleStage};
    use std::sync::Arc;

    fn role(org: &str, name: &str, perms: &[&str]) -> CustomRole {
        CustomRole {
            name: RoleName::new(format!("organizations/{org}/roles/{name}")),
            title: name.into(),
            description: String::new(),
            permissions: perms.iter().map(|p| p.to_string()).collect(),
            stage: RoleStage::Ga,
        }
    }

    fn setup() -> (FakeGcp, CheckCtx) {
        let f = FakeGcp::new();
        f.org("111").org("222");
        f.folder("10", "organizations/111");
        f.folder("20", "organizations/222");
        f.project("proj-aaaa", "1001", "folders/10");
        let m = Manifest::parse(
            "version: 1\nsource_org: \"111\"\ndestination_org: \"222\"\nprojects:\n  - id: proj-aaaa\nparity:\n  custom_roles: recreate\n",
        )
        .unwrap()
        .manifest;
        let project = Project {
            id: "proj-aaaa".parse().unwrap(),
            number: "1001".parse().unwrap(),
            parent: "folders/10".parse().unwrap(),
            state: gcp_orgmove_core::LifecycleState::Active,
            labels: Default::default(),
            etag: "e".into(),
        };
        (
            f,
            CheckCtx {
                manifest: Arc::new(m),
                project,
                landing_parent: "folders/20".parse().unwrap(),
            },
        )
    }

    async fn run(f: &FakeGcp, ctx: &CheckCtx) -> Vec<Finding> {
        CustomRoles::default().run(ctx, f).await.unwrap()
    }

    #[tokio::test]
    async fn no_custom_roles_no_findings() {
        let (f, ctx) = setup();
        f.grant("projects/proj-aaaa", "roles/viewer", "user:a@x.com");
        assert!(run(&f, &ctx).await.is_empty());
    }

    #[tokio::test]
    async fn own_binding_needs_a_new_role_and_a_rewrite() {
        let (f, ctx) = setup();
        f.custom_role(role("111", "deployer", &["compute.instances.get"]));
        f.grant(
            "projects/proj-aaaa",
            "organizations/111/roles/deployer",
            "user:a@x.com",
        );
        let fs = run(&f, &ctx).await;
        assert_eq!(fs.len(), 2);
        let create = fs.iter().find_map(|x| match x.remediation.as_ref()? {
            Remediation::CreateCustomRole { dest_org, role } => {
                Some((dest_org.to_string(), role.clone()))
            }
            _ => None,
        });
        let (org, new_role) = create.expect("create remediation");
        assert_eq!(org, "222");
        assert_eq!(new_role.name.as_str(), "organizations/222/roles/deployer");
        assert!(new_role.permissions.contains("compute.instances.get"));
        let rewrite = fs.iter().find_map(|x| match x.remediation.as_ref()? {
            Remediation::RewriteBinding { from, to, .. } => {
                Some((from.to_string(), to.to_string()))
            }
            _ => None,
        });
        assert_eq!(
            rewrite,
            Some((
                "organizations/111/roles/deployer".into(),
                "organizations/222/roles/deployer".into()
            ))
        );
        assert!(fs.iter().all(|x| x.severity == Severity::Gap));
    }

    #[tokio::test]
    async fn inherited_custom_role_grant_becomes_a_grant_of_the_new_role() {
        let (f, ctx) = setup();
        f.custom_role(role("111", "deployer", &["a.b.c"]));
        f.grant(
            "organizations/111",
            "organizations/111/roles/deployer",
            "group:ci@x.com",
        );
        let fs = run(&f, &ctx).await;
        let add = fs
            .iter()
            .find_map(|x| match x.remediation.as_ref()? {
                Remediation::AddIamBinding { scope, binding } => {
                    Some((scope.to_string(), binding.clone()))
                }
                _ => None,
            })
            .expect("add binding");
        assert_eq!(add.0, "projects/proj-aaaa");
        assert_eq!(add.1.role.as_str(), "organizations/222/roles/deployer");
        assert!(add.1.members.contains("group:ci@x.com"));
    }

    #[tokio::test]
    async fn identical_destination_role_needs_no_creation() {
        let (f, ctx) = setup();
        f.custom_role(role("111", "deployer", &["a.b.c"]));
        f.custom_role(role("222", "deployer", &["a.b.c"]));
        f.grant(
            "projects/proj-aaaa",
            "organizations/111/roles/deployer",
            "user:a@x.com",
        );
        let fs = run(&f, &ctx).await;
        assert_eq!(fs.len(), 1);
        assert!(matches!(
            fs[0].remediation,
            Some(Remediation::RewriteBinding { .. })
        ));
    }

    #[tokio::test]
    async fn conflicting_destination_role_is_a_blocker_with_a_diff() {
        let (f, ctx) = setup();
        f.custom_role(role("111", "deployer", &["a.b.c", "d.e.f"]));
        f.custom_role(role("222", "deployer", &["a.b.c", "x.y.z"]));
        f.grant(
            "projects/proj-aaaa",
            "organizations/111/roles/deployer",
            "user:a@x.com",
        );
        let fs = run(&f, &ctx).await;
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].severity, Severity::Blocker);
        assert!(
            fs[0].summary.contains("lacks d.e.f") && fs[0].summary.contains("also has x.y.z"),
            "{}",
            fs[0].summary
        );
        assert!(fs[0].remediation.is_none());
    }

    #[tokio::test]
    async fn role_missing_from_source_is_only_a_warning() {
        let (f, ctx) = setup();
        f.grant(
            "projects/proj-aaaa",
            "organizations/111/roles/ghost",
            "user:a@x.com",
        );
        let fs = run(&f, &ctx).await;
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].severity, Severity::Warning);
    }

    #[tokio::test]
    async fn other_orgs_custom_roles_are_ignored() {
        let (f, ctx) = setup();
        f.grant(
            "projects/proj-aaaa",
            "organizations/222/roles/deployer",
            "user:a@x.com",
        );
        f.grant(
            "projects/proj-aaaa",
            "organizations/999/roles/other",
            "user:a@x.com",
        );
        assert!(run(&f, &ctx).await.is_empty());
    }

    #[test]
    fn diff_is_readable() {
        let a: BTreeSet<String> = ["p1".into(), "p2".into()].into();
        let b: BTreeSet<String> = ["p2".into(), "p3".into()].into();
        assert_eq!(
            permission_diff(&a, &b),
            "destination lacks p1; destination also has p3"
        );
    }
}
