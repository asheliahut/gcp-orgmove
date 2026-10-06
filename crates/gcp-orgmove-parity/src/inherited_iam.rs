//! `inherited-iam` check: access the project gets from its source ancestors
//! that it will lose under the landing parent.

use async_trait::async_trait;
use gcp_orgmove_core::{
    Binding, Category, CheckCtx, Finding, Gcp, ParityCheck, Remediation, Resource, Result, Severity,
};

use crate::effective::{is_primitive_role, is_source_custom_role, lost_grants, GrantCache};

pub const ID: &str = "inherited-iam";

#[derive(Default)]
pub struct InheritedIam {
    cache: GrantCache,
}

fn subject(g: &gcp_orgmove_core::GrantKey) -> String {
    let cond = g
        .condition
        .as_ref()
        .map(|c| c.expression.as_str())
        .unwrap_or("");
    format!("{}|{}|{}", g.member, g.role, cond)
}

#[async_trait]
impl ParityCheck for InheritedIam {
    fn id(&self) -> &'static str {
        ID
    }

    async fn run(&self, ctx: &CheckCtx, gcp: &dyn Gcp) -> Result<Vec<Finding>> {
        let lost = lost_grants(gcp, &self.cache, &ctx.project.id, &ctx.landing_parent).await?;
        let mut out = vec![];
        for eg in lost {
            let g = eg.grant;
            // Deleted principals can't be re-granted; org custom roles are the
            // `custom-roles` check's job.
            if g.member.starts_with("deleted:")
                || is_source_custom_role(&g.role, &ctx.manifest.source_org)
            {
                continue;
            }
            let cond = g
                .condition
                .as_ref()
                .map(|c| format!(" (condition: {})", c.title))
                .unwrap_or_default();
            let mut f = Finding::new(
                ctx.project.id.clone(),
                ID,
                Category::Iam,
                Severity::Gap,
                &subject(&g),
                format!(
                    "{} has {} via {} today but will not under {}{cond}",
                    g.member, g.role, eg.from, ctx.landing_parent
                ),
            );
            // Always project-scoped data; `parity fix` decides the scope by mode.
            f = f.with_remediation(Remediation::AddIamBinding {
                scope: Resource::Project(ctx.project.id.clone()),
                binding: Binding {
                    role: g.role.clone(),
                    members: [g.member.clone()].into(),
                    condition: g.condition.clone(),
                },
            });
            out.push(f);
            if is_primitive_role(&g.role) {
                out.push(Finding::new(
                    ctx.project.id.clone(),
                    ID,
                    Category::Iam,
                    Severity::Warning,
                    &format!("primitive|{}", subject(&g)),
                    format!("{} would keep the broad primitive role {}; consider a narrower role in the destination", g.member, g.role),
                ));
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
    use gcp_orgmove_core::{Manifest, Parent, Project};
    use std::sync::Arc;

    fn setup() -> (FakeGcp, CheckCtx) {
        let f = FakeGcp::new();
        f.org("111").org("222");
        f.folder("10", "organizations/111");
        f.folder("20", "organizations/222");
        f.project("proj-aaaa", "1001", "folders/10");
        let m = Manifest::parse(
            "version: 1\nsource_org: \"111\"\ndestination_org: \"222\"\nprojects:\n  - id: proj-aaaa\n",
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
        let ctx = CheckCtx {
            manifest: Arc::new(m),
            project,
            landing_parent: "folders/20".parse::<Parent>().unwrap(),
        };
        (f, ctx)
    }

    #[tokio::test]
    async fn emits_gap_with_project_scoped_remediation() {
        let (f, ctx) = setup();
        f.grant(
            "organizations/111",
            "roles/compute.viewer",
            "group:eng@x.com",
        );
        let fs = InheritedIam::default().run(&ctx, &f).await.unwrap();
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].severity, Severity::Gap);
        assert!(
            fs[0].summary.contains("group:eng@x.com")
                && fs[0].summary.contains("organizations/111")
        );
        match fs[0].remediation.as_ref().unwrap() {
            Remediation::AddIamBinding { scope, binding } => {
                assert_eq!(scope.to_string(), "projects/proj-aaaa");
                assert_eq!(binding.role.as_str(), "roles/compute.viewer");
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn primitive_roles_add_a_warning() {
        let (f, ctx) = setup();
        f.grant("folders/10", "roles/editor", "user:a@x.com");
        let fs = InheritedIam::default().run(&ctx, &f).await.unwrap();
        assert_eq!(fs.iter().filter(|x| x.severity == Severity::Gap).count(), 1);
        assert_eq!(
            fs.iter()
                .filter(|x| x.severity == Severity::Warning)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn skips_source_custom_roles_and_deleted_principals() {
        let (f, ctx) = setup();
        f.grant(
            "organizations/111",
            "organizations/111/roles/deployer",
            "user:a@x.com",
        );
        f.grant(
            "organizations/111",
            "roles/viewer",
            "deleted:user:gone@x.com?uid=1",
        );
        assert!(InheritedIam::default()
            .run(&ctx, &f)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn no_findings_when_destination_already_grants() {
        let (f, ctx) = setup();
        f.grant("organizations/111", "roles/viewer", "group:eng@x.com");
        f.grant("organizations/222", "roles/viewer", "group:eng@x.com");
        assert!(InheritedIam::default()
            .run(&ctx, &f)
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn finding_ids_are_stable_across_runs() {
        let (f, ctx) = setup();
        f.grant(
            "organizations/111",
            "roles/compute.viewer",
            "group:eng@x.com",
        );
        let a = InheritedIam::default().run(&ctx, &f).await.unwrap();
        let b = InheritedIam::default().run(&ctx, &f).await.unwrap();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn findings_snapshot() {
        let (f, ctx) = setup();
        f.grant(
            "organizations/111",
            "roles/compute.viewer",
            "group:eng@x.com",
        );
        f.grant("folders/10", "roles/editor", "user:a@x.com");
        let fs = InheritedIam::default().run(&ctx, &f).await.unwrap();
        let rows: Vec<String> = fs
            .iter()
            .map(|x| format!("{:?} | {}", x.severity, x.summary))
            .collect();
        insta::assert_snapshot!(rows.join("\n"));
    }
}
