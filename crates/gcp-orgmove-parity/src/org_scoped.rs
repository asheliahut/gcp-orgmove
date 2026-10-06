//! `org-scoped` check: things tied to the *source organization* that do not
//! follow a project: org-level log sinks, tags, asset feeds, essential
//! contacts and billing. Reported as a checklist; nothing is automated.

use async_trait::async_trait;
use gcp_orgmove_core::{
    Category, CheckCtx, Finding, Gcp, ParityCheck, Remediation, Result, Severity,
};

pub const ID: &str = "org-scoped";

#[derive(Default)]
pub struct OrgScoped;

#[async_trait]
impl ParityCheck for OrgScoped {
    fn id(&self) -> &'static str {
        ID
    }

    async fn run(&self, ctx: &CheckCtx, gcp: &dyn Gcp) -> Result<Vec<Finding>> {
        let project = &ctx.project.id;
        let items = gcp
            .list_org_scoped(&ctx.manifest.source_org, project)
            .await?;
        let mut out = vec![];
        let mut add = |severity: Severity, subject: &str, summary: String, instructions: String| {
            out.push(
                Finding::new(
                    project.clone(),
                    ID,
                    Category::OrgScoped,
                    severity,
                    subject,
                    summary,
                )
                .with_remediation(Remediation::Manual { instructions }),
            );
        };

        for item in &items {
            match item.kind.as_str() {
                "log_sink" => add(
                    Severity::Warning,
                    &format!("log_sink|{}", item.name),
                    format!(
                        "organization log sink {} (includeChildren) exports this project's logs today and will stop after the move ({})",
                        item.name, item.detail
                    ),
                    format!("Create an equivalent aggregated sink in the destination organization before moving {project}, then remove it from the source when finished."),
                ),
                "tag_binding" => add(
                    Severity::Warning,
                    &format!("tag_binding|{}", item.name),
                    format!(
                        "project is bound to organization tag value {} ({}); tags belong to the source organization and will not carry over",
                        item.name, item.detail
                    ),
                    format!("Recreate the tag key/value in the destination organization and bind it to {project} after the move; update any IAM or org policy conditions that reference it."),
                ),
                "asset_feed" => add(
                    Severity::Info,
                    &format!("asset_feed|{}", item.name),
                    format!("organization asset feed {} may cover this project ({})", item.name, item.detail),
                    "Recreate the feed in the destination organization if you rely on it.".to_string(),
                ),
                other => add(
                    Severity::Info,
                    &format!("{other}|{}", item.name),
                    format!("{other} {}: {}", item.name, item.detail),
                    "Review manually.".to_string(),
                ),
            }
        }

        // Always-on checklist: neither is readable cheaply, and both bite after the move.
        add(
            Severity::Info,
            "billing",
            "billing accounts are not moved with the project".to_string(),
            format!("Confirm the project's billing account stays usable from the destination organization (billing.resourceAssociations.create) before moving {project}."),
        );
        add(
            Severity::Info,
            "essential-contacts",
            "essential contacts inherited from the source organization stop applying".to_string(),
            format!("Review essential contacts on {project} and on the destination hierarchy so security and billing notices still reach someone."),
        );
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gcp_orgmove_core::fake::FakeGcp;
    use gcp_orgmove_core::{Manifest, OrgScopedItem, Project};
    use std::sync::Arc;

    fn setup() -> (FakeGcp, CheckCtx) {
        let f = FakeGcp::new();
        f.org("111").org("222");
        f.folder("10", "organizations/111");
        f.project("proj-aaaa", "1001", "folders/10");
        let m = Manifest::parse("version: 1\nsource_org: \"111\"\ndestination_org: \"222\"\nprojects:\n  - id: proj-aaaa\n").unwrap().manifest;
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
                landing_parent: "organizations/222".parse().unwrap(),
            },
        )
    }

    #[tokio::test]
    async fn quiet_projects_still_get_the_billing_and_contacts_checklist() {
        let (f, ctx) = setup();
        let fs = OrgScoped.run(&ctx, &f).await.unwrap();
        assert_eq!(fs.len(), 2);
        assert!(fs.iter().all(|x| x.severity == Severity::Info));
        assert!(fs.iter().any(|x| x.summary.contains("billing")));
        assert!(fs.iter().any(|x| x.summary.contains("essential contacts")));
        assert!(fs
            .iter()
            .all(|x| matches!(x.remediation, Some(Remediation::Manual { .. }))));
    }

    #[tokio::test]
    async fn sinks_and_tags_are_warnings_feeds_are_info() {
        let (f, ctx) = setup();
        for (kind, name, detail) in [
            ("log_sink", "org-audit", "destination=bucket"),
            ("tag_binding", "tagValues/1", "111/env/prod"),
            ("asset_feed", "organizations/111/feeds/f", "assetNames=[]"),
            ("mystery", "m", "d"),
        ] {
            f.org_scoped_item(
                "proj-aaaa",
                OrgScopedItem {
                    kind: kind.into(),
                    name: name.into(),
                    detail: detail.into(),
                },
            );
        }
        let fs = OrgScoped.run(&ctx, &f).await.unwrap();
        let sev = |needle: &str| {
            fs.iter()
                .find(|x| x.summary.contains(needle))
                .unwrap()
                .severity
        };
        assert_eq!(sev("org-audit"), Severity::Warning);
        assert_eq!(sev("tagValues/1"), Severity::Warning);
        assert_eq!(sev("feeds/f"), Severity::Info);
        assert_eq!(sev("mystery"), Severity::Info);
        assert_eq!(fs.len(), 6);
    }

    #[tokio::test]
    async fn manual_instructions_name_the_project() {
        let (f, ctx) = setup();
        f.org_scoped_item(
            "proj-aaaa",
            OrgScopedItem {
                kind: "log_sink".into(),
                name: "s".into(),
                detail: "d".into(),
            },
        );
        let fs = OrgScoped.run(&ctx, &f).await.unwrap();
        let sink = fs.iter().find(|x| x.summary.contains("log sink")).unwrap();
        match sink.remediation.as_ref().unwrap() {
            Remediation::Manual { instructions } => assert!(instructions.contains("proj-aaaa")),
            other => panic!("{other:?}"),
        }
    }
}
