//! Report-only checks about principals: `principal-domains` and `groups`.

use std::collections::BTreeSet;

use async_trait::async_trait;
use gcp_orgmove_core::{
    Category, CheckCtx, Finding, Gcp, Parent, ParityCheck, Resource, Result, Severity,
};

use crate::effective::lost_grants;
use crate::network::project_principals;

pub const DOMAINS_ID: &str = "principal-domains";
pub const GROUPS_ID: &str = "groups";
pub const MEMBER_DOMAINS: &str = "constraints/iam.allowedPolicyMemberDomains";

fn email_domain(member: &str) -> Option<&str> {
    let (kind, rest) = member.split_once(':')?;
    // Service accounts belong to projects, not to a customer's directory.
    matches!(kind, "user" | "group").then_some(())?;
    rest.rsplit_once('@').map(|(_, d)| d)
}

/// `iam.allowedPolicyMemberDomains` takes Cloud Identity customer IDs, which
/// cannot be derived from an email address without the Directory API, so this
/// check reports the principal domains for a human to confirm.
#[derive(Default)]
pub struct PrincipalDomains;

fn restriction(p: &gcp_orgmove_core::OrgPolicy) -> Option<BTreeSet<String>> {
    let mut allowed = BTreeSet::new();
    for r in p.rules.iter().filter(|r| r.condition.is_none()) {
        if r.allow_all {
            return None;
        }
        allowed.extend(r.allowed_values.iter().cloned());
    }
    (!allowed.is_empty()).then_some(allowed)
}

#[async_trait]
impl ParityCheck for PrincipalDomains {
    fn id(&self) -> &'static str {
        DOMAINS_ID
    }

    async fn run(&self, ctx: &CheckCtx, gcp: &dyn Gcp) -> Result<Vec<Finding>> {
        let landing = Resource::from_parent(&ctx.landing_parent);
        let dest = gcp.get_effective_policy(&landing, MEMBER_DOMAINS).await?;
        let Some(dest_allowed) = restriction(&dest) else {
            return Ok(vec![]);
        };
        let src_res = Resource::Project(ctx.project.id.clone());
        let src_allowed = restriction(&gcp.get_effective_policy(&src_res, MEMBER_DOMAINS).await?);
        if src_allowed.as_ref() == Some(&dest_allowed) {
            return Ok(vec![]); // same restriction as today: nothing changes
        }
        let principals = project_principals(gcp, ctx).await?;
        let domains: BTreeSet<&str> = principals.iter().filter_map(|m| email_domain(m)).collect();
        Ok(domains
            .into_iter()
            .map(|d| {
                Finding::new(
                    ctx.project.id.clone(),
                    DOMAINS_ID,
                    Category::Domain,
                    Severity::Warning,
                    d,
                    format!(
                        "the destination restricts policy members to Cloud Identity customer(s) {}; principals from {d} are bound on this project. Confirm {d} belongs to an allowed customer, or later IAM changes (including `parity fix`) will be rejected",
                        dest_allowed.iter().cloned().collect::<Vec<_>>().join(", ")
                    ),
                )
            })
            .collect())
    }
}

/// Groups used in bindings (on the project, or inherited and about to be
/// re-granted) must resolve. Needs the Cloud Identity API; if it can't be
/// queried that is reported once as Info rather than failing the plan.
#[derive(Default)]
pub struct Groups;

#[async_trait]
impl ParityCheck for Groups {
    fn id(&self) -> &'static str {
        GROUPS_ID
    }

    async fn run(&self, ctx: &CheckCtx, gcp: &dyn Gcp) -> Result<Vec<Finding>> {
        let mut groups: BTreeSet<String> = project_principals(gcp, ctx)
            .await?
            .into_iter()
            .filter_map(|m| m.strip_prefix("group:").map(String::from))
            .collect();
        let cache = crate::effective::GrantCache::default();
        for g in lost_grants(
            gcp,
            &cache,
            &ctx.project.id,
            &Parent::clone(&ctx.landing_parent),
        )
        .await?
        {
            if let Some(email) = g.grant.member.strip_prefix("group:") {
                groups.insert(email.to_string());
            }
        }
        let mut out = vec![];
        for email in groups {
            match gcp.group_exists(&email).await {
                Ok(true) => {}
                Ok(false) => out.push(Finding::new(
                    ctx.project.id.clone(),
                    GROUPS_ID,
                    Category::Group,
                    Severity::Warning,
                    &email,
                    format!("group {email} is bound on this project but does not resolve in Cloud Identity; its access is already ineffective"),
                )),
                Err(e) => {
                    return Ok(vec![Finding::new(
                        ctx.project.id.clone(),
                        GROUPS_ID,
                        Category::Group,
                        Severity::Info,
                        "unavailable",
                        format!("groups could not be checked ({}); enable the Cloud Identity API or run with --skip groups", e.message),
                    )]);
                }
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
    use gcp_orgmove_core::{Error, ErrorKind, Manifest, OrgPolicy, Project};
    use std::sync::Arc;

    fn setup() -> (FakeGcp, CheckCtx) {
        let f = FakeGcp::new();
        f.org("111").org("222");
        f.folder("10", "organizations/111");
        f.folder("20", "organizations/222");
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
                landing_parent: "folders/20".parse().unwrap(),
            },
        )
    }

    fn allowed(vals: &[&str]) -> OrgPolicy {
        let mut p = OrgPolicy::empty(MEMBER_DOMAINS);
        for v in vals {
            p.allow_value(v);
        }
        p
    }

    #[test]
    fn domains_come_from_users_and_groups_only() {
        assert_eq!(email_domain("user:a@x.com"), Some("x.com"));
        assert_eq!(email_domain("group:g@y.org"), Some("y.org"));
        assert_eq!(
            email_domain("serviceAccount:s@p.iam.gserviceaccount.com"),
            None
        );
        assert_eq!(email_domain("allUsers"), None);
    }

    #[tokio::test]
    async fn domain_restriction_at_the_destination_lists_principal_domains() {
        let (f, ctx) = setup();
        f.grant("projects/proj-aaaa", "roles/viewer", "user:a@x.com");
        f.grant("projects/proj-aaaa", "roles/viewer", "group:g@partner.org");
        f.grant(
            "projects/proj-aaaa",
            "roles/viewer",
            "serviceAccount:s@proj-aaaa.iam.gserviceaccount.com",
        );
        f.policy("organizations/222", allowed(&["C0abc123"]));
        let fs = PrincipalDomains.run(&ctx, &f).await.unwrap();
        let mut domains: Vec<_> = fs
            .iter()
            .map(|x| {
                x.summary
                    .split("principals from ")
                    .nth(1)
                    .unwrap()
                    .split(' ')
                    .next()
                    .unwrap()
                    .to_string()
            })
            .collect();
        domains.sort();
        assert_eq!(domains, ["partner.org", "x.com"]);
        assert!(fs
            .iter()
            .all(|x| x.severity == Severity::Warning && x.summary.contains("C0abc123")));
    }

    #[tokio::test]
    async fn unchanged_or_absent_restrictions_are_quiet() {
        let (f, ctx) = setup();
        f.grant("projects/proj-aaaa", "roles/viewer", "user:a@x.com");
        assert!(
            PrincipalDomains.run(&ctx, &f).await.unwrap().is_empty(),
            "no restriction anywhere"
        );
        f.policy("organizations/111", allowed(&["C0abc123"]));
        f.policy("organizations/222", allowed(&["C0abc123"]));
        assert!(
            PrincipalDomains.run(&ctx, &f).await.unwrap().is_empty(),
            "identical restriction"
        );
    }

    #[tokio::test]
    async fn groups_that_do_not_resolve_are_reported() {
        let (f, ctx) = setup();
        f.group("eng@x.com");
        f.grant("projects/proj-aaaa", "roles/viewer", "group:eng@x.com");
        f.grant("projects/proj-aaaa", "roles/viewer", "group:ghost@x.com");
        f.grant("folders/10", "roles/editor", "group:inherited-ghost@x.com");
        let fs = Groups.run(&ctx, &f).await.unwrap();
        let names: Vec<_> = fs
            .iter()
            .map(|x| x.summary.split(' ').nth(1).unwrap().to_string())
            .collect();
        assert_eq!(fs.len(), 2, "{names:?}");
        assert!(
            names.contains(&"ghost@x.com".to_string())
                && names.contains(&"inherited-ghost@x.com".to_string())
        );
    }

    #[tokio::test]
    async fn api_unavailable_degrades_to_one_info_finding() {
        let (f, ctx) = setup();
        f.grant("projects/proj-aaaa", "roles/viewer", "group:eng@x.com");
        f.grant("projects/proj-aaaa", "roles/viewer", "group:ops@x.com");
        f.inject_fault(
            "group_exists",
            Error::new(ErrorKind::PermissionDenied, "Cloud Identity API disabled"),
        );
        let fs = Groups.run(&ctx, &f).await.unwrap();
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].severity, Severity::Info);
        assert!(fs[0].summary.contains("--skip groups"));
    }
}
