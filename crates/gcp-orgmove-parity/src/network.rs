//! Report-only checks that look at what the destination hierarchy attaches to
//! a project: `deny-policies`, `firewall-policies` and `vpc-sc`.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use gcp_orgmove_core::{
    Category, CheckCtx, Finding, Gcp, ParityCheck, Perimeter, Remediation, Resource, Result,
    Severity,
};
use tokio::sync::Mutex;

use crate::effective::landing_chain;

pub const DENY_ID: &str = "deny-policies";
pub const FIREWALL_ID: &str = "firewall-policies";
pub const VPC_SC_ID: &str = "vpc-sc";

/// The principals whose access matters for this project: everyone bound on
/// the project itself plus the configured probes.
pub async fn project_principals(gcp: &dyn Gcp, ctx: &CheckCtx) -> Result<BTreeSet<String>> {
    let mut out: BTreeSet<String> = ctx
        .manifest
        .parity
        .principals_to_probe
        .iter()
        .cloned()
        .collect();
    let own = gcp
        .get_iam(&Resource::Project(ctx.project.id.clone()))
        .await?;
    out.extend(own.bindings.iter().flat_map(|b| b.members.iter().cloned()));
    Ok(out)
}

/// IAM member string -> the principal identifier deny policies use.
pub fn deny_principal(member: &str) -> Option<String> {
    let (kind, rest) = member.split_once(':').unwrap_or((member, ""));
    match kind {
        "user" => Some(format!("principal://goog/subject/{rest}")),
        "serviceAccount" => Some(format!(
            "principal://iam.googleapis.com/projects/-/serviceAccounts/{rest}"
        )),
        "group" => Some(format!("principalSet://goog/group/{rest}")),
        "allUsers" | "allAuthenticatedUsers" => Some("principalSet://goog/public:all".to_string()),
        _ => None,
    }
}

// ----------------------------------------------------------- deny policies

#[derive(Default)]
pub struct DenyPolicies;

#[async_trait]
impl ParityCheck for DenyPolicies {
    fn id(&self) -> &'static str {
        DENY_ID
    }

    async fn run(&self, ctx: &CheckCtx, gcp: &dyn Gcp) -> Result<Vec<Finding>> {
        let principals = project_principals(gcp, ctx).await?;
        let ids: Vec<(String, String)> = principals
            .iter()
            .filter_map(|m| deny_principal(m).map(|d| (m.clone(), d)))
            .collect();
        let mut out = vec![];
        for res in landing_chain(gcp, &ctx.landing_parent).await? {
            for policy in gcp.list_deny_policies(&res).await? {
                for (n, rule) in policy.rules.iter().enumerate() {
                    if rule.denied_permissions.is_empty() {
                        continue;
                    }
                    for (member, deny_id) in &ids {
                        let denied = rule.denied_principals.contains(deny_id)
                            || rule
                                .denied_principals
                                .contains("principalSet://goog/public:all");
                        if !denied || rule.exception_principals.contains(deny_id) {
                            continue;
                        }
                        let cond = if rule.has_condition {
                            " (the rule is conditional; conditions are not evaluated)"
                        } else {
                            ""
                        };
                        out.push(Finding::new(
                            ctx.project.id.clone(),
                            DENY_ID,
                            Category::Deny,
                            Severity::Warning,
                            &format!("{}|{n}|{member}", policy.name),
                            format!(
                                "deny policy {} on {res} may deny {member} {}{cond}; deny rules are reported, not simulated",
                                policy.name,
                                rule.denied_permissions.iter().cloned().collect::<Vec<_>>().join(", ")
                            ),
                        ));
                    }
                }
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }
}

// -------------------------------------------------------- firewall policies

#[derive(Default)]
pub struct FirewallPolicies;

#[async_trait]
impl ParityCheck for FirewallPolicies {
    fn id(&self) -> &'static str {
        FIREWALL_ID
    }

    async fn run(&self, ctx: &CheckCtx, gcp: &dyn Gcp) -> Result<Vec<Finding>> {
        let mut source_chain: Vec<Resource> = gcp
            .get_ancestry(&ctx.project.id)
            .await?
            .iter()
            .map(Resource::from_parent)
            .collect();
        source_chain.dedup();
        let dest_chain = landing_chain(gcp, &ctx.landing_parent).await?;
        let mut out = vec![];
        for (chain, gained) in [(&dest_chain, true), (&source_chain, false)] {
            for res in chain {
                for p in gcp.list_firewall_policies(res).await? {
                    let (verb, subject) = if gained {
                        (
                            "will start applying to the project's networks after the move",
                            format!("gained|{}|{res}", p.name),
                        )
                    } else {
                        (
                            "applies today but will stop applying after the move",
                            format!("lost|{}|{res}", p.name),
                        )
                    };
                    out.push(Finding::new(
                        ctx.project.id.clone(),
                        FIREWALL_ID,
                        Category::Firewall,
                        Severity::Warning,
                        &subject,
                        format!(
                            "hierarchical firewall policy {} on {res} {verb}; review connectivity",
                            p.name
                        ),
                    ));
                }
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(out)
    }
}

// ------------------------------------------------------------------- VPC-SC

#[derive(Default)]
pub struct VpcSc {
    perimeters: Mutex<Option<Arc<Vec<Perimeter>>>>,
}

impl VpcSc {
    async fn perimeters(&self, gcp: &dyn Gcp, ctx: &CheckCtx) -> Result<Arc<Vec<Perimeter>>> {
        if let Some(hit) = self.perimeters.lock().await.as_ref() {
            return Ok(hit.clone());
        }
        let fetched = Arc::new(gcp.list_vpc_sc_perimeters(&ctx.manifest.source_org).await?);
        *self.perimeters.lock().await = Some(fetched.clone());
        Ok(fetched)
    }
}

#[async_trait]
impl ParityCheck for VpcSc {
    fn id(&self) -> &'static str {
        VPC_SC_ID
    }

    async fn run(&self, ctx: &CheckCtx, gcp: &dyn Gcp) -> Result<Vec<Finding>> {
        let mut out = vec![];
        for p in self
            .perimeters(gcp, ctx)
            .await?
            .iter()
            .filter(|p| p.projects.contains(&ctx.project.number))
        {
            out.push(
                Finding::new(
                    ctx.project.id.clone(),
                    VPC_SC_ID,
                    Category::VpcSc,
                    Severity::Blocker,
                    &p.name,
                    format!("project is inside VPC Service Controls perimeter {}; moving it is blocked until it is removed from the perimeter", p.name),
                )
                .with_remediation(Remediation::Manual {
                    instructions: format!(
                        "Remove project {} (number {}) from {} (Access Context Manager), run the migration, then add it to the matching destination perimeter. Reconfiguring VPC-SC is not automated.",
                        ctx.project.id, ctx.project.number, p.name
                    ),
                }),
            );
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gcp_orgmove_core::fake::FakeGcp;
    use gcp_orgmove_core::{DenyPolicy, DenyRule, FirewallPolicy, Manifest, Project};

    fn setup() -> (FakeGcp, CheckCtx) {
        let f = FakeGcp::new();
        f.org("111").org("222");
        f.folder("10", "organizations/111");
        f.folder("20", "organizations/222");
        f.project("proj-aaaa", "1001", "folders/10");
        f.grant("projects/proj-aaaa", "roles/viewer", "user:a@x.com");
        f.grant(
            "projects/proj-aaaa",
            "roles/viewer",
            "serviceAccount:ci@proj-aaaa.iam.gserviceaccount.com",
        );
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

    fn deny(
        at: &str,
        principals: &[&str],
        exceptions: &[&str],
        perms: &[&str],
        cond: bool,
    ) -> DenyPolicy {
        DenyPolicy {
            name: "policies/x/denypolicies/block".into(),
            attached_to: at.parse().unwrap(),
            rules: vec![DenyRule {
                denied_principals: principals.iter().map(|s| s.to_string()).collect(),
                denied_permissions: perms.iter().map(|s| s.to_string()).collect(),
                exception_principals: exceptions.iter().map(|s| s.to_string()).collect(),
                has_condition: cond,
            }],
        }
    }

    #[test]
    fn member_to_deny_principal_mapping() {
        assert_eq!(
            deny_principal("user:a@x.com").unwrap(),
            "principal://goog/subject/a@x.com"
        );
        assert_eq!(
            deny_principal("group:g@x.com").unwrap(),
            "principalSet://goog/group/g@x.com"
        );
        assert_eq!(
            deny_principal("serviceAccount:s@p.iam.gserviceaccount.com").unwrap(),
            "principal://iam.googleapis.com/projects/-/serviceAccounts/s@p.iam.gserviceaccount.com"
        );
        assert_eq!(
            deny_principal("allUsers").unwrap(),
            "principalSet://goog/public:all"
        );
        assert!(deny_principal("domain:x.com").is_none());
    }

    #[tokio::test]
    async fn deny_rule_naming_a_project_principal_is_reported() {
        let (f, ctx) = setup();
        f.deny_policy(
            "folders/20",
            deny(
                "folders/20",
                &["principal://goog/subject/a@x.com"],
                &[],
                &["iam.googleapis.com/roles.delete"],
                true,
            ),
        );
        let fs = DenyPolicies.run(&ctx, &f).await.unwrap();
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].severity, Severity::Warning);
        assert!(
            fs[0].summary.contains("user:a@x.com")
                && fs[0].summary.contains("roles.delete")
                && fs[0].summary.contains("conditional")
        );
    }

    #[tokio::test]
    async fn public_deny_hits_everyone_but_exceptions_are_respected() {
        let (f, ctx) = setup();
        f.deny_policy(
            "organizations/222",
            deny(
                "organizations/222",
                &["principalSet://goog/public:all"],
                &["principal://goog/subject/a@x.com"],
                &["x.y.z"],
                false,
            ),
        );
        let fs = DenyPolicies.run(&ctx, &f).await.unwrap();
        assert_eq!(
            fs.len(),
            1,
            "a@x.com is excepted; the service account is hit"
        );
        assert!(fs[0].summary.contains("serviceAccount:ci@proj-aaaa"));
    }

    #[tokio::test]
    async fn unrelated_or_permissionless_deny_rules_are_quiet() {
        let (f, ctx) = setup();
        f.deny_policy(
            "folders/20",
            deny(
                "folders/20",
                &["principal://goog/subject/other@x.com"],
                &[],
                &["x.y.z"],
                false,
            ),
        );
        f.deny_policy(
            "organizations/222",
            deny(
                "organizations/222",
                &["principal://goog/subject/a@x.com"],
                &[],
                &[],
                false,
            ),
        );
        assert!(DenyPolicies.run(&ctx, &f).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn firewall_policies_gained_and_lost_are_both_reported() {
        let (f, ctx) = setup();
        f.firewall_policy(
            "folders/20",
            FirewallPolicy {
                name: "corp-dest".into(),
                attached_to: "folders/20".parse().unwrap(),
            },
        );
        f.firewall_policy(
            "organizations/111",
            FirewallPolicy {
                name: "corp-src".into(),
                attached_to: "organizations/111".parse().unwrap(),
            },
        );
        let fs = FirewallPolicies.run(&ctx, &f).await.unwrap();
        assert_eq!(fs.len(), 2);
        assert!(fs
            .iter()
            .any(|x| x.summary.contains("corp-dest") && x.summary.contains("start applying")));
        assert!(fs
            .iter()
            .any(|x| x.summary.contains("corp-src") && x.summary.contains("stop applying")));
        assert!(fs.iter().all(|x| x.severity == Severity::Warning));
    }

    #[tokio::test]
    async fn vpc_sc_membership_is_a_blocker_with_manual_steps() {
        let (f, ctx) = setup();
        f.perimeter(Perimeter {
            name: "accessPolicies/1/servicePerimeters/prod".into(),
            projects: vec!["1001".parse().unwrap()],
        });
        f.perimeter(Perimeter {
            name: "accessPolicies/1/servicePerimeters/other".into(),
            projects: vec!["9999".parse().unwrap()],
        });
        let fs = VpcSc::default().run(&ctx, &f).await.unwrap();
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].severity, Severity::Blocker);
        assert!(
            matches!(&fs[0].remediation, Some(Remediation::Manual { instructions }) if instructions.contains("proj-aaaa") && instructions.contains("prod"))
        );
    }

    #[tokio::test]
    async fn vpc_sc_lists_perimeters_once_across_projects() {
        let (f, ctx) = setup();
        let check = VpcSc::default();
        for _ in 0..3 {
            check.run(&ctx, &f).await.unwrap();
        }
        assert_eq!(f.calls_to("list_vpc_sc_perimeters"), 1);
        assert!(check.run(&ctx, &f).await.unwrap().is_empty());
    }
}
