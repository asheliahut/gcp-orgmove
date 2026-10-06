//! Findings, severities, remediations and the `ParityCheck` trait (§9.3).

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::gcp::Gcp;
use crate::ids::*;
use crate::manifest::{hex, Manifest};
use crate::model::{Binding, CustomRole, OrgPolicy, Project};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Preflight,
    Analysis,
    Iam,
    CustomRole,
    OrgPolicy,
    Deny,
    Firewall,
    Domain,
    Group,
    SharedVpc,
    VpcSc,
    OrgScoped,
}

/// Ordered most severe first so sorting puts blockers on top.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Blocker,
    Gap,
    Warning,
    Info,
}

/// A data description of an action that resolves a finding. Never behavior:
/// the planner serializes it and a single executor interprets it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Remediation {
    AddIamBinding {
        scope: Scope,
        binding: Binding,
    },
    CreateCustomRole {
        dest_org: OrgId,
        role: CustomRole,
    },
    RewriteBinding {
        project: ProjectId,
        from: RoleName,
        to: RoleName,
    },
    /// `expires` is an ISO date (`YYYY-MM-DD`).
    SetPolicyOverride {
        project: ProjectId,
        policy: OrgPolicy,
        expires: String,
    },
    Manual {
        instructions: String,
    },
}

impl Remediation {
    pub fn is_manual(&self) -> bool {
        matches!(self, Remediation::Manual { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable ID (`F-` + 12 hex), see `Finding::make_id`.
    pub id: String,
    pub project: ProjectId,
    /// The check that produced it, e.g. `inherited-iam`.
    pub check: String,
    pub category: Category,
    pub severity: Severity,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<Remediation>,
}

impl Finding {
    /// `F-` + first 12 hex of `sha256(project \0 check \0 subject)`.
    pub fn make_id(project: &ProjectId, check: &str, subject: &str) -> String {
        let mut h = Sha256::new();
        h.update(project.as_str());
        h.update([0]);
        h.update(check);
        h.update([0]);
        h.update(subject);
        format!("F-{}", &hex(&h.finalize())[..12])
    }

    pub fn new(
        project: ProjectId,
        check: &str,
        category: Category,
        severity: Severity,
        subject: &str,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            id: Self::make_id(&project, check, subject),
            project,
            check: check.to_string(),
            category,
            severity,
            summary: summary.into(),
            remediation: None,
        }
    }

    pub fn with_remediation(mut self, r: Remediation) -> Self {
        self.remediation = Some(r);
        self
    }

    /// Sort key giving a deterministic order within a project.
    pub fn sort_key(&self) -> (Severity, Category, &str) {
        (self.severity, self.category, &self.id)
    }
}

/// Everything a check needs to know about the project under evaluation.
#[derive(Debug, Clone)]
pub struct CheckCtx {
    pub manifest: Arc<Manifest>,
    pub project: Project,
    pub landing_parent: Parent,
}

#[async_trait]
pub trait ParityCheck: Send + Sync {
    /// Check ID used by `--skip`, e.g. `inherited-iam`.
    fn id(&self) -> &'static str;
    async fn run(&self, ctx: &CheckCtx, gcp: &dyn Gcp) -> Result<Vec<Finding>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn finding_id_is_stable_and_distinct() {
        let p: ProjectId = "my-app-prod".parse().unwrap();
        let a = Finding::make_id(&p, "inherited-iam", "user:a|roles/viewer|");
        assert_eq!(
            a,
            Finding::make_id(&p, "inherited-iam", "user:a|roles/viewer|")
        );
        assert!(a.starts_with("F-") && a.len() == 14);
        assert_ne!(
            a,
            Finding::make_id(&p, "inherited-iam", "user:b|roles/viewer|")
        );
        assert_ne!(
            a,
            Finding::make_id(&p, "custom-roles", "user:a|roles/viewer|")
        );
    }

    #[test]
    fn severity_sorts_blockers_first() {
        let mut v = [
            Severity::Info,
            Severity::Gap,
            Severity::Blocker,
            Severity::Warning,
        ];
        v.sort();
        assert_eq!(v[0], Severity::Blocker);
        assert_eq!(v[3], Severity::Info);
    }

    #[test]
    fn remediation_serde_roundtrip_all_variants() {
        let p: ProjectId = "my-app-prod".parse().unwrap();
        let binding = Binding {
            role: RoleName::new("roles/viewer"),
            members: BTreeSet::from(["user:a@x.com".to_string()]),
            condition: None,
        };
        let all = vec![
            Remediation::AddIamBinding {
                scope: Resource::Project(p.clone()),
                binding,
            },
            Remediation::CreateCustomRole {
                dest_org: "222".parse().unwrap(),
                role: CustomRole {
                    name: RoleName::new("organizations/222/roles/r"),
                    title: "r".into(),
                    description: String::new(),
                    permissions: BTreeSet::from(["compute.instances.get".to_string()]),
                    stage: crate::model::RoleStage::Ga,
                },
            },
            Remediation::RewriteBinding {
                project: p.clone(),
                from: RoleName::new("organizations/111/roles/r"),
                to: RoleName::new("organizations/222/roles/r"),
            },
            Remediation::SetPolicyOverride {
                project: p,
                policy: OrgPolicy::empty("constraints/x"),
                expires: "2026-11-04".into(),
            },
            Remediation::Manual {
                instructions: "do it".into(),
            },
        ];
        for r in all {
            let j = serde_json::to_string(&r).unwrap();
            assert_eq!(serde_json::from_str::<Remediation>(&j).unwrap(), r);
        }
    }
}
