//! Domain model shared by the planner, parity checks and the `Gcp` trait.
//!
//! All collections that end up in the plan or state file are ordered
//! (`BTreeMap`/`BTreeSet`/sorted `Vec`) so serialization is deterministic.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::ids::*;

/// Org policy constraint that must allow the destination org on the source side.
pub const EXPORT_CONSTRAINT: &str = "constraints/resourcemanager.allowedExportDestinations";
/// Org policy constraint that must allow the source org on the destination side.
pub const IMPORT_CONSTRAINT: &str = "constraints/resourcemanager.allowedImportSources";

// ---------------------------------------------------------------- projects

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LifecycleState {
    Active,
    DeleteRequested,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    pub id: ProjectId,
    pub number: ProjectNumber,
    pub parent: Parent,
    pub state: LifecycleState,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    pub etag: String,
}

/// A long-running operation handle (e.g. `operations/cp.123`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum OperationStatus {
    Running,
    Done,
    Failed { code: i32, message: String },
}

// --------------------------------------------------------------------- IAM

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Condition {
    pub title: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    pub expression: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Binding {
    pub role: RoleName,
    /// Members like `user:a@b.com`, `serviceAccount:...`, `group:...`.
    pub members: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<Condition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IamPolicy {
    #[serde(default)]
    pub bindings: Vec<Binding>,
    #[serde(default)]
    pub etag: String,
}

impl IamPolicy {
    /// Add `members` to the binding for `(role, condition)`, creating it if
    /// needed. Returns `true` if anything changed. Never removes members.
    pub fn add_binding(&mut self, b: &Binding) -> bool {
        match self
            .bindings
            .iter_mut()
            .find(|x| x.role == b.role && x.condition == b.condition)
        {
            Some(existing) => {
                let before = existing.members.len();
                existing.members.extend(b.members.iter().cloned());
                existing.members.len() != before
            }
            None => {
                if b.members.is_empty() {
                    return false;
                }
                self.bindings.push(b.clone());
                true
            }
        }
    }

    /// True if every (role, condition, member) in `self` is present in `other`.
    pub fn is_subset_of(&self, other: &IamPolicy) -> bool {
        self.bindings.iter().all(|b| {
            other
                .bindings
                .iter()
                .find(|o| o.role == b.role && o.condition == b.condition)
                .is_some_and(|o| b.members.is_subset(&o.members))
        })
    }

    pub fn flatten(&self) -> BTreeSet<GrantKey> {
        self.bindings
            .iter()
            .flat_map(|b| {
                b.members.iter().map(|m| GrantKey {
                    member: m.clone(),
                    role: b.role.clone(),
                    condition: b.condition.clone(),
                })
            })
            .collect()
    }
}

/// One (member, role, condition) grant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GrantKey {
    pub member: String,
    pub role: RoleName,
    pub condition: Option<Condition>,
}

/// A grant together with where it was inherited from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveGrant {
    pub grant: GrantKey,
    pub from: Resource,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EffectiveIam {
    pub grants: Vec<EffectiveGrant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RoleStage {
    Alpha,
    Beta,
    Ga,
    Deprecated,
    Disabled,
    Eap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomRole {
    pub name: RoleName,
    pub title: String,
    #[serde(default)]
    pub description: String,
    pub permissions: BTreeSet<String>,
    pub stage: RoleStage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenyRule {
    pub denied_principals: BTreeSet<String>,
    pub denied_permissions: BTreeSet<String>,
    pub exception_principals: BTreeSet<String>,
    pub has_condition: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenyPolicy {
    pub name: String,
    pub attached_to: Resource,
    pub rules: Vec<DenyRule>,
}

// ------------------------------------------------------------- org policy

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Boolean constraint: `Some(true)` = enforced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforce: Option<bool>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub allowed_values: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub denied_values: BTreeSet<String>,
    #[serde(default)]
    pub allow_all: bool,
    #[serde(default)]
    pub deny_all: bool,
    /// CEL condition; reported, never evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgPolicy {
    pub constraint: String,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    #[serde(default)]
    pub inherit_from_parent: bool,
    #[serde(default)]
    pub reset: bool,
    #[serde(default)]
    pub etag: String,
}

impl OrgPolicy {
    pub fn empty(constraint: impl Into<String>) -> Self {
        Self {
            constraint: constraint.into(),
            rules: vec![],
            inherit_from_parent: false,
            reset: false,
            etag: String::new(),
        }
    }

    /// Unconditional allowed values across rules.
    pub fn allowed_values(&self) -> BTreeSet<&str> {
        self.rules
            .iter()
            .filter(|r| r.condition.is_none())
            .flat_map(|r| r.allowed_values.iter().map(String::as_str))
            .collect()
    }

    /// Add `value` to the unconditional allowed list. Returns whether it changed.
    pub fn allow_value(&mut self, value: &str) -> bool {
        self.reset = false;
        if self
            .rules
            .iter()
            .any(|r| r.condition.is_none() && r.allow_all)
        {
            return false;
        }
        match self
            .rules
            .iter_mut()
            .find(|r| r.condition.is_none() && r.enforce.is_none() && !r.deny_all)
        {
            Some(rule) => rule.allowed_values.insert(value.to_string()),
            None => {
                self.rules.push(PolicyRule {
                    allowed_values: BTreeSet::from([value.to_string()]),
                    ..Default::default()
                });
                true
            }
        }
    }

    pub fn allows(&self, value: &str) -> bool {
        self.rules
            .iter()
            .filter(|r| r.condition.is_none())
            .any(|r| r.allow_all || r.allowed_values.contains(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallPolicy {
    pub name: String,
    pub attached_to: Resource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedVpcLink {
    pub host: ProjectId,
    pub service: ProjectId,
}

// ------------------------------------------------------------ move analysis

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisLevel {
    Blocker,
    Warning,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalysisItem {
    pub level: AnalysisLevel,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MoveAnalysis {
    pub items: Vec<AnalysisItem>,
}

impl MoveAnalysis {
    pub fn of(&self, level: AnalysisLevel) -> impl Iterator<Item = &AnalysisItem> {
        self.items.iter().filter(move |i| i.level == level)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(role: &str, members: &[&str]) -> Binding {
        Binding {
            role: RoleName::new(role),
            members: members.iter().map(|s| s.to_string()).collect(),
            condition: None,
        }
    }

    #[test]
    fn add_binding_merges_and_never_removes() {
        let mut p = IamPolicy {
            bindings: vec![b("roles/viewer", &["user:a@x.com"])],
            etag: "e".into(),
        };
        assert!(p.add_binding(&b("roles/viewer", &["user:b@x.com"])));
        assert!(!p.add_binding(&b("roles/viewer", &["user:b@x.com"])));
        assert!(p.add_binding(&b("roles/editor", &["user:a@x.com"])));
        assert_eq!(p.bindings[0].members.len(), 2);
    }

    #[test]
    fn conditions_keep_bindings_separate() {
        let mut cond = b("roles/viewer", &["user:a@x.com"]);
        cond.condition = Some(Condition {
            title: "t".into(),
            description: String::new(),
            expression: "true".into(),
        });
        let mut p = IamPolicy::default();
        p.add_binding(&b("roles/viewer", &["user:a@x.com"]));
        p.add_binding(&cond);
        assert_eq!(p.bindings.len(), 2);
    }

    #[test]
    fn org_policy_allow_value() {
        let mut p = OrgPolicy::empty("constraints/resourcemanager.allowedExportDestinations");
        assert!(p.allow_value("under:organizations/2"));
        assert!(!p.allow_value("under:organizations/2"));
        assert!(p.allows("under:organizations/2"));
        assert!(!p.allows("under:organizations/3"));
    }
}
