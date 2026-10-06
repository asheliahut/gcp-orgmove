//! Plan file (generated, reviewed; §4.2). Serialization is deterministic.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorKind, Result};
use crate::finding::{Finding, Remediation, Severity};
use crate::ids::*;

pub const PLAN_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyChange {
    pub scope: Scope,
    pub constraint: String,
    /// Always `allow-value` today.
    pub action: String,
    pub value: String,
    pub backup_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Analysis {
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
    pub info: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanProject {
    pub id: ProjectId,
    pub number: ProjectNumber,
    pub current_parent: Parent,
    pub landing_parent: Parent,
    pub group: Option<String>,
    pub analysis: Analysis,
    pub findings: Vec<Finding>,
    pub remediations: Vec<Remediation>,
    pub live_parent_at_plan_time: Parent,
    pub etag: String,
}

impl PlanProject {
    pub fn has_blocker(&self) -> bool {
        !self.analysis.blockers.is_empty()
            || self
                .findings
                .iter()
                .any(|f| f.severity == Severity::Blocker)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Summary {
    pub projects: usize,
    pub blockers: usize,
    pub gaps: usize,
    pub warnings: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub version: u32,
    pub generated_at: DateTime<Utc>,
    pub manifest_sha256: String,
    pub source_org: OrgId,
    pub destination_org: OrgId,
    pub policy_changes: Vec<PolicyChange>,
    pub projects: Vec<PlanProject>,
    /// Batches run sequentially; members of a batch may move concurrently.
    pub order: Vec<Vec<ProjectId>>,
    pub summary: Summary,
}

impl Plan {
    /// Sort everything into canonical order and recompute the summary.
    /// Call before serializing so output is byte-identical for equal inputs.
    pub fn normalize(&mut self) {
        self.projects.sort_by(|a, b| a.id.cmp(&b.id));
        for p in &mut self.projects {
            p.findings.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
            p.findings.dedup_by(|a, b| a.id == b.id);
            let mut rems: Vec<Remediation> = p
                .findings
                .iter()
                .filter_map(|f| f.remediation.clone())
                .collect();
            rems.dedup();
            p.remediations = rems;
        }
        self.policy_changes.sort_by(|a, b| {
            (&a.scope, &a.constraint, &a.value).cmp(&(&b.scope, &b.constraint, &b.value))
        });
        self.summary = self.compute_summary();
    }

    fn compute_summary(&self) -> Summary {
        let mut s = Summary {
            projects: self.projects.len(),
            ..Default::default()
        };
        for p in &self.projects {
            s.blockers += p.analysis.blockers.len()
                + p.findings
                    .iter()
                    .filter(|f| f.severity == Severity::Blocker)
                    .count();
            s.gaps += p
                .findings
                .iter()
                .filter(|f| f.severity == Severity::Gap)
                .count();
            s.warnings += p.analysis.warnings.len()
                + p.findings
                    .iter()
                    .filter(|f| f.severity == Severity::Warning)
                    .count();
        }
        s
    }

    pub fn project(&self, id: &ProjectId) -> Option<&PlanProject> {
        self.projects.iter().find(|p| &p.id == id)
    }

    pub fn has_blockers(&self) -> bool {
        self.projects.iter().any(PlanProject::has_blocker)
    }

    /// Pretty JSON with a trailing newline.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>> {
        let mut b = serde_json::to_vec_pretty(self)?;
        b.push(b'\n');
        Ok(b)
    }

    pub fn from_json_bytes(b: &[u8]) -> Result<Plan> {
        let plan: Plan = serde_json::from_slice(b)
            .map_err(|e| Error::invalid(format!("plan file is invalid: {e}")))?;
        if plan.version != PLAN_VERSION {
            return Err(Error::invalid(format!(
                "plan version {} is not supported (expected {PLAN_VERSION}); re-run `gcp-orgmove plan`",
                plan.version
            )));
        }
        Ok(plan)
    }

    pub fn load(path: &Path) -> Result<Plan> {
        let b = std::fs::read(path).map_err(|e| {
            Error::new(
                ErrorKind::InvalidInput,
                format!("cannot read plan {}: {e}", path.display()),
            )
            .with_hint("run `gcp-orgmove plan` first")
        })?;
        Self::from_json_bytes(&b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Category;

    fn pid(s: &str) -> ProjectId {
        s.parse().unwrap()
    }

    fn sample(ts: &str) -> Plan {
        let mk = |id: &str| PlanProject {
            id: pid(id),
            number: "123456789".parse().unwrap(),
            current_parent: "folders/1".parse().unwrap(),
            landing_parent: "folders/444444444444".parse().unwrap(),
            group: None,
            analysis: Analysis::default(),
            findings: vec![
                Finding::new(
                    pid(id),
                    "inherited-iam",
                    Category::Iam,
                    Severity::Warning,
                    "b",
                    "w",
                ),
                Finding::new(
                    pid(id),
                    "inherited-iam",
                    Category::Iam,
                    Severity::Gap,
                    "a",
                    "g",
                ),
            ],
            remediations: vec![],
            live_parent_at_plan_time: "folders/1".parse().unwrap(),
            etag: "e".into(),
        };
        let mut p = Plan {
            version: PLAN_VERSION,
            generated_at: ts.parse().unwrap(),
            manifest_sha256: "abc".into(),
            source_org: "111111111111".parse().unwrap(),
            destination_org: "222222222222".parse().unwrap(),
            policy_changes: vec![],
            // deliberately unsorted
            projects: vec![mk("my-app-prod"), mk("my-app-dev")],
            order: vec![vec![pid("my-app-dev")], vec![pid("my-app-prod")]],
            summary: Summary::default(),
        };
        p.normalize();
        p
    }

    #[test]
    fn deterministic_bytes_except_generated_at() {
        let a = sample("2026-10-05T12:00:00Z");
        let b = sample("2026-10-06T08:30:00Z");
        let (ja, jb) = (a.to_json_bytes().unwrap(), b.to_json_bytes().unwrap());
        let mask = |bytes: &[u8]| {
            String::from_utf8(bytes.to_vec())
                .unwrap()
                .lines()
                .filter(|l| !l.contains("generated_at"))
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(mask(&ja), mask(&jb));
        assert_eq!(ja, sample("2026-10-05T12:00:00Z").to_json_bytes().unwrap());
        assert!(ja.ends_with(b"\n"));
    }

    #[test]
    fn normalize_sorts_and_summarizes() {
        let p = sample("2026-10-05T12:00:00Z");
        assert_eq!(p.projects[0].id.as_str(), "my-app-dev");
        assert_eq!(p.projects[0].findings[0].severity, Severity::Gap);
        assert_eq!(
            p.summary,
            Summary {
                projects: 2,
                blockers: 0,
                gaps: 2,
                warnings: 2
            }
        );
    }

    #[test]
    fn roundtrip_and_version_check() {
        let p = sample("2026-10-05T12:00:00Z");
        let back = Plan::from_json_bytes(&p.to_json_bytes().unwrap()).unwrap();
        assert_eq!(back, p);
        let bad = String::from_utf8(p.to_json_bytes().unwrap())
            .unwrap()
            .replace("\"version\": 1", "\"version\": 9");
        assert_eq!(
            Plan::from_json_bytes(bad.as_bytes())
                .unwrap_err()
                .exit_code(),
            2
        );
        assert_eq!(Plan::from_json_bytes(b"{").unwrap_err().exit_code(), 2);
    }

    #[test]
    fn json_snapshot() {
        insta::assert_snapshot!(String::from_utf8(
            sample("2026-10-05T12:00:00Z").to_json_bytes().unwrap()
        )
        .unwrap());
    }
}
