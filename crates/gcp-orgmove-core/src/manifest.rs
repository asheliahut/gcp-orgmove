//! Manifest (user-authored YAML input, §4.1): strict parsing and validation.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::ids::*;

/// A duration written as `10s`, `5m`, `24h` or `30d`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanDuration(pub Duration);

impl FromStr for HumanDuration {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        let (num, unit) = s.split_at(split);
        let n: u64 = num.parse().map_err(|_| {
            Error::invalid(format!(
                "invalid duration {s:?}: expected e.g. 30s, 5m, 24h, 30d"
            ))
        })?;
        let mult = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3600,
            "d" => 86_400,
            _ => {
                return Err(Error::invalid(format!(
                    "invalid duration {s:?}: unit must be s, m, h or d"
                )))
            }
        };
        Ok(HumanDuration(Duration::from_secs(n.saturating_mul(mult))))
    }
}

impl fmt::Display for HumanDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.0.as_secs();
        if s != 0 && s % 86_400 == 0 {
            write!(f, "{}d", s / 86_400)
        } else if s != 0 && s % 3600 == 0 {
            write!(f, "{}h", s / 3600)
        } else if s != 0 && s % 60 == 0 {
            write!(f, "{}m", s / 60)
        } else {
            write!(f, "{s}s")
        }
    }
}

impl Serialize for HumanDuration {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}
impl<'de> Deserialize<'de> for HumanDuration {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IamFixMode {
    Off,
    #[default]
    Project,
    Folder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyFixMode {
    #[default]
    Off,
    ProjectOverride,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CustomRoleMode {
    #[default]
    Off,
    Recreate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectEntry {
    pub id: ProjectId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_folder: Option<FolderId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    #[serde(default)]
    pub source_folders: Vec<FolderId>,
    #[serde(default)]
    pub exclude_labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub name: String,
    pub projects: Vec<ProjectId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedFinding {
    pub finding: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParityConfig {
    #[serde(default)]
    pub iam_fix: IamFixMode,
    #[serde(default)]
    pub policy_fix: PolicyFixMode,
    #[serde(default)]
    pub custom_roles: CustomRoleMode,
    #[serde(default = "default_override_expiry")]
    pub override_expiry: HumanDuration,
    #[serde(default)]
    pub principals_to_probe: Vec<String>,
    #[serde(default)]
    pub critical_permissions: Vec<String>,
    #[serde(default)]
    pub ignore_constraints: Vec<String>,
    #[serde(default)]
    pub accept: Vec<AcceptedFinding>,
}

fn default_override_expiry() -> HumanDuration {
    HumanDuration(Duration::from_secs(30 * 86_400))
}

impl Default for ParityConfig {
    fn default() -> Self {
        Self {
            iam_fix: IamFixMode::default(),
            policy_fix: PolicyFixMode::default(),
            custom_roles: CustomRoleMode::default(),
            override_expiry: default_override_expiry(),
            principals_to_probe: vec![],
            critical_permissions: vec![],
            ignore_constraints: vec![],
            accept: vec![],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmokePhase {
    Before,
    After,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmokeTest {
    pub name: String,
    pub run: String,
    #[serde(default = "default_smoke_timeout")]
    pub timeout: HumanDuration,
    #[serde(default = "default_phases")]
    pub phase: Vec<SmokePhase>,
}

fn default_smoke_timeout() -> HumanDuration {
    HumanDuration(Duration::from_secs(10))
}
fn default_phases() -> Vec<SmokePhase> {
    vec![SmokePhase::Before, SmokePhase::After]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_plan_max_age")]
    pub plan_max_age: HumanDuration,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
}

fn default_plan_max_age() -> HumanDuration {
    HumanDuration(Duration::from_secs(24 * 3600))
}
fn default_batch_size() -> usize {
    10
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            plan_max_age: default_plan_max_age(),
            batch_size: default_batch_size(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub source_org: OrgId,
    pub destination_org: OrgId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_destination_folder: Option<FolderId>,
    #[serde(default)]
    pub projects: Vec<ProjectEntry>,
    #[serde(default)]
    pub selection: Selection,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    pub parity: ParityConfig,
    #[serde(default)]
    pub smoke_tests: Vec<SmokeTest>,
    #[serde(default)]
    pub limits: Limits,
}

/// A parsed manifest and the hash of the exact bytes it came from.
#[derive(Debug, Clone)]
pub struct LoadedManifest {
    pub manifest: Manifest,
    pub sha256: String,
}

impl Manifest {
    /// Parse and validate. Errors carry the YAML line/column where available.
    pub fn parse(text: &str) -> Result<LoadedManifest> {
        let manifest: Manifest = serde_yaml::from_str(text).map_err(|e| {
            let loc = e
                .location()
                .map(|l| format!(" (line {}, column {})", l.line(), l.column()))
                .unwrap_or_default();
            Error::invalid(format!(
                "manifest: {}{loc}",
                e.to_string().split(" at line").next().unwrap_or("")
            ))
        })?;
        manifest.validate()?;
        let sha256 = hex(&Sha256::digest(text.as_bytes()));
        Ok(LoadedManifest { manifest, sha256 })
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(Error::invalid(format!(
                "manifest: unsupported version {}",
                self.version
            )));
        }
        if self.source_org == self.destination_org {
            return Err(Error::invalid(
                "manifest: source_org and destination_org must differ",
            ));
        }

        let mut seen = BTreeSet::new();
        for p in &self.projects {
            if !seen.insert(&p.id) {
                return Err(Error::invalid(format!(
                    "manifest: duplicate project {:?} in projects",
                    p.id.as_str()
                )));
            }
        }

        let mut in_group: BTreeMap<&ProjectId, &str> = BTreeMap::new();
        let mut names = BTreeSet::new();
        for g in &self.groups {
            if !names.insert(g.name.as_str()) {
                return Err(Error::invalid(format!(
                    "manifest: duplicate group name {:?}",
                    g.name
                )));
            }
            if g.projects.is_empty() {
                return Err(Error::invalid(format!(
                    "manifest: group {:?} is empty",
                    g.name
                )));
            }
            if g.projects.len() > self.limits.batch_size {
                return Err(Error::invalid(format!(
                    "manifest: group {:?} has {} projects but limits.batch_size is {}; a group cannot be split",
                    g.name,
                    g.projects.len(),
                    self.limits.batch_size
                )));
            }
            for p in &g.projects {
                if let Some(other) = in_group.insert(p, &g.name) {
                    return Err(Error::invalid(format!(
                        "manifest: project {:?} appears in groups {other:?} and {:?}",
                        p.as_str(),
                        g.name
                    )));
                }
            }
        }

        if self.limits.batch_size == 0 {
            return Err(Error::invalid(
                "manifest: limits.batch_size must be at least 1",
            ));
        }
        if self.projects.is_empty() && self.selection.source_folders.is_empty() {
            return Err(Error::invalid(
                "manifest: no projects: add `projects` or `selection.source_folders`",
            ));
        }
        Ok(())
    }

    /// Landing parent for an explicit project entry: entry override, then the
    /// default folder, then the destination organization root.
    pub fn landing_parent(&self, entry_folder: Option<&FolderId>) -> Parent {
        match entry_folder.or(self.default_destination_folder.as_ref()) {
            Some(f) => Parent::Folder(f.clone()),
            None => Parent::Org(self.destination_org.clone()),
        }
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
version: 1
source_org: "111111111111"
destination_org: "222222222222"
default_destination_folder: "333333333333"
projects:
  - id: my-app-prod
    destination_folder: "444444444444"
  - id: my-app-dev
groups:
  - name: shared-vpc-1
    projects: [net-host, app-svc-a, app-svc-b]
parity:
  iam_fix: project
  policy_fix: off
  custom_roles: recreate
  override_expiry: 30d
smoke_tests:
  - name: api-health
    run: "true"
    timeout: 10s
    phase: [before, after]
limits:
  plan_max_age: 24h
  batch_size: 10
"#;

    fn err(text: &str) -> String {
        Manifest::parse(text).unwrap_err().message
    }

    #[test]
    fn parses_valid_manifest() {
        let m = Manifest::parse(VALID).unwrap();
        assert_eq!(m.sha256.len(), 64);
        assert_eq!(m.manifest.parity.custom_roles, CustomRoleMode::Recreate);
        assert_eq!(
            m.manifest.limits.plan_max_age.0,
            Duration::from_secs(86_400)
        );
    }

    #[test]
    fn landing_parent_precedence() {
        let m = Manifest::parse(VALID).unwrap().manifest;
        let own: FolderId = "444444444444".parse().unwrap();
        assert_eq!(
            m.landing_parent(Some(&own)).to_string(),
            "folders/444444444444"
        );
        assert_eq!(m.landing_parent(None).to_string(), "folders/333333333333");
        let mut m2 = m.clone();
        m2.default_destination_folder = None;
        assert_eq!(
            m2.landing_parent(None).to_string(),
            "organizations/222222222222"
        );
    }

    #[test]
    fn rejects_unknown_keys() {
        let t = VALID.replace("version: 1", "version: 1\nbogus: true");
        assert!(err(&t).contains("unknown field"), "{}", err(&t));
    }

    #[test]
    fn rejects_same_orgs_and_non_numeric() {
        assert!(err(&VALID.replace("222222222222", "111111111111")).contains("must differ"));
        assert!(err(&VALID.replace("\"111111111111\"", "\"org-1\"")).contains("numeric"));
    }

    #[test]
    fn rejects_duplicates() {
        let t = VALID.replace("  - id: my-app-dev", "  - id: my-app-prod");
        assert!(err(&t).contains("duplicate project"));
        let t = VALID.replace(
            "groups:",
            "groups:\n  - name: other\n    projects: [net-host]",
        );
        assert!(err(&t).contains("appears in groups"));
    }

    #[test]
    fn rejects_group_larger_than_batch() {
        assert!(err(&VALID.replace("batch_size: 10", "batch_size: 2")).contains("cannot be split"));
    }

    #[test]
    fn rejects_bad_durations_and_enums() {
        assert!(err(&VALID.replace("24h", "24x")).contains("duration"));
        assert!(
            err(&VALID.replace("iam_fix: project", "iam_fix: everywhere"))
                .contains("unknown variant")
        );
    }

    #[test]
    fn duration_roundtrip() {
        for s in ["10s", "5m", "36h", "30d"] {
            assert_eq!(s.parse::<HumanDuration>().unwrap().to_string(), s);
        }
    }

    #[test]
    fn error_has_line_number() {
        let t = VALID.replace("version: 1", "version: one");
        assert!(err(&t).contains("line"), "{}", err(&t));
    }
}
