//! Validated identifiers and resource names.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, ErrorKind};

fn invalid(what: &str, input: &str, why: &str) -> Error {
    Error::new(
        ErrorKind::InvalidInput,
        format!("invalid {what} {input:?}: {why}"),
    )
}

fn is_numeric_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit())
}

macro_rules! numeric_id {
    ($(#[$m:meta])* $name:ident, $what:literal) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str { &self.0 }
        }
        impl FromStr for $name {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self, Error> {
                if is_numeric_id(s) { Ok(Self(s.to_string())) }
                else { Err(invalid($what, s, "must be a numeric ID")) }
            }
        }
        impl TryFrom<String> for $name {
            type Error = Error;
            fn try_from(s: String) -> Result<Self, Error> { s.parse() }
        }
        impl From<$name> for String {
            fn from(v: $name) -> String { v.0 }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
        }
    };
}

numeric_id!(
    /// Numeric organization ID, e.g. `111111111111`.
    OrgId, "organization ID");
numeric_id!(
    /// Numeric folder ID.
    FolderId, "folder ID");
numeric_id!(
    /// Numeric project number.
    ProjectNumber, "project number");

/// User-chosen project ID: 6-30 chars, lowercase letters, digits, hyphens;
/// starts with a letter, does not end with a hyphen.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProjectId(String);

impl ProjectId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ProjectId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let b = s.as_bytes();
        let ok = (6..=30).contains(&b.len())
            && b[0].is_ascii_lowercase()
            && b[b.len() - 1] != b'-'
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-');
        if ok {
            Ok(Self(s.to_string()))
        } else {
            Err(invalid(
                "project ID",
                s,
                "must be 6-30 chars of [a-z0-9-], start with a letter, not end with '-'",
            ))
        }
    }
}
impl TryFrom<String> for ProjectId {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Error> {
        s.parse()
    }
}
impl From<ProjectId> for String {
    fn from(v: ProjectId) -> String {
        v.0
    }
}
impl fmt::Display for ProjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A resource hierarchy parent: an organization or a folder.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Parent {
    Org(OrgId),
    Folder(FolderId),
}

impl FromStr for Parent {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        if let Some(id) = s.strip_prefix("organizations/") {
            Ok(Parent::Org(id.parse()?))
        } else if let Some(id) = s.strip_prefix("folders/") {
            Ok(Parent::Folder(id.parse()?))
        } else {
            Err(invalid(
                "parent",
                s,
                "expected organizations/<id> or folders/<id>",
            ))
        }
    }
}
impl TryFrom<String> for Parent {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Error> {
        s.parse()
    }
}
impl From<Parent> for String {
    fn from(v: Parent) -> String {
        v.to_string()
    }
}
impl fmt::Display for Parent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Parent::Org(o) => write!(f, "organizations/{o}"),
            Parent::Folder(o) => write!(f, "folders/{o}"),
        }
    }
}

/// Any resource that carries IAM or org policy.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Resource {
    Org(OrgId),
    Folder(FolderId),
    /// Referenced by project ID (the form used by Resource Manager v1 IAM).
    Project(ProjectId),
}

/// Org policy attach point. Same shape as [`Resource`].
pub type Scope = Resource;

impl Resource {
    pub fn from_parent(p: &Parent) -> Self {
        match p {
            Parent::Org(o) => Resource::Org(o.clone()),
            Parent::Folder(f) => Resource::Folder(f.clone()),
        }
    }
}

impl FromStr for Resource {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        if let Some(id) = s.strip_prefix("projects/") {
            Ok(Resource::Project(id.parse()?))
        } else {
            Parent::from_str(s).map(|p| Resource::from_parent(&p))
        }
    }
}
impl TryFrom<String> for Resource {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Error> {
        s.parse()
    }
}
impl From<Resource> for String {
    fn from(v: Resource) -> String {
        v.to_string()
    }
}
impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Resource::Org(o) => write!(f, "organizations/{o}"),
            Resource::Folder(o) => write!(f, "folders/{o}"),
            Resource::Project(o) => write!(f, "projects/{o}"),
        }
    }
}

/// A role name: predefined (`roles/x`), org custom (`organizations/N/roles/x`),
/// or project custom (`projects/P/roles/x`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RoleName(String);

impl RoleName {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// If this is an organization custom role, its org and short name.
    pub fn org_custom(&self) -> Option<(OrgId, &str)> {
        let rest = self.0.strip_prefix("organizations/")?;
        let (org, role) = rest.split_once("/roles/")?;
        Some((org.parse().ok()?, role))
    }
    /// The same custom role re-homed under another organization.
    pub fn rehomed(&self, dest: &OrgId) -> Option<RoleName> {
        let (_, role) = self.org_custom()?;
        Some(RoleName(format!("organizations/{dest}/roles/{role}")))
    }
}
impl fmt::Display for RoleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn org_id_validation() {
        assert!("111111111111".parse::<OrgId>().is_ok());
        assert!("".parse::<OrgId>().is_err());
        assert!("12a".parse::<OrgId>().is_err());
        assert!("organizations/1".parse::<OrgId>().is_err());
    }

    #[test]
    fn project_id_validation() {
        assert!("my-app-prod".parse::<ProjectId>().is_ok());
        for bad in [
            "short",
            "1starts-digit",
            "ends-hyphen-",
            "Upper-case",
            "has_underscore",
        ] {
            assert!(bad.parse::<ProjectId>().is_err(), "{bad}");
        }
    }

    #[test]
    fn custom_role_rehome() {
        let r = RoleName::new("organizations/111/roles/deployer");
        assert_eq!(r.org_custom().unwrap().1, "deployer");
        let dest: OrgId = "222".parse().unwrap();
        assert_eq!(
            r.rehomed(&dest).unwrap().as_str(),
            "organizations/222/roles/deployer"
        );
        assert!(RoleName::new("roles/viewer").org_custom().is_none());
    }

    proptest! {
        #[test]
        fn parent_roundtrip(id in "[0-9]{1,15}", folder in any::<bool>()) {
            let s = if folder { format!("folders/{id}") } else { format!("organizations/{id}") };
            let p: Parent = s.parse().unwrap();
            prop_assert_eq!(p.to_string(), s);
        }

        #[test]
        fn resource_roundtrip(id in "[a-z][a-z0-9-]{4,28}[a-z0-9]") {
            let s = format!("projects/{id}");
            let r: Resource = s.parse().unwrap();
            prop_assert_eq!(r.to_string(), s);
        }

        #[test]
        fn project_id_serde_roundtrip(id in "[a-z][a-z0-9-]{4,28}[a-z0-9]") {
            let p: ProjectId = id.parse().unwrap();
            let j = serde_json::to_string(&p).unwrap();
            let back: ProjectId = serde_json::from_str(&j).unwrap();
            prop_assert_eq!(p, back);
        }
    }
}
