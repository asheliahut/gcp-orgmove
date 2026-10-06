//! Conversions between SDK message types and core model types.

use std::collections::BTreeSet;

use gcp_orgmove_core::{Binding, Condition, IamPolicy, RoleName};
use google_cloud_iam_v1::model as iam;

pub fn policy_from_sdk(p: iam::Policy) -> IamPolicy {
    IamPolicy {
        bindings: p
            .bindings
            .into_iter()
            .map(|b| Binding {
                role: RoleName::new(b.role),
                members: b.members.into_iter().collect::<BTreeSet<_>>(),
                condition: b.condition.map(|c| Condition {
                    title: c.title,
                    description: c.description,
                    expression: c.expression,
                }),
            })
            .collect(),
        etag: etag_to_string(&p.etag),
    }
}

/// Version 3 is required to read and write conditional bindings safely.
pub fn policy_to_sdk(p: &IamPolicy, original: Option<&iam::Policy>) -> iam::Policy {
    let mut out = original.cloned().unwrap_or_default();
    out.version = 3;
    out.bindings = p
        .bindings
        .iter()
        .map(|b| {
            let mut sb = iam::Binding::new()
                .set_role(b.role.as_str())
                .set_members(b.members.iter().cloned());
            if let Some(c) = &b.condition {
                sb = sb.set_condition(
                    google_cloud_type::model::Expr::new()
                        .set_title(c.title.clone())
                        .set_description(c.description.clone())
                        .set_expression(c.expression.clone()),
                );
            }
            sb
        })
        .collect();
    out.etag = etag_from_string(&p.etag);
    out
}

/// Etags are opaque bytes; we carry them as base64 so they survive JSON.
pub fn etag_to_string(b: &bytes::Bytes) -> String {
    use std::fmt::Write;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

pub fn etag_from_string(s: &str) -> bytes::Bytes {
    let raw: Vec<u8> = (0..s.len() / 2)
        .filter_map(|i| u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok())
        .collect();
    bytes::Bytes::from(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etag_roundtrips_arbitrary_bytes() {
        let b = bytes::Bytes::from(vec![0u8, 1, 0xff, 0x7f, 0x10]);
        assert_eq!(etag_from_string(&etag_to_string(&b)), b);
        assert_eq!(etag_to_string(&bytes::Bytes::new()), "");
    }

    #[test]
    fn policy_roundtrip_keeps_conditions_and_requests_v3() {
        let sdk = iam::Policy::new()
            .set_etag(bytes::Bytes::from_static(b"\x01\x02"))
            .set_bindings([iam::Binding::new()
                .set_role("roles/viewer")
                .set_members(["user:a@x.com"])
                .set_condition(
                    google_cloud_type::model::Expr::new()
                        .set_title("t")
                        .set_expression("request.time < timestamp('2030-01-01T00:00:00Z')"),
                )]);
        let core = policy_from_sdk(sdk.clone());
        assert_eq!(core.bindings[0].condition.as_ref().unwrap().title, "t");
        let back = policy_to_sdk(&core, Some(&sdk));
        assert_eq!(back.version, 3);
        assert_eq!(back.etag, sdk.etag);
        assert_eq!(back.bindings[0].role, "roles/viewer");
        assert!(back.bindings[0].condition.is_some());
    }
}

// ------------------------------------------------------------- org policy

use google_cloud_orgpolicy_v2::model as op;
use google_cloud_orgpolicy_v2::model::policy_spec::policy_rule::{Kind, StringValues};
use google_cloud_orgpolicy_v2::model::policy_spec::PolicyRule as SdkRule;
use google_cloud_orgpolicy_v2::model::PolicySpec;

use gcp_orgmove_core::{OrgPolicy, PolicyRule};

/// `constraints/x.y` -> `x.y` (the policy resource's short name).
pub fn constraint_short_name(constraint: &str) -> &str {
    constraint
        .strip_prefix("constraints/")
        .unwrap_or(constraint)
}

pub fn policy_name(scope: &gcp_orgmove_core::Scope, constraint: &str) -> String {
    format!("{scope}/policies/{}", constraint_short_name(constraint))
}

pub fn orgpolicy_from_sdk(constraint: &str, spec: Option<PolicySpec>) -> OrgPolicy {
    let Some(spec) = spec else {
        return OrgPolicy::empty(constraint);
    };
    let rules = spec
        .rules
        .into_iter()
        .map(|r| {
            let mut rule = PolicyRule {
                condition: r.condition.map(|c| c.expression),
                ..Default::default()
            };
            match r.kind {
                Some(Kind::Values(v)) => {
                    rule.allowed_values = v.allowed_values.into_iter().collect();
                    rule.denied_values = v.denied_values.into_iter().collect();
                }
                Some(Kind::AllowAll(b)) => rule.allow_all = b,
                Some(Kind::DenyAll(b)) => rule.deny_all = b,
                Some(Kind::Enforce(b)) => rule.enforce = Some(b),
                _ => {}
            }
            rule
        })
        .collect();
    OrgPolicy {
        constraint: constraint.to_string(),
        rules,
        inherit_from_parent: spec.inherit_from_parent,
        reset: spec.reset,
        etag: spec.etag,
    }
}

pub fn orgpolicy_to_sdk(name: &str, p: &OrgPolicy) -> op::Policy {
    let rules: Vec<SdkRule> = p
        .rules
        .iter()
        .map(|r| {
            let kind = if let Some(e) = r.enforce {
                Kind::Enforce(e)
            } else if r.allow_all {
                Kind::AllowAll(true)
            } else if r.deny_all {
                Kind::DenyAll(true)
            } else {
                Kind::Values(Box::new(
                    StringValues::new()
                        .set_allowed_values(r.allowed_values.iter().cloned())
                        .set_denied_values(r.denied_values.iter().cloned()),
                ))
            };
            let mut sr = SdkRule::new().set_kind(kind);
            if let Some(c) = &r.condition {
                sr = sr
                    .set_condition(google_cloud_type::model::Expr::new().set_expression(c.clone()));
            }
            sr
        })
        .collect();
    let spec = PolicySpec::new()
        .set_rules(rules)
        .set_inherit_from_parent(p.inherit_from_parent)
        .set_reset(p.reset)
        .set_etag(p.etag.clone());
    op::Policy::new().set_name(name).set_spec(spec)
}

// ------------------------------------------------------------ custom roles

use gcp_orgmove_core::{CustomRole, RoleStage};
use google_cloud_iam_admin_v1::model::role::RoleLaunchStage;

pub fn stage_from_sdk(s: &RoleLaunchStage) -> RoleStage {
    match s {
        RoleLaunchStage::Alpha => RoleStage::Alpha,
        RoleLaunchStage::Beta => RoleStage::Beta,
        RoleLaunchStage::Deprecated => RoleStage::Deprecated,
        RoleLaunchStage::Disabled => RoleStage::Disabled,
        RoleLaunchStage::Eap => RoleStage::Eap,
        _ => RoleStage::Ga,
    }
}

pub fn stage_to_sdk(s: RoleStage) -> RoleLaunchStage {
    match s {
        RoleStage::Alpha => RoleLaunchStage::Alpha,
        RoleStage::Beta => RoleLaunchStage::Beta,
        RoleStage::Ga => RoleLaunchStage::Ga,
        RoleStage::Deprecated => RoleLaunchStage::Deprecated,
        RoleStage::Disabled => RoleLaunchStage::Disabled,
        RoleStage::Eap => RoleLaunchStage::Eap,
    }
}

pub fn role_from_sdk(r: google_cloud_iam_admin_v1::model::Role) -> CustomRole {
    CustomRole {
        name: RoleName::new(r.name),
        title: r.title,
        description: r.description,
        permissions: r.included_permissions.into_iter().collect(),
        stage: stage_from_sdk(&r.stage),
    }
}

#[cfg(test)]
mod orgpolicy_tests {
    use super::*;

    #[test]
    fn short_names_and_resource_names() {
        let scope: gcp_orgmove_core::Scope = "organizations/111".parse().unwrap();
        assert_eq!(
            policy_name(
                &scope,
                "constraints/resourcemanager.allowedExportDestinations"
            ),
            "organizations/111/policies/resourcemanager.allowedExportDestinations"
        );
    }

    #[test]
    fn policy_roundtrip() {
        let mut p = OrgPolicy::empty("constraints/resourcemanager.allowedExportDestinations");
        p.allow_value("under:organizations/222");
        p.inherit_from_parent = true;
        p.etag = "e1".into();
        p.rules.push(PolicyRule {
            enforce: Some(true),
            condition: Some("resource.matchTag('a/b','c')".into()),
            ..Default::default()
        });
        let sdk = orgpolicy_to_sdk("organizations/111/policies/x", &p);
        let back = orgpolicy_from_sdk(
            "constraints/resourcemanager.allowedExportDestinations",
            sdk.spec,
        );
        assert_eq!(back, p);
    }

    #[test]
    fn missing_spec_is_an_empty_policy() {
        assert!(orgpolicy_from_sdk("constraints/x", None).rules.is_empty());
    }

    #[test]
    fn stages_roundtrip() {
        for s in [
            RoleStage::Alpha,
            RoleStage::Beta,
            RoleStage::Ga,
            RoleStage::Deprecated,
            RoleStage::Disabled,
            RoleStage::Eap,
        ] {
            assert_eq!(stage_from_sdk(&stage_to_sdk(s)), s);
        }
    }
}
