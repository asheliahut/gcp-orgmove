//! Parity checks and the remediation executor.

pub mod custom_roles;
pub mod effective;
pub mod executor;
pub mod identity;
pub mod inherited_iam;
pub mod network;
pub mod org_policy;
pub mod org_scoped;
pub mod prune;
pub mod verify;

use gcp_orgmove_core::ParityCheck;

/// All parity checks, in the order they run. Checks are added as their
/// roadmap phase lands.
pub fn default_checks() -> Vec<Box<dyn ParityCheck>> {
    vec![
        Box::new(inherited_iam::InheritedIam::default()),
        Box::new(custom_roles::CustomRoles::default()),
        Box::new(org_policy::OrgPolicyCheck::default()),
        Box::new(network::DenyPolicies),
        Box::new(network::FirewallPolicies),
        Box::new(network::VpcSc::default()),
        Box::new(identity::PrincipalDomains),
        Box::new(identity::Groups),
        Box::new(org_scoped::OrgScoped),
    ]
}

/// IDs of every registered check (used to refresh only parity findings).
pub fn check_ids() -> Vec<&'static str> {
    default_checks().iter().map(|c| c.id()).collect()
}
