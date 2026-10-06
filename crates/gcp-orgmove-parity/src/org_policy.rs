//! `org-policy` check (report-only): where the destination's effective
//! organization policy is stricter than what the project lives under today.
//!
//! Project-level policies travel with the project; folder and organization
//! policies do not. Both sides are computed the same way, client-side, from
//! the directly-set policies along each chain, so they are comparable:
//! source = source org → folders → project, destination = destination org →
//! landing folders → project. Conditional rules are reported, never evaluated.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use gcp_orgmove_core::{
    Category, CheckCtx, Finding, Gcp, OrgPolicy, Parent, ParityCheck, Remediation, Resource,
    Result, Severity, EXPORT_CONSTRAINT, IMPORT_CONSTRAINT,
};
use tokio::sync::Mutex;

use crate::effective::landing_chain;

pub const ID: &str = "org-policy";

/// Directly-set policies per resource, keyed by constraint.
type Direct = BTreeMap<String, OrgPolicy>;

#[derive(Default)]
pub struct OrgPolicyCheck {
    cache: Mutex<BTreeMap<Resource, Arc<Direct>>>,
}

impl OrgPolicyCheck {
    async fn direct(&self, gcp: &dyn Gcp, r: &Resource) -> Result<Arc<Direct>> {
        if let Some(hit) = self.cache.lock().await.get(r) {
            return Ok(hit.clone());
        }
        let map: Direct = gcp
            .list_policies(r)
            .await?
            .into_iter()
            .map(|p| (p.constraint.clone(), p))
            .collect();
        let map = Arc::new(map);
        self.cache.lock().await.insert(r.clone(), map.clone());
        Ok(map)
    }
}

/// Merge policies from the root down to the leaf into the effective policy.
pub fn merge_chain(constraint: &str, root_to_leaf: &[Option<&OrgPolicy>]) -> OrgPolicy {
    let mut eff = OrgPolicy::empty(constraint);
    for p in root_to_leaf.iter().flatten() {
        if p.reset {
            eff = OrgPolicy::empty(constraint);
        } else if p.inherit_from_parent {
            eff.rules.extend(p.rules.iter().cloned());
        } else {
            eff = (*p).clone();
        }
    }
    eff.etag.clear();
    eff.inherit_from_parent = false;
    eff.reset = false;
    eff
}

/// An effective policy flattened for comparison.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Summary {
    pub enforced: bool,
    pub allow_all: bool,
    pub deny_all: bool,
    pub allowed: BTreeSet<String>,
    pub denied: BTreeSet<String>,
    /// Conditional rules, serialized, so they can be compared but not evaluated.
    pub conditional: BTreeSet<String>,
}

impl Summary {
    pub fn of(p: &OrgPolicy) -> Self {
        let mut s = Summary::default();
        for r in &p.rules {
            if let Some(c) = &r.condition {
                s.conditional.insert(format!("{c} => {r:?}"));
                continue;
            }
            s.enforced |= r.enforce == Some(true);
            s.allow_all |= r.allow_all;
            s.deny_all |= r.deny_all;
            s.allowed.extend(r.allowed_values.iter().cloned());
            s.denied.extend(r.denied_values.iter().cloned());
        }
        s
    }

    fn restricts_allowed(&self) -> bool {
        !self.allow_all && (self.deny_all || !self.allowed.is_empty())
    }
}

/// Reasons the destination is stricter than the source (empty = not stricter).
pub fn stricter(src: &Summary, dst: &Summary) -> Vec<String> {
    let mut why = vec![];
    if dst.enforced && !src.enforced {
        why.push("enforced at the destination but not at the source".to_string());
    }
    if dst.deny_all && !src.deny_all {
        why.push("denies all values at the destination".to_string());
    }
    if dst.restricts_allowed() && !dst.deny_all {
        if !src.restricts_allowed() {
            why.push(format!("destination only allows {}", join(&dst.allowed)));
        } else {
            let missing: BTreeSet<String> = src.allowed.difference(&dst.allowed).cloned().collect();
            if !missing.is_empty() {
                why.push(format!("destination does not allow {}", join(&missing)));
            }
        }
    }
    let extra: BTreeSet<String> = dst.denied.difference(&src.denied).cloned().collect();
    if !extra.is_empty() {
        why.push(format!("destination additionally denies {}", join(&extra)));
    }
    why
}

fn join(s: &BTreeSet<String>) -> String {
    s.iter().cloned().collect::<Vec<_>>().join(", ")
}

fn is_tool_managed(c: &str) -> bool {
    c == EXPORT_CONSTRAINT || c == IMPORT_CONSTRAINT
}

#[async_trait]
impl ParityCheck for OrgPolicyCheck {
    fn id(&self) -> &'static str {
        ID
    }

    async fn run(&self, ctx: &CheckCtx, gcp: &dyn Gcp) -> Result<Vec<Finding>> {
        let me = Resource::Project(ctx.project.id.clone());
        // root → leaf, ending with the project itself (its own policies travel).
        let mut source_chain: Vec<Resource> = gcp
            .get_ancestry(&ctx.project.id)
            .await?
            .iter()
            .map(Resource::from_parent)
            .collect();
        source_chain.reverse();
        let mut dest_chain: Vec<Resource> = landing_chain(gcp, &ctx.landing_parent).await?;
        dest_chain.reverse();
        source_chain.push(me.clone());
        dest_chain.push(me.clone());

        let mut src_direct = vec![];
        for r in &source_chain {
            src_direct.push(self.direct(gcp, r).await?);
        }
        let mut dst_direct = vec![];
        for r in &dest_chain {
            dst_direct.push(self.direct(gcp, r).await?);
        }

        let ignored: BTreeSet<&str> = ctx
            .manifest
            .parity
            .ignore_constraints
            .iter()
            .map(String::as_str)
            .collect();
        let constraints: BTreeSet<&String> = src_direct
            .iter()
            .chain(dst_direct.iter())
            .flat_map(|d| d.keys())
            .collect();

        let mut out = vec![];
        for c in constraints {
            if ignored.contains(c.as_str()) || is_tool_managed(c) {
                continue;
            }
            let pick = |ds: &[Arc<Direct>]| -> OrgPolicy {
                let ps: Vec<Option<&OrgPolicy>> = ds.iter().map(|d| d.get(c)).collect();
                merge_chain(c, &ps)
            };
            let (src_eff, dst_eff) = (pick(&src_direct), pick(&dst_direct));
            let (src, dst) = (Summary::of(&src_eff), Summary::of(&dst_eff));
            let reasons = stricter(&src, &dst);
            let dest_scope = match &ctx.landing_parent {
                Parent::Org(o) => format!("organizations/{o}"),
                Parent::Folder(f) => format!("folders/{f}"),
            };
            if !reasons.is_empty() {
                let mut f = Finding::new(
                    ctx.project.id.clone(),
                    ID,
                    Category::OrgPolicy,
                    Severity::Gap,
                    c,
                    format!(
                        "{c} is stricter under {dest_scope}: {}. Preferred fix: change the destination policy deliberately; alternative: a time-limited project override (`parity fix --policy-fix project-override --allow-policy-overrides`)",
                        reasons.join("; ")
                    ),
                );
                // Override = the policy the project has today. Expiry is filled in at fix time.
                f = f.with_remediation(Remediation::SetPolicyOverride {
                    project: ctx.project.id.clone(),
                    policy: src_eff,
                    expires: String::new(),
                });
                out.push(f);
            } else if src.conditional != dst.conditional {
                out.push(Finding::new(
                    ctx.project.id.clone(),
                    ID,
                    Category::OrgPolicy,
                    Severity::Warning,
                    &format!("conditional|{c}"),
                    format!("{c} has conditional rules that differ between source and destination; conditions are not evaluated, review manually"),
                ));
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
    use gcp_orgmove_core::{Manifest, PolicyRule, Project};

    fn enforce(c: &str, on: bool) -> OrgPolicy {
        let mut p = OrgPolicy::empty(c);
        p.rules.push(PolicyRule {
            enforce: Some(on),
            ..Default::default()
        });
        p
    }

    fn allowed(c: &str, vals: &[&str]) -> OrgPolicy {
        let mut p = OrgPolicy::empty(c);
        for v in vals {
            p.allow_value(v);
        }
        p
    }

    #[test]
    fn merge_semantics() {
        let a = allowed("c", &["x"]);
        let mut b = allowed("c", &["y"]);
        assert_eq!(
            Summary::of(&merge_chain("c", &[Some(&a), Some(&b)])).allowed,
            ["y".to_string()].into(),
            "replace"
        );
        b.inherit_from_parent = true;
        assert_eq!(
            Summary::of(&merge_chain("c", &[Some(&a), Some(&b)]))
                .allowed
                .len(),
            2,
            "inherit unions"
        );
        let mut r = OrgPolicy::empty("c");
        r.reset = true;
        assert!(
            merge_chain("c", &[Some(&a), Some(&r)]).rules.is_empty(),
            "reset clears"
        );
        assert!(merge_chain("c", &[None, None]).rules.is_empty());
        assert_eq!(
            Summary::of(&merge_chain("c", &[Some(&a), None]))
                .allowed
                .len(),
            1,
            "gaps in the chain inherit"
        );
    }

    #[test]
    fn stricter_booleans() {
        let on = Summary::of(&enforce("c", true));
        let off = Summary::of(&enforce("c", false));
        assert!(!stricter(&off, &on).is_empty());
        assert!(stricter(&on, &off).is_empty(), "relaxing is not a gap");
        assert!(stricter(&on, &on).is_empty());
        assert!(stricter(&Summary::default(), &off).is_empty());
    }

    #[test]
    fn stricter_lists() {
        let s = |v: &[&str]| Summary::of(&allowed("c", v));
        assert!(
            !stricter(&Summary::default(), &s(&["a"])).is_empty(),
            "unrestricted -> restricted"
        );
        assert!(!stricter(&s(&["a", "b"]), &s(&["a"])).is_empty());
        assert!(
            stricter(&s(&["a"]), &s(&["a", "b"])).is_empty(),
            "wider allow-list is fine"
        );
        let mut allow_all = OrgPolicy::empty("c");
        allow_all.rules.push(PolicyRule {
            allow_all: true,
            ..Default::default()
        });
        assert!(!stricter(&Summary::of(&allow_all), &s(&["a"])).is_empty());
        let mut deny_all = OrgPolicy::empty("c");
        deny_all.rules.push(PolicyRule {
            deny_all: true,
            ..Default::default()
        });
        assert!(stricter(&s(&["a"]), &Summary::of(&deny_all))
            .iter()
            .any(|r| r.contains("denies all")));
        let mut denied = OrgPolicy::empty("c");
        denied.rules.push(PolicyRule {
            denied_values: ["bad".to_string()].into(),
            ..Default::default()
        });
        assert!(stricter(&Summary::default(), &Summary::of(&denied))[0]
            .contains("additionally denies bad"));
    }

    fn setup(ignore: &str) -> (FakeGcp, CheckCtx) {
        let f = FakeGcp::new();
        f.org("111").org("222");
        f.folder("10", "organizations/111");
        f.folder("20", "organizations/222");
        f.project("proj-aaaa", "1001", "folders/10");
        let m = Manifest::parse(&format!(
            "version: 1\nsource_org: \"111\"\ndestination_org: \"222\"\nprojects:\n  - id: proj-aaaa\n{ignore}"
        ))
        .unwrap()
        .manifest;
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

    async fn run(f: &FakeGcp, ctx: &CheckCtx) -> Vec<Finding> {
        OrgPolicyCheck::default().run(ctx, f).await.unwrap()
    }

    #[tokio::test]
    async fn stricter_destination_is_a_gap_with_an_override_remediation() {
        let (f, ctx) = setup("");
        f.policy(
            "organizations/222",
            enforce("constraints/compute.requireOsLogin", true),
        );
        let fs = run(&f, &ctx).await;
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].severity, Severity::Gap);
        assert!(fs[0].summary.contains("enforced at the destination"));
        assert!(fs[0].summary.contains("folders/20"));
        assert!(fs[0].summary.contains("Preferred fix"));
        match fs[0].remediation.as_ref().unwrap() {
            Remediation::SetPolicyOverride {
                project,
                policy,
                expires,
            } => {
                assert_eq!(project.as_str(), "proj-aaaa");
                assert_eq!(policy.constraint, "constraints/compute.requireOsLogin");
                assert!(
                    expires.is_empty(),
                    "expiry is decided at fix time so plans stay deterministic"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn same_policy_on_both_sides_is_quiet() {
        let (f, ctx) = setup("");
        f.policy(
            "organizations/111",
            enforce("constraints/compute.requireOsLogin", true),
        );
        f.policy(
            "organizations/222",
            enforce("constraints/compute.requireOsLogin", true),
        );
        assert!(run(&f, &ctx).await.is_empty());
    }

    #[tokio::test]
    async fn a_policy_set_on_the_project_travels_and_masks_the_destination() {
        let (f, ctx) = setup("");
        f.policy(
            "organizations/222",
            enforce("constraints/compute.requireOsLogin", true),
        );
        f.policy(
            "projects/proj-aaaa",
            enforce("constraints/compute.requireOsLogin", false),
        );
        assert!(
            run(&f, &ctx).await.is_empty(),
            "the project's own non-inheriting policy wins at the destination too"
        );
    }

    #[tokio::test]
    async fn relaxed_destination_and_ignored_constraints_are_quiet() {
        let (f, ctx) =
            setup("parity:\n  ignore_constraints: [\"constraints/compute.requireOsLogin\"]\n");
        f.policy(
            "organizations/111",
            enforce("constraints/iam.disableServiceAccountKeyCreation", true),
        );
        f.policy(
            "organizations/222",
            enforce("constraints/compute.requireOsLogin", true),
        );
        assert!(run(&f, &ctx).await.is_empty());
    }

    #[tokio::test]
    async fn tool_managed_constraints_are_never_reported() {
        let (f, ctx) = setup("");
        f.allow_moves("111", "222");
        let mut deny = OrgPolicy::empty(IMPORT_CONSTRAINT);
        deny.allow_value("under:organizations/999");
        f.policy("organizations/222", deny);
        assert!(run(&f, &ctx).await.is_empty());
    }

    #[tokio::test]
    async fn differing_conditional_rules_are_a_warning_not_a_gap() {
        let (f, ctx) = setup("");
        let mut p = OrgPolicy::empty("constraints/compute.vmExternalIpAccess");
        p.rules.push(PolicyRule {
            condition: Some("resource.matchTag('env','dev')".into()),
            enforce: Some(true),
            ..Default::default()
        });
        f.policy("organizations/222", p);
        let fs = run(&f, &ctx).await;
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].severity, Severity::Warning);
        assert!(fs[0].remediation.is_none());
    }

    #[tokio::test]
    async fn list_constraint_allowing_less_is_a_gap() {
        let (f, ctx) = setup("");
        f.policy(
            "organizations/111",
            allowed(
                "constraints/gcp.resourceLocations",
                &["in:us-locations", "in:eu-locations"],
            ),
        );
        f.policy(
            "organizations/222",
            allowed("constraints/gcp.resourceLocations", &["in:us-locations"]),
        );
        let fs = run(&f, &ctx).await;
        assert_eq!(fs.len(), 1);
        assert!(
            fs[0].summary.contains("does not allow in:eu-locations"),
            "{}",
            fs[0].summary
        );
    }
}
