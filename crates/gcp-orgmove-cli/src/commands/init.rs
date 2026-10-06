//! `init` (§6.1): validate authentication, write a starter manifest.

use gcp_orgmove_core::state::atomic_write;
use gcp_orgmove_core::{Error, ErrorKind, OrgId, Resource, Result};
use serde_json::json;

use crate::output::Printer;
use crate::Ctx;

const TEMPLATE: &str = r#"# gcp-orgmove manifest. See `gcp-orgmove --help`.
version: 1

# Numeric organization IDs. They must differ.
source_org: "__SOURCE__"
destination_org: "__DEST__"

# Where projects land unless overridden below. Omit to land at the org root.
# default_destination_folder: "333333333333"

projects:
  # - id: my-app-prod
  #   destination_folder: "444444444444"   # overrides the default

# Projects that must move together (Shared VPC host and its service projects).
# groups:
#   - name: shared-vpc-1
#     projects: [net-host, app-svc-a]

parity:
  iam_fix: project          # off | project | folder
  policy_fix: off           # off | project-override
  custom_roles: off         # off | recreate
  override_expiry: 30d
  # principals_to_probe: ["serviceAccount:deployer@my-app-prod.iam.gserviceaccount.com"]
  # critical_permissions: ["compute.instances.get"]
  # ignore_constraints: ["constraints/compute.requireOsLogin"]
  # accept:                  # gaps you have reviewed and accept
  #   - finding: "F-0123456789ab"
  #     reason: "covered by group access in the destination"

# smoke_tests:
#   - name: api-health
#     run: "curl -fsS https://my-app.example.com/healthz"
#     timeout: 10s
#     phase: [before, after]

limits:
  plan_max_age: 24h
  batch_size: 10
"#;

pub async fn run(
    ctx: &Ctx<'_>,
    p: &mut Printer<'_>,
    source_org: Option<&str>,
    destination_org: Option<&str>,
    force: bool,
) -> Result<u8> {
    let path = &ctx.global.manifest;
    if path.exists() && !force {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("{} already exists", path.display()),
        )
        .with_hint("pass --force to overwrite it"));
    }

    let principal = (ctx.whoami)().await?;
    p.info(format!("Authenticated as {principal}"));

    for (label, org) in [("source", source_org), ("destination", destination_org)] {
        if let Some(raw) = org {
            let id: OrgId = raw.parse()?;
            let wanted = ["resourcemanager.organizations.get".to_string()];
            let granted = ctx
                .gcp
                .test_permissions(&Resource::Org(id.clone()), &wanted)
                .await?;
            if granted.is_empty() {
                return Err(Error::new(
                    ErrorKind::PermissionDenied,
                    format!("cannot read {label} organization {id} (missing resourcemanager.organizations.get)"),
                )
                .with_resource(format!("organizations/{id}"))
                .with_hint("grant a role such as roles/resourcemanager.organizationViewer"));
            }
            p.info(format!("Can read {label} organization {id}"));
        }
    }

    let text = TEMPLATE
        .replace("__SOURCE__", source_org.unwrap_or("111111111111"))
        .replace("__DEST__", destination_org.unwrap_or("222222222222"));
    atomic_write(path, text.as_bytes())?;
    p.info(format!("Wrote {}", path.display()));
    p.json("init", &json!({"principal": principal, "manifest": path}));
    Ok(0)
}
