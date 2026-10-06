# Required permissions and APIs

`plan` calls `testIamPermissions` for what it needs and reports each missing
permission as a **blocker that names the role**, so you can run it first and see
exactly what to grant. Roles can be split across people. Always check the current
[Google migration checklist](https://cloud.google.com/resource-manager/docs/project-migration-checklist)
because required permissions change.

| Where | Role(s) | Used for |
|---|---|---|
| Each source project and its parent | Project Mover (`roles/resourcemanager.projectMover`) | `projects.move` |
| Destination folder / org | Project Creator (`roles/resourcemanager.projectCreator`) | landing a project |
| Source and destination orgs | Organization Policy Administrator (`roles/orgpolicy.policyAdmin`) | setting the export/import constraints (only when a change is needed) |
| Source and destination | A read role such as Security Reviewer (`roles/iam.securityReviewer`) | IAM, org policy, deny/firewall policy reads |
| Destination org, if `custom_roles: recreate` | Organization Role Administrator (`roles/iam.organizationRoleAdmin`) | creating recreated roles |
| Projects/folders being fixed | `resourcemanager.projects.setIamPolicy` / `folders.setIamPolicy` | `parity fix` / `prune` |
| Projects (policy overrides) | `orgpolicy.policies.create/update`, `resourcemanager.projects.update` | overrides and their audit label |
| Cloud Asset | `cloudasset.assets.analyzeMove` | `analyzeMove` |
| Source org (VPC-SC) | Access Context Manager reader | perimeter membership |
| Source org (log sinks, tags, feeds) | read access to sinks, tag bindings, asset feeds | `org-scoped` checklist |

## APIs to enable on the quota project

Cloud Resource Manager, Cloud Asset, Organization Policy, IAM, IAM Policy
Troubleshooter (for `parity verify` probes), Access Context Manager, Compute
Engine (Shared VPC and hierarchical firewall policies), Cloud Logging, and
Cloud Identity (group checks). Pass the project with `--quota-project`.

Optional APIs degrade gracefully where it is safe: the `groups` check reports
"could not be checked" as an Info finding, and Policy Troubleshooter probes fall
back to the effective-IAM diff. Other checks that cannot run become **blockers**
with a hint to fix the cause or pass `--skip <check>`, because "unknown" is not safe.

## Two logins

For step-by-step grants (including time-limited access and cleanup) see
[provisioning-access.md](provisioning-access.md).

The source and destination organizations may use different logins
(`--source-auth`, `--destination-auth`; see the [README](../README.md#different-logins-for-the-source-and-destination-orgs)).
Who needs what:

| Login | Needs |
|---|---|
| **Source** | read and, for `parity fix`, write on the source projects and their folders/org; Organization Policy Administrator on the source org (export constraint); read on perimeters and sinks |
| **Destination** | Organization Policy Administrator on the destination org (import constraint); read on the landing folder's hierarchy (IAM, policy, deny and firewall policies); Organization Role Administrator if `custom_roles: recreate` |
| **The mover** (`--move-as`) | **both**: `roles/resourcemanager.projectMover` on each project (and its source parent) **and** `roles/resourcemanager.projectCreator` on the landing parent in the destination org. A login that belongs to only one organization cannot move a project; add it as an external member of the other org, or use one identity that is trusted in both |

After a move the project belongs to the destination org, so verification and
anything done to the project afterwards (`verify`, `parity verify`, `rollback`'s
IAM changes) uses the destination login; the source login may no longer see it.

## Authentication

| `--token-source` | Behavior |
|---|---|
| `adc` (default) | Application Default Credentials via the official SDK (service account, workload identity, `gcloud auth application-default login`) |
| `adc:<file>` | A specific credentials JSON of type `service_account`, `authorized_user`, `external_account` or `impersonated_service_account` |
| `gcloud` / `gcloud:<account>` | Runs `gcloud auth print-access-token [--account=<account>]`, refreshed every 30 minutes |
| `env` / `env:<VAR>` | Reads `GCP_ORGMOVE_TOKEN` / `$VAR` |

Tokens are never written to disk or logged, and are scrubbed from smoke-test
environments. The migration spans two organizations, so the principal must be
trusted in both (for example added as an external user in the source org).
