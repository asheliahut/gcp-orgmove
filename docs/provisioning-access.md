# Provisioning access for a migration

A project move is one API call made by **one identity**, and Google checks that
identity on **both** sides. So before you run anything, someone has to be allowed
to act in both organizations. This page shows how to set that up with the least
privilege that works, how to scope it to the migration window, and how to take it
away afterwards.

> The `gcloud` commands below are illustrative. Role contents and org-policy
> behavior change, so confirm them against the current
> [project migration checklist](https://cloud.google.com/resource-manager/docs/project-migration-checklist)
> and with `gcloud iam roles describe <role>` before relying on them. `gcp-orgmove plan`
> is the real test: it reports each missing permission as a blocker and names the role.

## What has to be true

| Who | Where | Role | Why |
|---|---|---|---|
| The **mover** | the project being moved (or its folder/org) | `roles/resourcemanager.projectMover` | `resourcemanager.projects.move` |
| The **mover** | the destination folder or org | `roles/resourcemanager.projectCreator` | `resourcemanager.projects.create` on the landing parent |
| Whoever sets the source constraint | source org | `roles/orgpolicy.policyAdmin` | `allowedExportDestinations` |
| Whoever sets the destination constraint | destination org | `roles/orgpolicy.policyAdmin` | `allowedImportSources` |
| Whoever runs `plan`/`verify` | both orgs | `roles/iam.securityReviewer` (read) | IAM, org policy, deny and firewall policy reads |
| Whoever runs `parity fix` | the projects (or their folder) | a role with `resourcemanager.projects.setIamPolicy` | adding the missing access |
| Whoever recreates custom roles | destination org | `roles/iam.organizationRoleAdmin` | only with `custom_roles: recreate` |
| Whoever calls `analyzeMove` | the project | a role with `cloudasset.assets.analyzeMove` | move analysis |

With one identity that holds all of this in both orgs you use a single login. With
two identities, the **mover** is the one that must hold the cross-org rows; the other
login only needs the rows for its own org. Use `--move-as source|destination` to
say which login is the mover.

## Pick a pattern

### A. One migration identity (simplest)

Create one identity that exists in both orgs' IAM and give it the table above. You
use it for everything and need no per-org flags.

- **A service account** is the usual choice: create it in a project in either org, then
  grant it roles in both. Prefer short-lived impersonation over a downloaded key.
- **One person's account** works too if that person is trusted in both orgs.

### B. Two people, two logins

Each person keeps their own account; one of them is the mover.

1. The org owners agree who the mover is.
2. The other org's admin grants the mover the cross-org rows (below). The mover's
   login becomes an *external member* of that org.
3. Each person runs the tool with their own login for their own side:

```sh
gcp-orgmove --source-auth gcloud:alice@source.example \
            --destination-auth gcloud:bob@dest.example \
            --move-as source \
            plan
```

Alice (source admin) is the mover here, so Bob's org must have granted
`alice@source.example` the destination-side roles. Bob's login is then only used
for destination-org policy and reads. If you would rather Bob be the mover, grant him
the source-side roles and use `--move-as destination`.

## Step by step

Replace the `SRC_`/`DST_` values. Run each command as an admin of the org named in the
heading.

### 1. In the destination org (a destination admin runs this)

Let the mover create projects under the landing parent. Scope it to the landing
folder rather than the whole org:

```sh
gcloud resource-manager folders add-iam-policy-binding DST_FOLDER_ID \
  --member="user:alice@source.example" \
  --role="roles/resourcemanager.projectCreator"
```

If projects land at the org root, grant it on the org instead:

```sh
gcloud organizations add-iam-policy-binding DST_ORG_ID \
  --member="user:alice@source.example" \
  --role="roles/resourcemanager.projectCreator"
```

Whoever sets the import constraint needs `roles/orgpolicy.policyAdmin` on this org
(a destination admin already has it, or grant it to your migration identity the same way).
Read access for `plan`:

```sh
gcloud organizations add-iam-policy-binding DST_ORG_ID \
  --member="user:alice@source.example" \
  --role="roles/iam.securityReviewer"
```

### 2. In the source org (a source admin runs this)

Let the mover move the project. Per project is the tightest scope:

```sh
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="user:alice@source.example" \
  --role="roles/resourcemanager.projectMover"
```

For many projects, grant it on the folder that contains them instead:

```sh
gcloud resource-manager folders add-iam-policy-binding SRC_FOLDER_ID \
  --member="user:alice@source.example" \
  --role="roles/resourcemanager.projectMover"
```

The org-policy and read roles for the source side go the same way
(`roles/orgpolicy.policyAdmin`, `roles/iam.securityReviewer` on `SRC_ORG_ID` via
`gcloud organizations add-iam-policy-binding`).

### 3. Make the migration window temporary

Add an IAM condition so access expires on its own:

```sh
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="user:alice@source.example" \
  --role="roles/resourcemanager.projectMover" \
  --condition='expression=request.time < timestamp("2026-12-01T00:00:00Z"),title=migration-window'
```

Keep the window long enough to cover the whole **soak period**: `rollback` needs the
mover's rights again, and so does moving anything back.

### 4. If adding the outside identity is refused

Adding a member from another organization can fail with a policy error. That is the
`constraints/iam.allowedPolicyMemberDomains` organization policy, which restricts
who may appear in IAM bindings to listed Cloud Identity customer IDs.

- Ask the org-policy admin of the org that refuses to add the *other* org's customer
  ID (it looks like `C0xxxxxxx`) to that constraint, for the duration of the
  migration only.
- Find a customer ID with `gcloud organizations list`
  (the `DIRECTORY_CUSTOMER_ID` column).
- Remove it again when you are done (see below). `gcp-orgmove plan` also reports this
  under `principal-domains`, because the same restriction would later block
  `parity fix` from re-granting someone's access.

A service account owned by a project in the *refusing* org is allowed without any
policy change, which is one reason to prefer pattern A with a service account created
there.

### 5. Authenticate as each identity

| You have | Use |
|---|---|
| a person already signed in with gcloud | `--source-auth gcloud` / `gcloud:alice@source.example` |
| a person, with a dedicated ADC file | `gcloud auth application-default login`, then `adc:<file>` pointing at the saved JSON |
| a service account (preferred: impersonation) | `gcloud auth application-default login --impersonate-service-account=SA_EMAIL`, then `adc:<file>` |
| a service account key file | `adc:/path/key.json` (treat the key as a secret and delete it after) |
| a token from a secrets system | `env:SOURCE_TOKEN` / `env:DEST_TOKEN` |

Then see who the tool thinks you are:

```sh
gcp-orgmove --source-auth ... --destination-auth ... init \
  --source-org SRC_ORG_ID --destination-org DST_ORG_ID
```

`init` prints each principal and checks that each login can read its own org.

### 6. Let the tool check the grants

```sh
gcp-orgmove plan
```

Anything still missing shows up as a **blocker** that names the permission, the
resource and the role that grants it, for example `missing permission
resourcemanager.projects.create on folders/123; grant roles/resourcemanager.projectCreator`.
Grant it, re-run `plan`, and repeat until there are no permission blockers.

## Cleanup afterwards

Do this only after `verify`, `parity verify` and your soak period, since `rollback`
depends on the mover's access.

1. Remove the mover's bindings in both orgs, for example
   `gcloud projects remove-iam-policy-binding PROJECT_ID --member=... --role=roles/resourcemanager.projectMover`
   (and the folder/org bindings you added; conditional bindings must be removed with the
   same `--condition`).
2. Remove any customer ID you added to `iam.allowedPolicyMemberDomains`.
3. Delete service account keys; disable or delete the migration service account.
4. Confirm `gcp-orgmove status` shows no pending constraint cleanup (the export and
   import constraints are restored by `apply` itself).
5. `gcp-orgmove parity prune` removes access that `parity fix` added and the
   destination now covers; it is separate from removing the migration identity.

## Quick checklist

- [ ] One login (or the chosen `--move-as` login) holds `projectMover` on the project and `projectCreator` on the landing parent.
- [ ] Someone with `orgpolicy.policyAdmin` on each org will be signed in for `apply`.
- [ ] `iam.allowedPolicyMemberDomains` allows the identities involved (or you have a plan for it).
- [ ] Access is time-limited and covers the soak period.
- [ ] `gcp-orgmove plan` shows no permission blockers.
- [ ] You know how and when each grant will be removed.
