# End-to-end tests against real organizations

Everything else in the test suite uses an in-memory fake or recorded HTTP mocks.
This opt-in test is the only one that touches real Google Cloud, and it is how
you should gain confidence before a real migration.

> **It temporarily changes organization policy** (the export/import constraints
> on both orgs, restored afterwards) and creates and deletes projects. Use two
> disposable test organizations, never production.

## Prerequisites

- Two test organizations, and a principal trusted in both.
- `gcloud` installed and authenticated as that principal, with
  `gcloud auth application-default login` done (or pass credentials another way).
- The roles in [permissions.md](permissions.md): Project Creator on the source org,
  Project Mover, Organization Policy Administrator on both orgs, and the read roles.
- The APIs from [permissions.md](permissions.md) enabled on the quota project.

## Run

```sh
export GCP_ORGMOVE_E2E=1
export E2E_SOURCE_ORG=111111111111
export E2E_DEST_ORG=222222222222
export E2E_DEST_FOLDER=333333333333        # optional
export E2E_QUOTA_PROJECT=my-quota-project   # optional

cargo test -p gcp-orgmove-cli --test e2e -- --ignored --nocapture
```

Without `GCP_ORGMOVE_E2E=1` the test returns immediately, even with `--ignored`.

## What it does

1. Creates two projects under the source org with `gcloud projects create`.
2. Writes a manifest and runs the **real binary**: `plan` → `parity fix --yes` →
   `apply --yes` → `verify --wait 10m` → `parity verify`.
3. Asserts both projects are now under the destination.
4. `rollback --all --yes`, then asserts both are back under the source org.
5. Always deletes the projects (a `Drop` guard), even if an assertion fails. If
   cleanup itself fails, it prints the project IDs.

## CI

`.github/workflows/e2e.yml` runs this manually (`workflow_dispatch`) with
secrets for the two orgs. It is never triggered by pushes.

## Extending it

Good additions once you have real orgs: a Shared VPC host with a service
project, a project bound to an org custom role (`custom_roles: recreate`), a
destination folder with a stricter org policy, and an `after` smoke test.
