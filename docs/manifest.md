# Manifest reference

`orgmove.yaml` is user-authored input. Parsing is **strict**: unknown keys are an
error, and errors name the line. `plan` records the manifest's SHA-256; `apply`
refuses a plan made from a different manifest (exit 5), so any edit means
re-planning.

```yaml
version: 1                                  # required, must be 1

source_org: "111111111111"                  # required, numeric
destination_org: "222222222222"             # required, numeric, must differ
default_destination_folder: "333333333333"  # optional; omit to land at the org root

projects:                                   # explicit projects
  - id: my-app-prod
    destination_folder: "444444444444"      # overrides the default
  - id: my-app-dev

selection:                                  # in addition to `projects`
  source_folders: ["555555555555"]          # every ACTIVE project under these folders
  exclude_labels: { migrate: "false" }      # skip projects with any of these labels

groups:                                     # projects that must move together
  - name: shared-vpc-1
    projects: [net-host, app-svc-a, app-svc-b]

parity:
  iam_fix: project                # off | project | folder            (default project)
  policy_fix: off                 # off | project-override            (default off)
  custom_roles: off               # off | recreate                    (default off)
  override_expiry: 30d            # for policy overrides
  principals_to_probe:            # for `parity verify`
    - serviceAccount:deployer@my-app-prod.iam.gserviceaccount.com
  critical_permissions: [compute.instances.get, storage.objects.get]
  ignore_constraints: [constraints/compute.requireOsLogin]
  accept:                         # gaps you reviewed and accept
    - finding: "F-0123456789ab"
      reason: "covered by group access in the destination"

smoke_tests:
  - name: api-health
    run: "curl -fsS https://my-app.example.com/healthz"
    timeout: 10s                  # default 10s
    phase: [before, after]        # default both

limits:
  plan_max_age: 24h               # apply refuses an older plan (default 24h)
  batch_size: 10                  # max projects per batch (default 10)
```

Durations are `<n>s`, `<n>m`, `<n>h` or `<n>d`.

## Rules

- A project listed explicitly wins over a `selection` match (its folder override applies).
- Duplicate project IDs in `projects`, or a project in two groups, are errors.
- A group larger than `limits.batch_size` is rejected: a group is never split.
- Members of a manifest `group` that aren't otherwise listed are pulled in
  automatically.
- A Shared VPC host and its service projects are grouped automatically when
  **both sides are in the migration**. If only one side is, the other is a
  blocker (add it to the manifest, or detach it first). `plan --skip shared-vpc`
  turns detection off.

## Parity options

- `iam_fix: project` grants each missing role **on the project** (precise).
  `folder` grants on the landing folder instead, which gives that access to
  every project in the folder, so it also needs `--yes-widen-access`. It never
  widens to the whole organization.
- `custom_roles: recreate` lets `parity fix` create `organizations/<DEST>/roles/*`
  equivalents and add bindings to them. The old bindings stay until `parity prune`.
  With `off`, the gaps are reported and `apply` stays blocked until you accept them.
- `policy_fix: project-override` is only half of the consent: `parity fix` also
  needs `--allow-policy-overrides`. Overrides copy the project's current
  effective policy, expire after `override_expiry`, and set the project label
  `orgmove-override-exp=YYYYMMDD` (the earliest expiry) for auditing.
- `accept` takes finding IDs from `plan`/`status --findings`. IDs are stable
  across plans (a hash of project, check and subject).

## Smoke tests

Shell commands run with `sh -c` in your environment (minus `GCP_ORGMOVE_TOKEN`).
They also get `ORGMOVE_PROJECT` and `ORGMOVE_PHASE`. Exit 0 passes. A `before`
failure stops the run before anything moves; an `after` failure stops the batch
and exits 7 with the exact `rollback` command. A timed-out test's whole process
group is killed. Results are stored in the state file and shown by `status`.
