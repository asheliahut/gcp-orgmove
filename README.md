# gcp-orgmove

Move Google Cloud projects from one organization to another, with preflight
analysis, IAM and policy parity checks, resumable batch execution,
verification and rollback.

The move itself is one API call (`projects.move`). Everything around it is where
migrations go wrong: the export/import org-policy constraints, access that a
project silently loses when it stops inheriting from its old folders, bindings
to organization-level custom roles that stop resolving, Shared VPC, and VPC
Service Controls. `gcp-orgmove` turns that into **plan → fix → apply → verify**:

```
init → discover → plan → parity fix → apply → verify → parity verify → (parity prune)
                                                  └────────── rollback ──────────┘
```

It is written in Rust and talks to Google Cloud through the official
[google-cloud-rust](https://github.com/googleapis/google-cloud-rust) SDK
(`reqwest` only for Cloud Identity Groups, which the SDK doesn't cover).

> **Status:** feature-complete against the design spec and tested against an
> in-memory fake and recorded HTTP mocks. It has **not** yet been run against real
> organizations; do that on disposable projects first (see [docs/e2e.md](docs/e2e.md)).

## Install

Download a release archive (Linux, macOS) from the GitHub releases page and verify it
with the matching `.sha256` file, or build from source. `gcp-orgmove --version`
prints the version and git commit. The crates are not published to crates.io.

## Build

```sh
cargo build --release          # binary: target/release/gcp-orgmove
cargo test --workspace
```

Requires a recent stable Rust toolchain (see `rust-toolchain.toml`).

## Quick start

```sh
gcloud auth application-default login          # or --token-source gcloud|env
gcp-orgmove init --source-org 111111111111 --destination-org 222222222222
$EDITOR orgmove.yaml                           # set default_destination_folder, parity options
gcp-orgmove discover --write-manifest          # or list projects: by hand / selection
gcp-orgmove plan                               # read-only; writes orgmove.plan.json
gcp-orgmove parity fix --yes                   # grant missing access on each project first
gcp-orgmove apply                              # dry run: prints exactly what would happen
gcp-orgmove apply --yes                        # sets constraints, moves, restores constraints
gcp-orgmove verify --wait 10m
gcp-orgmove parity verify
gcp-orgmove parity prune --yes                 # optional: remove access that is now redundant
```

Mutating commands (`parity fix`, `apply`, `rollback`, `parity prune`) show what
they would do first:

| How you run it | What happens |
|---|---|
| at a terminal, no flags | prints the preview, then **asks** `[y/N]` (`rollback` and `parity prune` need the full word `yes`) |
| `--yes` | executes without asking |
| `--dry-run` | previews only, never asks (wins over `--yes`) |
| in a script, with `-q`, or with `--format json`, no `--yes` | previews only (nothing could answer or see the preview) |

Declining prints `Aborted; nothing was changed.` and exits 0. Long steps draw
progress bars on stderr (hidden when stderr isn't a terminal, with `-q`, or
with `--format json`, so stdout stays clean).

## Walkthrough: a full migration

The same steps as the quick start, with what to check at each one. Try it on
disposable projects first ([docs/e2e.md](docs/e2e.md)). Files live in the current
directory: `orgmove.yaml` (you edit), `orgmove.plan.json` and
`orgmove.state.json` (the tool writes; keep the state file until you are done,
since `rollback` needs it).

**1. Authenticate and create the manifest.**

```sh
gcloud auth application-default login
gcp-orgmove init --source-org 111111111111 --destination-org 222222222222
```

Confirms you can read both organizations and writes `orgmove.yaml`.

**2. Choose what to move.** Edit `orgmove.yaml`: set `default_destination_folder`,
then list projects by hand or let the tool find them.

```sh
gcp-orgmove discover                     # just list candidates
gcp-orgmove discover --write-manifest    # add them to `projects:` (comments kept)
```

Optional but worthwhile: `parity.principals_to_probe` and
`critical_permissions` (checked after the move), and `smoke_tests`
([manifest reference](docs/manifest.md)).

**3. Plan.** Read-only; changes nothing in GCP.

```sh
gcp-orgmove plan
```

Read the output. **Blockers** (exit 4) must be fixed, then re-run `plan`; they are
usually a missing permission, a VPC-SC perimeter, or half of a Shared VPC.
**Gaps** are access or policy the project would lose; step 4 handles them.
Re-check anytime with `gcp-orgmove status --findings`.

**4. Close the gaps before moving.** Project-level access travels with the project,
so grant what is missing *on the project first*.

```sh
gcp-orgmove parity fix          # previews, then asks
```

For org-policy gaps, either change the destination policy deliberately or accept an
expiring override (`--policy-fix project-override --allow-policy-overrides`). For
custom roles set `parity.custom_roles: recreate` in the manifest (then re-run
`plan`). A gap you have reviewed can be listed under `parity.accept`.
Run `gcp-orgmove parity check` to confirm nothing is left.

**5. Apply.** Sets the export/import constraints, runs smoke tests, moves projects
in batches, and restores the constraints.

```sh
gcp-orgmove apply               # shows every action, then asks
```

If it is interrupted or some projects fail, fix the cause and run `apply` again: it
resumes ([recovery runbook](docs/recovery.md)). A smoke-test failure stops the run
and prints the exact `rollback` command.

**6. Verify.**

```sh
gcp-orgmove verify --wait 10m   # parent, organization, lifecycle, constraints restored
gcp-orgmove parity verify       # access and permissions survived; smoke tests pass
```

**7. Clean up (optional, after a soak period).** Remove access that is now redundant,
such as old bindings to source-org custom roles.

```sh
gcp-orgmove parity prune --older-than 7d
```

**If something is wrong at any point after step 5:**

```sh
gcp-orgmove rollback --all                          # moves projects back
gcp-orgmove rollback --all --revert-remediations    # ...and undoes what the tool added
```

Use `--yes` on any mutating command to skip the question, for example in automation.

## Different logins for the source and destination orgs

If you sign in differently to each organization, give each side its own login. Swap
nothing by hand: the tool uses the right one for each call.

```sh
gcp-orgmove --source-auth gcloud:alice@source.example \
            --destination-auth adc:/keys/dest-admin.json \
            --move-as source \
            plan
```

| Spec | Login comes from |
|---|---|
| `adc` | Application Default Credentials |
| `adc:<file>` | that credentials JSON (service account key, `gcloud auth application-default login` file, external-account or impersonated config) |
| `gcloud` / `gcloud:<account>` | the active gcloud account / `gcloud auth print-access-token --account=<account>` |
| `env` / `env:<VAR>` | the token in `GCP_ORGMOVE_TOKEN` / `$VAR` |

`--token-source` is the default for both sides; `--source-auth` and
`--destination-auth` override one side. Each side can also have its own billing
project (`--source-quota-project`, `--destination-quota-project`, falling back to
`--quota-project`). Give the same flags to every command (for example `apply`,
`verify`, `rollback`). Tokens are never stored.

**Which login does what**

- Anything in the source organization (its projects, folders, org policy, IAM, custom
  roles, perimeters) uses the **source** login; anything in the destination
  organization uses the **destination** login. The tool works out which is which and
  remembers it, so a project is read with the destination login once it has moved.
- The constraints are set with the matching login: the export constraint on the
  source org with the source login, the import constraint on the destination org
  with the destination login.
- **The move itself is one API call made by one login, and Google checks that login
  on both sides** (move on the project, create on the landing parent). `--move-as
  source|destination` chooses which login makes it; that login must hold
  `roles/resourcemanager.projectMover` on the project and
  `roles/resourcemanager.projectCreator` on the destination parent. `plan` checks
  exactly this and tells you what is missing. `analyze_move` and rollback moves use
  the same login.

When both logins are the same, nothing is routed and behavior is identical to
the single-login flow above. If a call fails on both logins, the error names both.

## Commands

| Command | What it does | Mutates GCP |
|---|---|---|
| `init` | Check authentication, write a starter manifest | no |
| `discover` | List candidate projects; `--write-manifest` merges them in (comments preserved) | no |
| `plan` | Preflight + parity checks; writes the plan file. Exit 4 if blockers | no |
| `parity check` | Recompute parity findings against live state | no |
| `parity fix` | Apply additive remediations (IAM grants, custom roles, policy overrides) | yes |
| `apply` | Set constraints, run smoke tests, move in batches, restore constraints | yes |
| `verify` | Parent, organization, lifecycle, constraints restored | no |
| `parity verify` | Effective-IAM diff, permission probes, `after` smoke tests | no |
| `parity prune` | Remove access that `parity fix` added and is now redundant | yes |
| `rollback` | Move projects back; `--revert-remediations` undoes what the tool added | yes |
| `status` | Per-project state, findings, overrides, smoke results, pending cleanup | no |

Global options: `--manifest`, `--plan`, `--state`, `--concurrency` (1–16),
`--format table|json`, `--token-source adc|gcloud|env`, `--quota-project`,
`--yes`, `--dry-run`, `-q`, `-v/-vv`, `--no-color`. `--format json` prints one
versioned document (`schema_version`) per command.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Unexpected error (for example another run holds the state lock) |
| 2 | Invalid usage, manifest or plan file |
| 3 | Authentication or permission failure |
| 4 | Plan contains blockers or unresolved gaps; nothing was changed |
| 5 | Plan is stale or the project parents drifted; re-run `plan` |
| 6 | Partial failure; some projects failed (see `status`) |
| 7 | Smoke test failed; the batch was halted |

## Documentation

- [Manifest reference](docs/manifest.md)
- [Provisioning access to both orgs](docs/provisioning-access.md): who needs which roles, with `gcloud` commands, time-limited grants and cleanup
- [Required permissions and APIs](docs/permissions.md)
- [Safety model](docs/safety.md)
- [Recovery runbook](docs/recovery.md) — crashed runs, stuck constraints, partial failures
- [Known limitations](docs/limitations.md)
- [End-to-end test runbook](docs/e2e.md)
- [Design decisions](docs/decisions/0001-spec-clarifications.md)
