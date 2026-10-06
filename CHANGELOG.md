# Changelog

All notable changes are recorded here. This project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Complete `plan → parity fix → apply → verify → parity verify → parity prune` workflow and `rollback`.
- Preflight: permissions, export/import constraints (including lower-level overrides),
  `analyzeMove`, Shared VPC grouping, VPC-SC membership.
- Parity checks: `inherited-iam`, `custom-roles`, `org-policy`, `deny-policies`,
  `firewall-policies`, `principal-domains`, `groups`, `org-scoped`.
- Additive-only remediation executor (project/folder IAM grants, recreated custom
  roles, consent-gated policy overrides with expiry and audit label).
- Resumable, idempotent `apply` with a constraint guard that restores on success,
  error, panic and interrupt, and repairs a crashed run.
- Smoke tests (`before`/`after`), `verify`, `parity verify` (IAM diff, Policy
  Troubleshooter probes), `rollback --revert-remediations`.
- Built on the official `google-cloud-rust` SDK; `reqwest` for Cloud Identity Groups.
- Stable `--format json` output (`schema_version` 1) and exit codes 0–7.

### Added (interactive UX)

- Progress bars (indicatif) for `plan`, `parity check`/`fix`/`verify`/`prune`, `apply`,
  `verify` and `rollback`, drawn on stderr and hidden for non-terminals, `-q` and `--format json`.
- Interactive confirmation for `apply`, `rollback`, `parity fix` and `parity prune`:
  preview first, then ask; destructive and access-widening steps require typing `yes`.
  `--yes` skips the prompt; `--dry-run` never prompts.

### Added (per-organization authentication)

- Separate logins for the source and destination organizations:
  `--source-auth`, `--destination-auth` (`adc[:file]`, `gcloud[:account]`,
  `env[:VAR]`), per-side quota projects, and `--move-as source|destination` to choose
  which login performs `projects.move`.
- `RealGcp` keeps one SDK client set per login and routes each call to the login that
  owns the resource, learning ownership and seeding it from the manifest.
- The permission preflight now asks the right identity: move and create permissions as
  the mover, org-policy and role permissions as the owning organization's login.
- New `Gcp::test_move_permissions`.

### Notes

- Not yet exercised against real organizations; see `docs/e2e.md`.
- Linux and macOS are supported; Windows is untested (smoke tests need `sh`).
- Distributed as release binaries, not published to crates.io.
