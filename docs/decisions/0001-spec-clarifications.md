# 0001 — Spec clarifications

Resolves the open questions (docket DKT-2) in the design spec.

1. **Gap acceptance.** Gaps are accepted in the manifest, so acceptance is covered by
   `manifest_sha256`: `parity.accept: [{ finding: "F-ab12cd34ef56", reason: "..." }]`.
   `apply` treats a Gap as resolved if (a) its remediation is recorded applied in state,
   or (b) its finding ID is accepted. Accepted gaps are listed by `status --findings`.
2. **Finding IDs.** `F-` + first 12 hex of `sha256(project "\0" check_id "\0" subject)`.
   `subject` is a check-defined canonical string (e.g. `member|role|condition`). Stable across plans.
3. **ParityFixed.** A project is `ParityFixed` when every auto-fixable remediation is applied.
   Findings with only `Manual` remediations must be accepted (1) before the project is `Ready`.
4. **Gcp trait additions.** `get_folder_ancestry`, `get_custom_role`, `delete_custom_role`,
   `set_project_labels`, `list_vpc_sc_perimeters`, `list_org_scoped`, `troubleshoot_access`.
5. **backup_ref.** Policy backups live inline in the state file under
   `policy_backups[<ref>]`; `ref = "policy-backups/<scope>/<constraint>"`.
6. **selection vs projects.** An explicit `projects:` entry wins over a `selection` match.
   Duplicates inside `projects:` (or a project in two groups) are errors.
7. **--dry-run / --yes.** `--dry-run` always wins. Otherwise `--yes` executes. With neither,
   mutating commands are a dry run; on a TTY the user is additionally offered a confirm prompt.
   Non-TTY without `--yes` is always a dry run.
8. **Prune.** Only unconditional bindings the tool added or superseded are eligible; a binding
   with a condition is never pruned automatically ("covered by inheritance" requires
   identical member, role and no condition on both sides).
9. **Rollback constraints.** Rollback takes fresh backups of the reversed constraints
   (export on dest, import on source) and restores them with the same guard as `apply`.
10. **Permission probes (`parity verify`).** `testIamPermissions` only tests the caller, so
    per-principal probes use the IAM Policy Troubleshooter API (`troubleshoot_access`).
    If unavailable, probes degrade to Warning and effective-IAM diff remains authoritative.
