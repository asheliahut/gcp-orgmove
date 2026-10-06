# Known limitations

## By design

- **No zero-downtime guarantee.** The tool detects and closes the most common
  causes of post-move breakage and reports the rest.
- **Shared VPC and VPC Service Controls are not reconfigured.** Shared VPC hosts
  and their service projects are grouped and moved together; if either side is
  outside the migration, that is a blocker. Projects inside a VPC-SC perimeter
  are a blocker with manual steps.
- It does not recreate folders, organization-level IAM or organization policies
  wholesale, and does not migrate Workspace / Cloud Identity domains.
- `parity fix` never removes access; only `parity prune` and
  `rollback --revert-remediations` do.

## Where the checks are approximate

- **Effective IAM and policy** are computed by walking ancestors; exotic
  inheritance cases may be missed.
- **IAM conditions and deny policies are reported, not simulated.** Conditional
  org-policy rules are compared as text and flagged for review.
- **`parity verify` IAM diff** compares each probed principal's *own* bindings
  against a snapshot taken just before the move. Access that comes from group
  membership is covered by the permission probes (IAM Policy Troubleshooter), not
  the diff.
- **`principal-domains`** can't map an email domain to a Cloud Identity customer
  ID, so it lists the domains for you to confirm.
- **`analyzeMove`** findings are necessary, not sufficient.
- The **`org-scoped`** checklist covers log sinks, tag bindings and asset feeds;
  billing accounts and essential contacts are always listed as a manual reminder.

## Two logins

- The login that performs the move must have rights on **both** organizations; there
  is no way to split one `projects.move` call across two identities.
- Which login owns an org, folder or project is learned at run time. The first call
  for an unknown resource may be refused on the wrong login before it succeeds on
  the right one; the manifest seeds the common cases so this rarely happens.
- If a resource is reachable by neither login the error says so and names both; it
  cannot tell "doesn't exist" from "not visible to either".
- Cloud Identity group lookups use the source login and fall back to the destination
  login only on a permission error.

## Implementation notes

- Progress bars and prompts need a terminal; elsewhere the tool prints plain output and
  previews unless `--yes`. Prompts read from stdin, so don't pipe other input into a command you want to confirm.
- Policy overrides replicate the project's *current effective* policy; the
  recommended alternative is always a deliberate destination-side change.
- Not yet exercised against real organizations. Use disposable projects first.
- Linux and macOS only. Smoke tests run via `sh -c`; Windows is untested.
