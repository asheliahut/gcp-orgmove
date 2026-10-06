# Safety model

| Rule | How it is enforced |
|---|---|
| Read-only by default | `discover`, `plan`, `parity check`, `verify`, `parity verify`, `status` never call a mutating API (tests assert this against the fake) |
| Preview, then confirm | Mutating commands print the exact actions first. At a terminal they then ask (`[y/N]`; `rollback`, `parity prune`, and anything that widens access or relaxes policy need the full word `yes`). Without a terminal, or with `-q`/`--format json`, they only preview unless `--yes`. `--dry-run` always wins and never prompts |
| Blockers stop the run | Exit 4 and nothing changes |
| Plan is a contract | `apply` checks plan age, manifest hash and each project's live parent; any drift exits 5 |
| Additive before destructive | `parity fix` can only add access: the executor refuses any IAM write whose result is not a superset of the old policy |
| Widening needs consent | `--iam-fix folder` needs `--yes-widen-access`; never widens to the org |
| Policy relaxation needs consent | `project-override` needs both the setting and `--allow-policy-overrides`, expires, and is labeled |
| Constraints always restored | Backed up before change, restored on success, error, panic and Ctrl-C; a crash is repaired at the start of the next run |
| Restore never clobbers | Restoring removes only the value this tool added, so a concurrent edit by someone else survives |
| Removal is explicit | Only `parity prune` and `rollback --revert-remediations` remove access, and only access the tool added or superseded |
| No concurrent runs | An exclusive lock on `<state>.lock` |
| Bounded blast radius | Concurrency hard cap 16 (halved on every 429), batch size limit |
| Full audit trail | Every mutation is recorded in the state file with its prior value |

## Logins

With separate source and destination logins, each call uses the login for the
organization that owns the resource, so a login is never used on an organization it
has no business in: org policy on each org is changed only by that org's own login.
The move is the one exception, since Google requires the mover to have rights on
both sides; `plan` checks those rights as the mover before anything changes.
Routing is learned by trying the likely login and falling back on a permission
or not-found error, so a refused attempt on the wrong login is expected and harmless
(it is a read, or a write that the wrong login would be refused anyway).

## What the state file records

`orgmove.state.json` is written atomically (temp file, fsync, rename) after
every transition, and is the source of truth for resuming, `status` and
`rollback`: per-project status, the **original parent recorded before each
move**, in-flight operation names, constraint backups, every applied
remediation with its prior value, pruned access, smoke and verify results.
Do not delete it mid-migration: `rollback` depends on it.

## Moves

For each project: record the original parent, call `projects.move`, persist the
operation name, poll with backoff, then check the live parent. A project
already at its landing parent counts as moved. An interrupted run resumes an
in-flight operation instead of re-moving. A move group halts as a unit: when
one member fails, members that have not started do not start.

Retries: HTTP 429 always, 5xx only for idempotent calls, never other 4xx. A 409
(etag conflict) is re-read and retried by the read-modify-write callers.
