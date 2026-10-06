# Recovery runbook

Start with `gcp-orgmove status`: it shows each project's state, the last failure,
smoke results, and **pending cleanup** (constraints still modified).

## `apply` was interrupted or crashed

Re-run `gcp-orgmove apply --yes`. At the start of every `apply`/`rollback` the tool
restores any constraint it left modified (recorded in the state file), then
resumes: projects already moved are skipped, a project with an in-flight move
operation is polled rather than re-moved. One Ctrl-C finishes in-flight
operations and restores constraints; a second aborts immediately (exit 130),
leaving the repair to the next run.

## Constraints are still modified

`status` lists them under "Pending cleanup". Running `apply` or `rollback`
repairs them. If restoration fails (for example a permission problem), the error
names the constraint and scope; fix it and re-run. You can also reverse by hand:
remove `under:organizations/<DEST>` from
`constraints/resourcemanager.allowedExportDestinations` on the source org, and
`under:organizations/<SRC>` from `constraints/resourcemanager.allowedImportSources`
on the destination org. `--keep-constraints` leaves them on purpose and prints
what remains changed.

## Some projects failed (exit 6)

`status` shows `failed: <reason>` per project. Fix the cause and re-run `apply --yes`:
failed projects become ready again; moved ones are skipped. `--continue-on-error`
lets the rest of the batches proceed meanwhile. A failed member halts its whole
move group.

## "timed out waiting for operations/…"

The operation may still be running. The project stays `moving` with the operation
recorded; re-run `apply --yes` to resume polling.

## Smoke test failed after a move (exit 7)

The batch is halted. The output prints the exact command, for example
`gcp-orgmove rollback --project my-app-prod --yes`. Add `--revert-remediations`
to also remove the IAM grants, recreated roles and policy overrides the tool added.

## Roll back

```sh
gcp-orgmove rollback --all                     # dry run
gcp-orgmove rollback --all --yes               # move back; constraints set in reverse and restored
gcp-orgmove rollback --all --yes --revert-remediations
```

Groups roll back as a unit. Rollback refuses (changing nothing) if a project
has no recorded original parent. If `parity prune` removed access, it is put
back first when you use `--revert-remediations`.

## "another gcp-orgmove run holds …lock"

Another process is using the state file. If that process is gone, delete
`orgmove.state.json.lock`.

## Plan is stale (exit 5)

The plan is older than `limits.plan_max_age`, the manifest changed, or a project's
parent moved since planning. Re-run `plan` (and `parity fix` if needed).
