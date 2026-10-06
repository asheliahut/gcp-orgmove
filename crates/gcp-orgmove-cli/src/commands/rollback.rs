//! `rollback` (§6.7): move projects back to their recorded original parents.

use std::collections::BTreeSet;

use gcp_orgmove_core::rollback::{describe, reverse_changes, rollback, select, RollbackOptions};
use gcp_orgmove_core::{ProjectId, Result, StateStore};
use gcp_orgmove_parity::executor::{revert, RevertOutcome};
use serde_json::json;

use crate::output::Printer;
use crate::{load_manifest, parse_ids, Ctx, Mode};

pub async fn run(
    ctx: &Ctx<'_>,
    p: &mut Printer<'_>,
    projects: &[String],
    all: bool,
    revert_remediations: bool,
) -> Result<u8> {
    let loaded = load_manifest(&ctx.global.manifest)?;
    let mut opts = RollbackOptions::new();
    opts.concurrency = usize::from(ctx.global.concurrency);
    opts.projects = parse_ids::<ProjectId>(projects)?;
    opts.all = all;
    opts.observer = ctx.observer.clone();

    let store = StateStore::open(&ctx.global.state).await?;
    let handle = store.handle();
    let result = run_inner(
        ctx,
        p,
        &loaded.manifest,
        &handle,
        &opts,
        revert_remediations,
    )
    .await;
    store.close().await;
    result
}

async fn run_inner(
    ctx: &Ctx<'_>,
    p: &mut Printer<'_>,
    manifest: &gcp_orgmove_core::Manifest,
    handle: &gcp_orgmove_core::StateHandle,
    opts: &RollbackOptions,
    revert_remediations: bool,
) -> Result<u8> {
    let state = handle.snapshot().await?;
    let ids = select(&state, opts)?;
    if ids.is_empty() {
        p.info("Nothing to roll back.");
        p.json(
            "rollback",
            &json!({"rolled_back": [], "dry_run": ctx.mode() != Mode::Execute}),
        );
        return Ok(0);
    }
    let changes = reverse_changes(ctx.gcp, manifest).await?;

    if ctx.mode() != Mode::Execute {
        let mut lines = describe(&state, &ids, &changes);
        let set: BTreeSet<ProjectId> = ids.iter().cloned().collect();
        if revert_remediations {
            for r in revert(ctx.gcp, handle, &set, true).await? {
                lines.push(format!("revert: {} ({})", r.description, r.project));
            }
        }
        if ctx.mode() == Mode::Ask {
            p.info("`rollback` will do the following:");
        } else {
            p.info("Dry run: `rollback` would do the following (re-run with --yes to execute):");
        }
        for l in &lines {
            p.info(format!("  {l}"));
        }
        // Moving projects back (and possibly removing access) deserves a deliberate "yes".
        let question = format!("Roll back {} project(s)?", ids.len());
        if !ctx.proceed(p, &question, true)? {
            p.json("rollback", &json!({"dry_run": true, "actions": lines}));
            return Ok(0);
        }
    }

    let report = rollback(
        ctx.gcp,
        handle.clone(),
        &ids,
        &changes,
        ctx.cancel.clone(),
        opts,
    )
    .await?;
    p.table(
        &["Project", "Result"],
        ids.iter()
            .map(|id| {
                let result = if report.rolled_back.contains(id) {
                    "rolled back".to_string()
                } else if let Some((_, why)) = report.failed.iter().find(|(f, _)| f == id) {
                    format!("FAILED: {why}")
                } else {
                    "not started".to_string()
                };
                vec![id.to_string(), result]
            })
            .collect(),
    );
    if report.constraints_restored {
        p.info("Constraints restored.");
    }
    for e in &report.restore_errors {
        p.info(format!("CONSTRAINT RESTORE FAILED: {e}"));
    }
    for l in &report.constraints_left {
        p.info(format!("Still modified (--keep-constraints): {l}"));
    }

    let mut reverted = vec![];
    if revert_remediations {
        let done: BTreeSet<ProjectId> = report.rolled_back.iter().cloned().collect();
        let results = revert(ctx.gcp, handle, &done, false).await?;
        for r in &results {
            let line = match &r.outcome {
                Ok(RevertOutcome::Removed) => format!("reverted: {}", r.description),
                Ok(RevertOutcome::AlreadyGone) => format!("already gone: {}", r.description),
                Ok(RevertOutcome::NotAddedByTool) => format!(
                    "left alone (existed before the tool ran): {}",
                    r.description
                ),
                Ok(RevertOutcome::Restored) => format!("restored: {}", r.description),
                Ok(RevertOutcome::WouldRemove | RevertOutcome::WouldRestore) => {
                    unreachable!("not a dry run")
                }
                Ok(RevertOutcome::Skipped(why)) => format!("skipped ({why}): {}", r.description),
                Err(e) => format!("FAILED to revert ({e}): {}", r.description),
            };
            p.info(&line);
            reverted.push(line);
        }
        if results.iter().any(|r| r.outcome.is_err()) {
            p.json(
                "rollback",
                &json!({"rolled_back": report.rolled_back, "reverted": reverted}),
            );
            return Ok(6);
        }
    }
    if !report.failed.is_empty() {
        p.info("Some projects were not rolled back; see `gcp-orgmove status`. Re-run `rollback` to resume.");
    }
    p.json(
        "rollback",
        &json!({
            "rolled_back": report.rolled_back,
            "failed": report.failed.iter().map(|(id, why)| json!({"project": id, "reason": why})).collect::<Vec<_>>(),
            "skipped": report.skipped,
            "constraints_restored": report.constraints_restored,
            "reverted": reverted,
        }),
    );
    Ok(report.exit_code())
}
