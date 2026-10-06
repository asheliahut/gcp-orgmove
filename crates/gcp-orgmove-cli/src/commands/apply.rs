//! `apply` (§6.5): constraints, moves, restore.

use std::collections::BTreeSet;

use gcp_orgmove_core::apply::{apply, describe, preflight, ApplyHooks, ApplyOptions, NoHooks};
use gcp_orgmove_core::smoke::SmokeHooks;
use gcp_orgmove_core::{Plan, ProjectId, Result, StateStore};
use gcp_orgmove_parity::verify as parity_verify;
use serde_json::json;

use crate::output::Printer;
use crate::{load_manifest, parse_ids, Ctx, Mode};

pub async fn run(
    ctx: &Ctx<'_>,
    p: &mut Printer<'_>,
    keep_constraints: bool,
    projects: &[String],
    skip_smoke_tests: bool,
    continue_on_error: bool,
) -> Result<u8> {
    let loaded = load_manifest(&ctx.global.manifest)?;
    let plan = Plan::load(&ctx.global.plan)?;

    let mut opts = ApplyOptions::new(ctx.now);
    opts.concurrency = usize::from(ctx.global.concurrency);
    opts.keep_constraints = keep_constraints;
    opts.projects = parse_ids::<ProjectId>(projects)?;
    opts.continue_on_error = continue_on_error;
    opts.observer = ctx.observer.clone();

    // The lock is held for the whole run, dry-run included.
    let store = StateStore::open(&ctx.global.state).await?;
    let handle = store.handle();
    let state = handle.snapshot().await?;
    let approved = preflight(
        ctx.gcp,
        &plan,
        &loaded.manifest,
        &loaded.sha256,
        &state,
        &opts,
    )
    .await?;

    if ctx.mode() != Mode::Execute {
        let mut lines = describe(&plan, &approved.sel, keep_constraints);
        if !skip_smoke_tests {
            for t in &loaded.manifest.smoke_tests {
                lines.push(format!(
                    "smoke test {:?} ({:?}): {}",
                    t.name, t.phase, t.run
                ));
            }
        }
        if ctx.mode() == Mode::Ask {
            p.info("`apply` will do the following:");
        } else {
            p.info("Dry run: `apply` would do the following (re-run with --yes to execute):");
        }
        for l in &lines {
            p.info(format!("  {l}"));
        }
        let question = format!("Move {} project(s) now?", approved.sel.len());
        if !ctx.proceed(p, &question, false)? {
            p.json("apply", &json!({"dry_run": true, "actions": lines}));
            store.close().await;
            return Ok(0);
        }
    }

    // Record the probed principals' access *before* anything moves, so
    // `parity verify` can compare against it afterwards.
    let sel_ids: Vec<ProjectId> = approved.sel.iter().cloned().collect();
    parity_verify::snapshot(
        ctx.gcp,
        &handle,
        &sel_ids,
        &loaded.manifest.parity.principals_to_probe,
    )
    .await?;

    let smoke = SmokeHooks {
        tests: loaded.manifest.smoke_tests.clone(),
        state: handle.clone(),
    };
    let hooks: &dyn ApplyHooks = if skip_smoke_tests || loaded.manifest.smoke_tests.is_empty() {
        &NoHooks
    } else {
        &smoke
    };
    let report = apply(
        ctx.gcp,
        &plan,
        &approved,
        handle,
        hooks,
        ctx.cancel.clone(),
        &opts,
    )
    .await;
    store.close().await;
    let report = report?;

    let moved: BTreeSet<_> = report.moved.iter().collect();
    p.table(
        &["Project", "Result"],
        plan.projects
            .iter()
            .filter(|pr| approved.sel.contains(&pr.id))
            .map(|pr| {
                let result = if moved.contains(&pr.id) {
                    "moved".to_string()
                } else if let Some((_, why)) = report.failed.iter().find(|(id, _)| id == &pr.id) {
                    format!("FAILED: {why}")
                } else {
                    "not started".to_string()
                };
                vec![pr.id.to_string(), result]
            })
            .collect(),
    );
    if report.interrupted {
        p.info("Interrupted: no new moves were started.");
    }
    if report.constraints_restored {
        p.info("Constraints restored.");
    }
    for line in &report.constraints_left {
        p.info(format!("Still modified (--keep-constraints): {line}"));
    }
    for e in &report.restore_errors {
        p.info(format!("CONSTRAINT RESTORE FAILED: {e}"));
    }
    if let Some((id, why)) = &report.smoke_failure {
        p.info(format!("Smoke test failed after moving {id}: {why}"));
        p.info(format!(
            "To undo: gcp-orgmove rollback --project {id} --yes"
        ));
    }
    if report.exit_code() == 6 {
        p.info("Some projects did not move; see `gcp-orgmove status`. Re-run `apply` to resume.");
    }
    p.json(
        "apply",
        &json!({
            "moved": report.moved,
            "failed": report.failed.iter().map(|(id, why)| json!({"project": id, "reason": why})).collect::<Vec<_>>(),
            "skipped": report.skipped,
            "interrupted": report.interrupted,
            "constraints_restored": report.constraints_restored,
            "constraints_left": report.constraints_left,
            "restore_errors": report.restore_errors,
        }),
    );
    Ok(report.exit_code())
}
