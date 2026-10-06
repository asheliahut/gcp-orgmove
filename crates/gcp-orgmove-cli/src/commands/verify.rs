//! `verify` (§6.6): structural outcome of the migration.

use std::time::Duration;

use gcp_orgmove_core::verify::{verify, VerifyOptions};
use gcp_orgmove_core::{Error, HumanDuration, Plan, ProjectId, Result, StateStore};
use serde_json::json;

use crate::output::Printer;
use crate::{parse_ids, Ctx};

pub async fn run(
    ctx: &Ctx<'_>,
    p: &mut Printer<'_>,
    projects: &[String],
    wait: Option<&str>,
) -> Result<u8> {
    let plan = Plan::load(&ctx.global.plan)?;
    let only = parse_ids::<ProjectId>(projects)?;
    let mut opts = VerifyOptions {
        concurrency: usize::from(ctx.global.concurrency),
        observer: ctx.observer.clone(),
        ..VerifyOptions::default()
    };
    if let Some(w) = wait {
        opts.wait = w.parse::<HumanDuration>()?.0;
    }
    run_with(ctx, p, &plan, &only, opts).await
}

pub async fn run_with(
    ctx: &Ctx<'_>,
    p: &mut Printer<'_>,
    plan: &Plan,
    only: &[ProjectId],
    opts: VerifyOptions,
) -> Result<u8> {
    let store = StateStore::open(&ctx.global.state).await?;
    let handle = store.handle();
    if handle.snapshot().await?.projects.is_empty() {
        store.close().await;
        return Err(Error::invalid("no state recorded; nothing to verify")
            .with_hint("run `gcp-orgmove apply --yes` first"));
    }
    let results = verify(ctx.gcp, plan, &handle, only, &opts).await;
    store.close().await;
    let results = results?;

    let mut rows = vec![];
    for r in &results {
        for c in &r.checks {
            rows.push(vec![
                r.project.to_string(),
                c.name.to_string(),
                if c.ok {
                    "ok".to_string()
                } else if c.fatal {
                    "FAIL".to_string()
                } else {
                    "warn".to_string()
                },
                c.detail.clone(),
            ]);
        }
    }
    p.table(&["Project", "Check", "Result", "Detail"], rows);
    let failed = results.iter().filter(|r| !r.passed()).count();
    p.info(if failed == 0 {
        format!("{} project(s) verified.", results.len())
    } else {
        format!("{failed} of {} project(s) failed verification (try --wait 10m if the move just finished).", results.len())
    });
    let _ = Duration::ZERO;
    p.json(
        "verify",
        &json!({
            "projects": results.iter().map(|r| json!({
                "id": r.project,
                "passed": r.passed(),
                "checks": r.checks.iter().map(|c| json!({"name": c.name, "ok": c.ok, "fatal": c.fatal, "detail": c.detail})).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        }),
    );
    Ok(if failed == 0 { 0 } else { 6 })
}
