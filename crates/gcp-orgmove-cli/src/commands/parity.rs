//! `parity check` (§6.4.4) and `parity fix` (§6.4.5).

use std::collections::BTreeSet;

use gcp_orgmove_core::apply::unresolved_gaps;
use gcp_orgmove_core::planner::{refresh_parity, RefreshOptions};
use gcp_orgmove_core::state::atomic_write;
use gcp_orgmove_core::PolicyFixMode;
use gcp_orgmove_core::{
    Error, IamFixMode, Plan, PlanProject, ProjectId, Result, Severity, State, StateHandle,
    StateStore, Status,
};
use gcp_orgmove_parity::executor::{execute_with, FixItem, FixOptions, Outcome};
use serde_json::json;

use crate::output::Printer;
use crate::{load_manifest, parse_ids, Ctx, Mode};

pub async fn check(ctx: &Ctx<'_>, p: &mut Printer<'_>, projects: &[String]) -> Result<u8> {
    let loaded = load_manifest(&ctx.global.manifest)?;
    let mut plan = Plan::load(&ctx.global.plan)?;
    let only = parse_ids::<ProjectId>(projects)?;
    let checks = gcp_orgmove_parity::default_checks();
    let mut refresh = RefreshOptions::new(usize::from(ctx.global.concurrency));
    refresh.only = only.clone();
    refresh.observer = ctx.observer.clone();
    refresh_parity(ctx.gcp, &mut plan, &loaded.manifest, &checks, &refresh).await?;
    atomic_write(&ctx.global.plan, &plan.to_json_bytes()?)?;

    let mut rows = vec![];
    for pr in plan
        .projects
        .iter()
        .filter(|pr| only.is_empty() || only.contains(&pr.id))
    {
        for f in &pr.findings {
            rows.push(vec![
                pr.id.to_string(),
                format!("{:?}", f.category).to_lowercase(),
                format!("{:?}", f.severity).to_lowercase(),
                f.id.clone(),
                f.summary.clone(),
            ]);
        }
    }
    p.table(
        &["Project", "Category", "Severity", "Finding", "Summary"],
        rows,
    );
    p.info(format!(
        "{} blocker(s), {} gap(s), {} warning(s). Plan updated: {}",
        plan.summary.blockers,
        plan.summary.gaps,
        plan.summary.warnings,
        ctx.global.plan.display()
    ));
    p.json("parity-check", &plan);
    Ok(if plan.has_blockers() { 4 } else { 0 })
}

fn parse_iam_fix(raw: &str) -> Result<IamFixMode> {
    serde_json::from_value(json!(raw)).map_err(|_| {
        Error::invalid(format!(
            "--iam-fix {raw:?}: expected off, project or folder"
        ))
    })
}

/// Move projects forward through ParityGaps/ParityFixed after a fix run.
async fn advance_status(
    state: &StateHandle,
    id: &ProjectId,
    has_gaps: bool,
    all_fixed: bool,
) -> Result<()> {
    let id = id.clone();
    state
        .update(move |s: &mut State| {
            let ps = s.ensure_project(&id);
            if ps.status == Status::Discovered {
                s.set_status(&id, Status::Analyzed)?;
            }
            let cur = s.project(&id).expect("ensured").status.clone();
            if has_gaps && cur == Status::Analyzed {
                s.set_status(&id, Status::ParityGaps)?;
            }
            if all_fixed && s.project(&id).expect("ensured").status == Status::ParityGaps {
                s.set_status(&id, Status::ParityFixed)?;
            }
            Ok(())
        })
        .await
}

fn items_for(plan: &Plan, only: &[ProjectId], accepted: &BTreeSet<&str>) -> Vec<FixItem> {
    plan.projects
        .iter()
        .filter(|pr| only.is_empty() || only.contains(&pr.id))
        .flat_map(|pr: &PlanProject| {
            pr.findings
                .iter()
                .filter(|f| f.severity == Severity::Gap && !accepted.contains(f.id.as_str()))
                .filter_map(|f| {
                    f.remediation.clone().map(|remediation| FixItem {
                        finding: Some(f.id.clone()),
                        project: pr.id.clone(),
                        landing: pr.landing_parent.clone(),
                        remediation,
                    })
                })
        })
        .collect()
}

pub async fn fix(
    ctx: &Ctx<'_>,
    p: &mut Printer<'_>,
    projects: &[String],
    iam_fix: Option<&str>,
    policy_fix: Option<&str>,
    allow_policy_overrides: bool,
    yes_widen_access: bool,
) -> Result<u8> {
    let loaded = load_manifest(&ctx.global.manifest)?;
    let plan = Plan::load(&ctx.global.plan)?;
    let only = parse_ids::<ProjectId>(projects)?;

    let policy_mode = match policy_fix {
        Some("off") | None => loaded.manifest.parity.policy_fix,
        Some("project-override") => PolicyFixMode::ProjectOverride,
        Some(other) => {
            return Err(Error::invalid(format!(
                "--policy-fix {other:?}: expected off or project-override"
            )))
        }
    };
    if policy_fix == Some("project-override") && !allow_policy_overrides {
        return Err(Error::invalid(
            "--policy-fix project-override also requires --allow-policy-overrides",
        ));
    }

    let mode = match iam_fix {
        Some(raw) => parse_iam_fix(raw)?,
        None => loaded.manifest.parity.iam_fix,
    };
    let accepted: BTreeSet<&str> = loaded
        .manifest
        .parity
        .accept
        .iter()
        .map(|a| a.finding.as_str())
        .collect();
    let items = items_for(&plan, &only, &accepted);
    let preview = ctx.mode() != Mode::Execute;
    let mut opts = FixOptions {
        iam_fix: mode,
        custom_roles: loaded.manifest.parity.custom_roles,
        policy_fix: policy_mode,
        allow_policy_overrides,
        override_expiry: loaded.manifest.parity.override_expiry.0,
        now: ctx.now,
        widen_access: yes_widen_access,
        dry_run: preview,
    };

    let store = StateStore::open(&ctx.global.state).await?;
    let handle = store.handle();
    let outcome = fix_inner(
        ctx,
        p,
        &plan,
        &loaded.manifest,
        &only,
        &items,
        &mut opts,
        &handle,
    )
    .await;
    store.close().await;
    outcome
}

fn render_fix(
    p: &mut Printer<'_>,
    results: &[gcp_orgmove_parity::executor::FixResult],
) -> (usize, usize) {
    let (mut failed, mut manual) = (0, 0);
    let rows: Vec<Vec<String>> = results
        .iter()
        .map(|r| {
            let result = match &r.outcome {
                Ok(Outcome::Applied) => "applied".to_string(),
                Ok(Outcome::AlreadyPresent) => "already present".to_string(),
                Ok(Outcome::WouldApply) => "would apply".to_string(),
                Ok(Outcome::Skipped(why)) => {
                    manual += 1;
                    format!("skipped: {why}")
                }
                Err(e) => {
                    failed += 1;
                    format!("FAILED: {e}")
                }
            };
            vec![
                r.project.to_string(),
                r.finding.clone().unwrap_or_default(),
                r.description.clone(),
                result,
            ]
        })
        .collect();
    p.table(&["Project", "Finding", "Action", "Result"], rows);
    (failed, manual)
}

#[allow(clippy::too_many_arguments)]
async fn fix_inner(
    ctx: &Ctx<'_>,
    p: &mut Printer<'_>,
    plan: &Plan,
    manifest: &gcp_orgmove_core::Manifest,
    only: &[ProjectId],
    items: &[FixItem],
    opts: &mut FixOptions,
    handle: &StateHandle,
) -> Result<u8> {
    let fix_json = |dry: bool, results: &[gcp_orgmove_parity::executor::FixResult]| {
        json!({
            "dry_run": dry,
            "results": results.iter().map(|r| json!({
                "project": r.project, "finding": r.finding, "action": r.description,
                "result": match &r.outcome { Ok(o) => format!("{o:?}"), Err(e) => format!("failed: {e}") },
            })).collect::<Vec<_>>(),
        })
    };

    // Don't let someone confirm a prompt that the real run would then refuse.
    if ctx.mode() == Mode::Ask && opts.iam_fix == IamFixMode::Folder && !opts.widen_access {
        return Err(Error::invalid(
            "--iam-fix folder grants access to every project in the landing folder; pass --yes-widen-access to confirm",
        ));
    }
    let mut results = execute_with(ctx.gcp, handle, items, opts, &ctx.observer).await?;
    if ctx.mode() == Mode::Ask {
        p.info("Planned changes:");
    }
    let (mut failed, mut manual) = render_fix(p, &results);

    if opts.dry_run {
        let pending = results
            .iter()
            .filter(|r| matches!(r.outcome, Ok(Outcome::WouldApply)))
            .count();
        if pending == 0 {
            p.info("Nothing to apply.");
            p.json("parity-fix", &fix_json(true, &results));
            return Ok(0);
        }
        // Widening access or relaxing policy deserves a deliberate "yes".
        let strict = opts.iam_fix == IamFixMode::Folder
            || (opts.policy_fix == PolicyFixMode::ProjectOverride && opts.allow_policy_overrides);
        let go = ctx.proceed(p, &format!("Apply {pending} change(s)?"), strict)?;
        if !go {
            if ctx.mode() != Mode::Ask {
                p.info("Dry run: nothing changed. Re-run with --yes to apply.");
            }
            p.json("parity-fix", &fix_json(true, &results));
            return Ok(0);
        }
        opts.dry_run = false;
        results = execute_with(ctx.gcp, handle, items, opts, &ctx.observer).await?;
        p.info("Results:");
        (failed, manual) = render_fix(p, &results);
    }

    let state = handle.snapshot().await?;
    for pr in plan
        .projects
        .iter()
        .filter(|pr| only.is_empty() || only.contains(&pr.id))
    {
        let has_gaps = pr.findings.iter().any(|f| f.severity == Severity::Gap);
        if !has_gaps {
            continue;
        }
        let one: BTreeSet<ProjectId> = [pr.id.clone()].into();
        let fixed = unresolved_gaps(plan, &state, manifest, &one).is_empty();
        advance_status(handle, &pr.id, true, fixed).await?;
    }
    let state = handle.snapshot().await?;
    let all: BTreeSet<ProjectId> = plan
        .projects
        .iter()
        .filter(|pr| only.is_empty() || only.contains(&pr.id))
        .map(|pr| pr.id.clone())
        .collect();
    let left = unresolved_gaps(plan, &state, manifest, &all);
    if left.is_empty() {
        p.info("All gaps are resolved.");
    } else {
        p.info(format!(
            "{} gap(s) remain; fix them manually or accept them under parity.accept: {}",
            left.len(),
            left.iter()
                .map(|f| f.id.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if manual > 0 {
        p.info(format!(
            "{manual} item(s) were skipped (manual action or disabled by mode)."
        ));
    }
    p.json("parity-fix", &fix_json(false, &results));
    Ok(if failed > 0 { 6 } else { 0 })
}

pub async fn verify(ctx: &Ctx<'_>, p: &mut Printer<'_>, projects: &[String]) -> Result<u8> {
    let loaded = load_manifest(&ctx.global.manifest)?;
    let plan = Plan::load(&ctx.global.plan)?;
    let only = parse_ids::<ProjectId>(projects)?;
    let store = StateStore::open(&ctx.global.state).await?;
    let handle = store.handle();
    let results = gcp_orgmove_parity::verify::verify_with(
        ctx.gcp,
        &handle,
        &loaded.manifest,
        &plan,
        &only,
        &ctx.observer,
    )
    .await;
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
        format!(
            "{} project(s) passed parity verification; `parity prune` is now allowed for them.",
            results.len()
        )
    } else {
        format!(
            "{failed} of {} project(s) failed parity verification.",
            results.len()
        )
    });
    p.json(
        "parity-verify",
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

pub async fn prune(
    ctx: &Ctx<'_>,
    p: &mut Printer<'_>,
    projects: &[String],
    older_than: Option<&str>,
) -> Result<u8> {
    use gcp_orgmove_parity::prune::{describe, eligible, prune_with, PruneOutcome};
    let loaded = load_manifest(&ctx.global.manifest)?;
    let only = parse_ids::<ProjectId>(projects)?;
    let soak = older_than
        .map(|d| d.parse::<gcp_orgmove_core::HumanDuration>())
        .transpose()?
        .map(|d| d.0);

    let store = StateStore::open(&ctx.global.state).await?;
    let handle = store.handle();
    let state = handle.snapshot().await?;
    let found = eligible(ctx.gcp, &state, &loaded.manifest, &only, soak, ctx.now).await;
    let found = match found {
        Ok(f) => f,
        Err(e) => {
            store.close().await;
            return Err(e);
        }
    };

    // Explicitly requested projects that cannot be pruned are an error, not a skip.
    if let Some((id, why)) = found.refused.iter().find(|(id, _)| only.contains(id)) {
        store.close().await;
        return Err(Error::invalid(format!("cannot prune {id}: {why}"))
            .with_resource(format!("projects/{id}")));
    }
    for (id, why) in &found.refused {
        p.info(format!("skipping {id}: {why}"));
    }
    if found.candidates.is_empty() {
        p.info("Nothing to prune.");
        store.close().await;
        p.json(
            "parity-prune",
            &json!({"dry_run": ctx.mode() != Mode::Execute, "removed": []}),
        );
        return Ok(0);
    }

    if ctx.mode() != Mode::Execute {
        if ctx.mode() == Mode::Ask {
            p.info("`parity prune` will remove exactly this access:");
        } else {
            p.info("Dry run: `parity prune` would remove exactly this access (re-run with --yes to apply):");
        }
        for c in &found.candidates {
            p.info(format!("  - {}", describe(c)));
        }
        // This is the one command that removes access: demand a deliberate "yes".
        let question = format!("Remove access from {} binding(s)?", found.candidates.len());
        if !ctx.proceed(p, &question, true)? {
            store.close().await;
            p.json(
                "parity-prune",
                &json!({
                    "dry_run": true,
                    "removed": found.candidates.iter().map(|c| json!({
                        "project": c.project, "change": describe(c), "result": "WouldRemove",
                    })).collect::<Vec<_>>(),
                }),
            );
            return Ok(0);
        }
    }
    let dry = false;
    let results = prune_with(ctx.gcp, &handle, &found.candidates, dry, &ctx.observer).await;
    store.close().await;
    let results = results?;

    let mut failed = 0;
    {
        p.table(
            &["Project", "Change", "Result"],
            results
                .iter()
                .map(|r| {
                    let res = match &r.outcome {
                        Ok(PruneOutcome::Removed) => "removed".to_string(),
                        Ok(PruneOutcome::AlreadyGone) => "already gone".to_string(),
                        Ok(PruneOutcome::WouldRemove) => "would remove".to_string(),
                        Err(e) => {
                            failed += 1;
                            format!("FAILED: {e}")
                        }
                    };
                    vec![r.project.to_string(), r.description.clone(), res]
                })
                .collect(),
        );
        p.info("Pruned access is recorded; `rollback --revert-remediations` restores it.");
    }
    p.json(
        "parity-prune",
        &json!({
            "dry_run": dry,
            "removed": results.iter().map(|r| json!({
                "project": r.project, "change": r.description,
                "result": match &r.outcome { Ok(o) => format!("{o:?}"), Err(e) => format!("failed: {e}") },
            })).collect::<Vec<_>>(),
        }),
    );
    Ok(if failed > 0 { 6 } else { 0 })
}
