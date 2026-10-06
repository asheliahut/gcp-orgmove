//! `plan` (§6.3): preflight + parity checks, write the plan file. Read-only against GCP.

use std::collections::BTreeSet;

use gcp_orgmove_core::planner::{build_plan, PlanOptions};
use gcp_orgmove_core::state::atomic_write;
use gcp_orgmove_core::{Plan, ProjectId, Result, Severity};

use crate::output::Printer;
use crate::{load_manifest, parse_ids, Ctx};

pub async fn run(
    ctx: &Ctx<'_>,
    p: &mut Printer<'_>,
    skip: &[String],
    only: &[String],
    strict: bool,
) -> Result<u8> {
    let loaded = load_manifest(&ctx.global.manifest)?;
    let mut opts = PlanOptions::new(ctx.now);
    opts.concurrency = usize::from(ctx.global.concurrency);
    opts.skip = skip.iter().cloned().collect::<BTreeSet<_>>();
    opts.only = parse_ids::<ProjectId>(only)?;
    opts.strict = strict;
    opts.observer = ctx.observer.clone();

    let checks = gcp_orgmove_parity::default_checks();
    let plan = build_plan(ctx.gcp, &loaded, &checks, &opts).await?;
    atomic_write(&ctx.global.plan, &plan.to_json_bytes()?)?;

    render(p, &plan, &ctx.global.plan);
    Ok(if plan.has_blockers() { 4 } else { 0 })
}

fn render(p: &mut Printer<'_>, plan: &Plan, path: &std::path::Path) {
    p.table(
        &[
            "Project",
            "Current parent",
            "Landing parent",
            "Group",
            "Blockers",
            "Gaps",
            "Warnings",
        ],
        plan.projects
            .iter()
            .map(|pr| {
                let count =
                    |sev: Severity| pr.findings.iter().filter(|f| f.severity == sev).count();
                vec![
                    pr.id.to_string(),
                    pr.current_parent.to_string(),
                    pr.landing_parent.to_string(),
                    pr.group.clone().unwrap_or_default(),
                    (pr.analysis.blockers.len() + count(Severity::Blocker)).to_string(),
                    count(Severity::Gap).to_string(),
                    (pr.analysis.warnings.len() + count(Severity::Warning)).to_string(),
                ]
            })
            .collect(),
    );
    if !plan.policy_changes.is_empty() {
        p.info("\nConstraint changes `apply` will make (and restore):");
        for c in &plan.policy_changes {
            p.info(format!(
                "  {} on {}: allow {}",
                c.constraint, c.scope, c.value
            ));
        }
    }
    for pr in &plan.projects {
        for f in pr
            .findings
            .iter()
            .filter(|f| f.severity <= Severity::Warning)
        {
            p.info(format!(
                "  [{}] {:?} {}: {}",
                f.id, f.severity, f.project, f.summary
            ));
        }
    }
    p.info(format!(
        "\n{} project(s), {} blocker(s), {} gap(s), {} warning(s); {} batch(es). Plan written to {}",
        plan.summary.projects,
        plan.summary.blockers,
        plan.summary.gaps,
        plan.summary.warnings,
        plan.order.len(),
        path.display()
    ));
    if plan.has_blockers() {
        p.info("The plan contains blockers; nothing was changed. Fix them and re-run `plan`.");
    }
    p.json("plan", plan);
}
