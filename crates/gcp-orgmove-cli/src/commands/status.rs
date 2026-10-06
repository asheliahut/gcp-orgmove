//! `status` (§6.8): read-only view of the state file (and plan findings).

use gcp_orgmove_core::state::read_state;
use gcp_orgmove_core::{Plan, ProjectId, Remediation, Result, Severity, Status};
use serde_json::json;

use crate::output::Printer;
use crate::{parse_ids, Ctx};

fn describe_status(s: &Status) -> String {
    match s {
        Status::Failed { reason } => format!("failed: {reason}"),
        other => format!("{:?}", other.kind()).to_lowercase(),
    }
}

pub fn run(
    ctx: &Ctx<'_>,
    p: &mut Printer<'_>,
    only: &[String],
    overrides: bool,
    findings: bool,
) -> Result<u8> {
    let state = read_state(&ctx.global.state)?;
    let only = parse_ids::<ProjectId>(only)?;
    let keep = |id: &ProjectId| only.is_empty() || only.contains(id);

    p.table(
        &["Project", "State", "Updated", "Original parent"],
        state
            .projects
            .iter()
            .filter(|(id, _)| keep(id))
            .map(|(id, ps)| {
                vec![
                    id.to_string(),
                    describe_status(&ps.status),
                    ps.updated_at.format("%Y-%m-%d %H:%M:%SZ").to_string(),
                    ps.original_parent
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_default(),
                ]
            })
            .collect(),
    );
    if state.projects.is_empty() {
        p.info("No project state recorded yet (run `plan` and `apply`).");
    }

    let smoke: Vec<_> = state
        .smoke_results
        .iter()
        .filter(|r| r.project.as_ref().map(&keep).unwrap_or(true))
        .collect();
    if !smoke.is_empty() {
        p.info("\nSmoke tests:");
        p.table(
            &["Test", "Phase", "Project", "Result", "Took"],
            smoke
                .iter()
                .map(|r| {
                    vec![
                        r.name.clone(),
                        format!("{:?}", r.phase).to_lowercase(),
                        r.project
                            .as_ref()
                            .map(ToString::to_string)
                            .unwrap_or_default(),
                        if r.passed {
                            "pass".to_string()
                        } else {
                            format!("FAIL: {}", r.output)
                        },
                        format!("{}ms", r.duration_ms),
                    ]
                })
                .collect(),
        );
    }

    let pending: Vec<String> = state
        .pending_constraints()
        .map(|(_, b)| {
            format!(
                "{} on {} still allows {}",
                b.constraint, b.scope, b.added_value
            )
        })
        .collect();
    if !pending.is_empty() {
        p.info(
            "\nPending cleanup: constraints are still modified (the next `apply` restores them):",
        );
        for l in &pending {
            p.info(format!("  {l}"));
        }
    }

    let mut outstanding = vec![];
    if findings {
        let plan = Plan::load(&ctx.global.plan)?;
        for pr in plan.projects.iter().filter(|pr| keep(&pr.id)) {
            for f in pr.findings.iter().filter(|f| f.severity != Severity::Info) {
                outstanding.push(json!({"id": f.id, "project": f.project, "severity": f.severity, "summary": f.summary}));
                p.info(format!(
                    "[{}] {:?} {}: {}",
                    f.id, f.severity, f.project, f.summary
                ));
            }
        }
        if outstanding.is_empty() {
            p.info("No outstanding findings.");
        }
    }
    let mut override_rows = vec![];
    if overrides {
        let today = ctx.now.format("%Y-%m-%d").to_string();
        for a in state
            .applied
            .iter()
            .filter(|a| !a.reverted && !a.prior.is_empty() && keep(&a.project))
        {
            if let Remediation::SetPolicyOverride {
                project,
                policy,
                expires,
            } = &a.remediation
            {
                override_rows.push((
                    project.clone(),
                    policy.constraint.clone(),
                    expires.clone(),
                    expires.as_str() < today.as_str(),
                ));
            }
        }
        if override_rows.is_empty() {
            p.info("No org policy overrides are active.");
        } else {
            p.info("\nOrg policy overrides added by this tool:");
            p.table(
                &["Project", "Constraint", "Expires", "State"],
                override_rows
                    .iter()
                    .map(|(pr, c, e, expired)| {
                        vec![
                            pr.to_string(),
                            c.clone(),
                            e.clone(),
                            if *expired {
                                "EXPIRED".into()
                            } else {
                                "active".into()
                            },
                        ]
                    })
                    .collect(),
            );
        }
    }

    p.json(
        "status",
        &json!({
            "projects": state.projects.iter().filter(|(id, _)| keep(id)).map(|(id, ps)| json!({
                "id": id, "state": ps.status, "updated_at": ps.updated_at, "original_parent": ps.original_parent,
            })).collect::<Vec<_>>(),
            "smoke_results": smoke,
            "overrides": override_rows.iter().map(|(pr, c, e, expired)| json!({"project": pr, "constraint": c, "expires": e, "expired": expired})).collect::<Vec<_>>(),
            "pending_constraints": pending,
            "findings": outstanding,
        }),
    );
    Ok(0)
}
