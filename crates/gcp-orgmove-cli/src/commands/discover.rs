//! `discover` (§6.2): list candidate projects; optionally merge into the manifest.

use std::collections::BTreeSet;

use gcp_orgmove_core::state::atomic_write;
use gcp_orgmove_core::{FolderId, LifecycleState, Manifest, Parent, Project, Result};
use serde_json::json;

use crate::manifest_edit::add_projects;
use crate::output::Printer;
use crate::{load_manifest, parse_ids, parse_labels, Ctx};

pub async fn run(
    ctx: &Ctx<'_>,
    p: &mut Printer<'_>,
    source_folders: &[String],
    include: &[String],
    exclude: &[String],
    write_manifest: bool,
) -> Result<u8> {
    let loaded = load_manifest(&ctx.global.manifest)?;
    let include = parse_labels(include)?;
    let exclude = parse_labels(exclude)?;

    let parents: Vec<Parent> = if source_folders.is_empty() {
        vec![Parent::Org(loaded.manifest.source_org.clone())]
    } else {
        parse_ids::<FolderId>(source_folders)?
            .into_iter()
            .map(Parent::Folder)
            .collect()
    };

    let mut found: Vec<Project> = vec![];
    let mut seen = BTreeSet::new();
    for parent in &parents {
        for proj in ctx.gcp.list_projects(parent).await? {
            if proj.state == LifecycleState::Active && seen.insert(proj.id.clone()) {
                found.push(proj);
            }
        }
    }
    found.retain(|proj| {
        include.iter().all(|(k, v)| proj.labels.get(k) == Some(v))
            && !exclude.iter().any(|(k, v)| proj.labels.get(k) == Some(v))
    });
    found.sort_by(|a, b| a.id.cmp(&b.id));

    p.table(
        &["ID", "Number", "Parent", "Labels", "State"],
        found
            .iter()
            .map(|proj| {
                vec![
                    proj.id.to_string(),
                    proj.number.to_string(),
                    proj.parent.to_string(),
                    proj.labels
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join(","),
                    format!("{:?}", proj.state).to_uppercase(),
                ]
            })
            .collect(),
    );
    p.info(format!("{} project(s)", found.len()));

    let mut added = vec![];
    if write_manifest {
        let existing: BTreeSet<&gcp_orgmove_core::ProjectId> =
            loaded.manifest.projects.iter().map(|e| &e.id).collect();
        added = found
            .iter()
            .filter(|proj| !existing.contains(&proj.id))
            .map(|proj| proj.id.to_string())
            .collect();
        if !added.is_empty() {
            let text = std::fs::read_to_string(&ctx.global.manifest)?;
            let updated = add_projects(&text, &added);
            // Never write a manifest we could not load again.
            Manifest::parse(&updated)?;
            atomic_write(&ctx.global.manifest, updated.as_bytes())?;
        }
        p.info(format!(
            "Added {} project(s) to {}",
            added.len(),
            ctx.global.manifest.display()
        ));
    }

    p.json(
        "discover",
        &json!({
            "projects": found.iter().map(|proj| json!({
                "id": proj.id, "number": proj.number, "parent": proj.parent,
                "labels": proj.labels, "state": format!("{:?}", proj.state).to_uppercase(),
            })).collect::<Vec<_>>(),
            "added_to_manifest": added,
        }),
    );
    Ok(0)
}
