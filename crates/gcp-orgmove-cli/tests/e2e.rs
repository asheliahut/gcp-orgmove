//! Opt-in end-to-end test against two REAL, disposable test organizations.
//!
//! It never runs by default: it is `#[ignore]`d and also requires
//! `GCP_ORGMOVE_E2E=1`. It creates throwaway projects with `gcloud`, drives
//! the real binary through the whole workflow, and always deletes the projects
//! afterwards. See docs/e2e.md for setup and what it touches.
//!
//! Required environment:
//!   GCP_ORGMOVE_E2E=1
//!   E2E_SOURCE_ORG   numeric source organization ID
//!   E2E_DEST_ORG     numeric destination organization ID
//! Optional:
//!   E2E_DEST_FOLDER  numeric folder ID in the destination to land in
//!   E2E_QUOTA_PROJECT project billed for API usage
//!   E2E_PROJECT_PREFIX prefix for created project IDs (default "orgmove-e2e")

use std::process::Command as Std;

use assert_cmd::Command;

struct Env {
    source: String,
    dest: String,
    folder: Option<String>,
    quota: Option<String>,
    prefix: String,
}

fn env() -> Option<Env> {
    if std::env::var("GCP_ORGMOVE_E2E").ok().as_deref() != Some("1") {
        eprintln!("skipping: set GCP_ORGMOVE_E2E=1 (and see docs/e2e.md) to run against real organizations");
        return None;
    }
    let need = |k: &str| {
        std::env::var(k).unwrap_or_else(|_| panic!("{k} must be set when GCP_ORGMOVE_E2E=1"))
    };
    Some(Env {
        source: need("E2E_SOURCE_ORG"),
        dest: need("E2E_DEST_ORG"),
        folder: std::env::var("E2E_DEST_FOLDER").ok(),
        quota: std::env::var("E2E_QUOTA_PROJECT").ok(),
        prefix: std::env::var("E2E_PROJECT_PREFIX").unwrap_or_else(|_| "orgmove-e2e".into()),
    })
}

fn gcloud(args: &[&str]) -> std::process::Output {
    Std::new("gcloud")
        .args(args)
        .output()
        .expect("gcloud must be installed and authenticated")
}

/// Deletes the projects whatever happens in the test body.
struct Cleanup(Vec<String>);
impl Drop for Cleanup {
    fn drop(&mut self) {
        for id in &self.0 {
            let out = gcloud(&["projects", "delete", id, "--quiet"]);
            if !out.status.success() {
                eprintln!(
                    "WARNING: could not delete {id}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
    }
}

fn parent_of(id: &str) -> String {
    let out = gcloud(&[
        "projects",
        "describe",
        id,
        "--format=value(parent.type,parent.id)",
    ]);
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .replace('\t', "/")
}

fn tool(dir: &std::path::Path, env: &Env, args: &[&str]) -> assert_cmd::assert::Assert {
    let mut cmd = Command::cargo_bin("gcp-orgmove").unwrap();
    cmd.current_dir(dir).args(args);
    if let Some(q) = &env.quota {
        cmd.args(["--quota-project", q]);
    }
    cmd.assert()
}

#[test]
#[ignore = "talks to real organizations; run with GCP_ORGMOVE_E2E=1 -- --ignored"]
fn full_workflow_against_real_organizations() {
    let Some(env) = env() else { return };
    let suffix = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    );
    let ids: Vec<String> = (1..=2)
        .map(|n| format!("{}-{suffix}-{n}", env.prefix))
        .collect();
    let _cleanup = Cleanup(ids.clone());

    for id in &ids {
        let out = gcloud(&[
            "projects",
            "create",
            id,
            &format!("--organization={}", env.source),
            "--quiet",
        ]);
        assert!(
            out.status.success(),
            "creating {id}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let dir = tempfile::tempdir().unwrap();
    let folder = env
        .folder
        .as_ref()
        .map(|f| format!("default_destination_folder: \"{f}\"\n"))
        .unwrap_or_default();
    let projects: String = ids.iter().map(|i| format!("  - id: {i}\n")).collect();
    std::fs::write(
        dir.path().join("orgmove.yaml"),
        format!("version: 1\nsource_org: \"{}\"\ndestination_org: \"{}\"\n{folder}projects:\n{projects}", env.source, env.dest),
    )
    .unwrap();

    // Plan is read-only; blockers (exit 4) mean the test setup is wrong, so fail loudly.
    tool(dir.path(), &env, &["plan"]).success();
    tool(dir.path(), &env, &["parity", "fix", "--yes"]).success();
    tool(dir.path(), &env, &["apply", "--yes"]).success();
    tool(dir.path(), &env, &["verify", "--wait", "10m"]).success();
    tool(dir.path(), &env, &["parity", "verify"]).success();

    let expected = match &env.folder {
        Some(f) => format!("folder/{f}"),
        None => format!("organization/{}", env.dest),
    };
    for id in &ids {
        assert_eq!(
            parent_of(id),
            expected,
            "{id} should be under the destination"
        );
    }

    tool(dir.path(), &env, &["rollback", "--all", "--yes"]).success();
    for id in &ids {
        assert_eq!(
            parent_of(id),
            format!("organization/{}", env.source),
            "{id} should be back in the source org"
        );
    }
}
