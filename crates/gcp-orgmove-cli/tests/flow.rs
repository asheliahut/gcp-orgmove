use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use clap::Parser;
use futures::FutureExt;
use gcp_orgmove_cli::cli::Cli;
use gcp_orgmove_cli::output::Printer;
use gcp_orgmove_cli::{run, Ctx};
use gcp_orgmove_core::fake::FakeGcp;
use gcp_orgmove_core::{Error, Result};

const MANIFEST: &str = r#"version: 1
source_org: "111"
destination_org: "222"
default_destination_folder: "20"
# keep this comment
projects:
  - id: proj-aaaa
  - id: proj-bbbb
limits:
  batch_size: 1
"#;

fn world() -> FakeGcp {
    let f = FakeGcp::new();
    f.org("111").org("222");
    f.folder("10", "organizations/111");
    f.folder("20", "organizations/222");
    f.project("proj-aaaa", "1001", "folders/10");
    f.project("proj-bbbb", "1002", "folders/10");
    f.project("proj-cccc", "1003", "folders/10");
    f.set_op_polls(0);
    f
}

struct Run {
    code: Result<u8>,
    out: String,
}

async fn cli(gcp: &FakeGcp, dir: &Path, args: &[&str]) -> Run {
    let m = dir.join("orgmove.yaml");
    let p = dir.join("orgmove.plan.json");
    let s = dir.join("orgmove.state.json");
    let mut argv = vec![
        "gcp-orgmove".to_string(),
        "--manifest".into(),
        m.display().to_string(),
        "--plan".into(),
        p.display().to_string(),
        "--state".into(),
        s.display().to_string(),
    ];
    argv.extend(args.iter().map(|a| a.to_string()));
    let parsed = Cli::try_parse_from(argv).expect("valid args");
    let mut buf = vec![];
    let code = {
        let mut printer = Printer::new(parsed.global.format, parsed.global.quiet, &mut buf);
        let whoami = || async { Ok::<_, Error>("me@example.com".to_string()) }.boxed();
        let ctx = Ctx {
            global: &parsed.global,
            gcp,
            whoami: &whoami,
            now: chrono::Utc::now(),
            cancel: Arc::new(AtomicBool::new(false)),
            observer: gcp_orgmove_core::progress::silent(),
            interactive: false,
            confirm: &gcp_orgmove_cli::confirm::NeverConfirm,
        };
        run(&parsed.command, &ctx, &mut printer).await
    };
    Run {
        code,
        out: String::from_utf8(buf).unwrap(),
    }
}

fn write_manifest(dir: &Path) {
    std::fs::write(dir.join("orgmove.yaml"), MANIFEST).unwrap();
}

#[tokio::test]
async fn init_writes_a_loadable_template_and_refuses_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let g = world();
    let r = cli(
        &g,
        dir.path(),
        &["init", "--source-org", "111", "--destination-org", "222"],
    )
    .await;
    assert_eq!(r.code.unwrap(), 0);
    assert!(r.out.contains("Authenticated as me@example.com"));
    let text = std::fs::read_to_string(dir.path().join("orgmove.yaml")).unwrap();
    assert!(text.contains("source_org: \"111\""));
    // template has no projects yet, so loading it asks you to add some
    assert!(gcp_orgmove_core::Manifest::parse(&text)
        .unwrap_err()
        .message
        .contains("no projects"));

    let again = cli(&g, dir.path(), &["init"]).await;
    assert_eq!(again.code.unwrap_err().exit_code(), 2);
    assert_eq!(
        cli(&g, dir.path(), &["init", "--force"])
            .await
            .code
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn init_reports_unreadable_organization_as_exit_3() {
    let dir = tempfile::tempdir().unwrap();
    let g = world();
    g.deny_caller("organizations/222", "resourcemanager.organizations.get");
    let r = cli(
        &g,
        dir.path(),
        &["init", "--source-org", "111", "--destination-org", "222"],
    )
    .await;
    let e = r.code.unwrap_err();
    assert_eq!(e.exit_code(), 3);
    assert!(e.message.contains("destination"));
    assert!(
        !dir.path().join("orgmove.yaml").exists(),
        "nothing written on failure"
    );
}

#[tokio::test]
async fn discover_lists_filters_and_merges_into_manifest() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = world();
    g.set_project_labels(
        &"proj-cccc".parse().unwrap(),
        [("migrate".to_string(), "false".to_string())].into(),
    )
    .await
    .map(|_| ())
    .unwrap();
    use gcp_orgmove_core::Gcp;
    let r = cli(
        &g,
        dir.path(),
        &["discover", "--exclude-labels", "migrate=false"],
    )
    .await;
    assert_eq!(r.code.unwrap(), 0);
    assert!(
        r.out.contains("proj-aaaa") && !r.out.contains("proj-cccc"),
        "{}",
        r.out
    );

    let r = cli(&g, dir.path(), &["discover", "--write-manifest"]).await;
    assert_eq!(r.code.unwrap(), 0);
    let text = std::fs::read_to_string(dir.path().join("orgmove.yaml")).unwrap();
    assert!(text.contains("# keep this comment"));
    assert!(text.contains("- id: proj-cccc"));
    assert_eq!(
        text.matches("- id: proj-aaaa").count(),
        1,
        "existing entries are not duplicated"
    );
    assert!(gcp_orgmove_core::Manifest::parse(&text).is_ok());
    // second run adds nothing
    let again = cli(&g, dir.path(), &["discover", "--write-manifest"]).await;
    assert!(again.out.contains("Added 0 project(s)"));
}

#[tokio::test]
async fn plan_writes_file_prints_summary_and_never_mutates() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = world();
    let r = cli(&g, dir.path(), &["plan"]).await;
    assert_eq!(r.code.unwrap(), 0);
    assert!(g.mutating_calls().is_empty());
    assert!(r.out.contains("proj-aaaa") && r.out.contains("folders/20"));
    assert!(r.out.contains("allowedExportDestinations"));
    let plan = gcp_orgmove_core::Plan::load(&dir.path().join("orgmove.plan.json")).unwrap();
    assert_eq!(plan.projects.len(), 2);
    assert_eq!(plan.order.len(), 2);
}

#[tokio::test]
async fn plan_with_blockers_exits_4_but_still_writes_the_plan() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = world();
    g.deny_caller("projects/proj-aaaa", "resourcemanager.projects.move");
    let r = cli(&g, dir.path(), &["plan"]).await;
    assert_eq!(r.code.unwrap(), 4);
    assert!(r.out.contains("resourcemanager.projects.move"));
    assert!(dir.path().join("orgmove.plan.json").exists());
}

#[tokio::test]
async fn plan_json_output_is_a_single_versioned_document() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let r = cli(&world(), dir.path(), &["--format", "json", "plan"]).await;
    assert_eq!(r.code.unwrap(), 0);
    let v: serde_json::Value =
        serde_json::from_str(&r.out).expect("stdout is exactly one JSON document");
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["command"], "plan");
    assert_eq!(v["data"]["summary"]["projects"], 2);
}

#[tokio::test]
async fn apply_is_a_dry_run_without_yes_and_moves_with_it() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = world();
    assert_eq!(cli(&g, dir.path(), &["plan"]).await.code.unwrap(), 0);
    g.clear_calls();

    let dry = cli(&g, dir.path(), &["apply"]).await;
    assert_eq!(dry.code.unwrap(), 0);
    assert!(dry.out.contains("Dry run"));
    assert!(dry.out.contains("move proj-aaaa"));
    assert!(
        g.mutating_calls().is_empty(),
        "dry run must not mutate: {:?}",
        g.mutating_calls()
    );

    // --dry-run wins even with --yes
    let both = cli(&g, dir.path(), &["apply", "--yes", "--dry-run"]).await;
    assert!(both.out.contains("Dry run"));
    assert!(g.mutating_calls().is_empty());

    let real = cli(&g, dir.path(), &["apply", "--yes"]).await;
    assert_eq!(real.code.unwrap(), 0, "{}", real.out);
    assert_eq!(g.parent_of("proj-aaaa").to_string(), "folders/20");
    assert_eq!(g.parent_of("proj-bbbb").to_string(), "folders/20");
    assert_eq!(
        g.parent_of("proj-cccc").to_string(),
        "folders/10",
        "not in the plan, not moved"
    );
    assert!(real.out.contains("Constraints restored"));
    assert!(g
        .policy_at(
            "organizations/111",
            "constraints/resourcemanager.allowedExportDestinations"
        )
        .is_none());

    let st = cli(&g, dir.path(), &["status"]).await;
    assert_eq!(st.code.unwrap(), 0);
    assert!(st.out.contains("proj-aaaa") && st.out.contains("moved"));
}

#[tokio::test]
async fn apply_without_a_plan_explains_what_to_do() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let e = cli(&world(), dir.path(), &["apply", "--yes"])
        .await
        .code
        .unwrap_err();
    assert_eq!(e.exit_code(), 2);
    assert!(e.hint.unwrap().contains("plan"));
}

#[tokio::test]
async fn apply_after_manifest_edit_is_stale_exit_5() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    let edited = format!("{MANIFEST}# edited after planning\n");
    std::fs::write(dir.path().join("orgmove.yaml"), edited).unwrap();
    let e = cli(&g, dir.path(), &["apply", "--yes"])
        .await
        .code
        .unwrap_err();
    assert_eq!(e.exit_code(), 5);
    assert!(g.mutating_calls().is_empty());
}

#[tokio::test]
async fn apply_partial_failure_exits_6() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = world();
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    g.fail_next_operation("backend exploded");
    let r = cli(&g, dir.path(), &["apply", "--yes"]).await;
    assert_eq!(r.code.unwrap(), 6);
    assert!(r.out.contains("FAILED") && r.out.contains("backend exploded"));
    assert!(r.out.contains("Constraints restored"));
    let st = cli(&g, dir.path(), &["status"]).await;
    assert!(st.out.contains("failed: backend exploded"));
}

#[tokio::test]
async fn status_findings_lists_plan_findings() {
    let dir = tempfile::tempdir().unwrap();
    write_manifest(dir.path());
    let g = world();
    g.deny_caller("projects/proj-aaaa", "resourcemanager.projects.move");
    cli(&g, dir.path(), &["plan"]).await.code.unwrap_err_or_ok();
    let st = cli(&g, dir.path(), &["status", "--findings"]).await;
    assert!(
        st.out.contains("resourcemanager.projects.move"),
        "{}",
        st.out
    );
}

trait Ignore {
    fn unwrap_err_or_ok(self);
}
impl Ignore for Result<u8> {
    fn unwrap_err_or_ok(self) {}
}
