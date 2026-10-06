//! Interactive confirmation and progress reporting.

mod common;

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use clap::Parser;
use common::*;
use futures::FutureExt;
use gcp_orgmove_cli::cli::Cli;
use gcp_orgmove_cli::confirm::NeverConfirm;
use gcp_orgmove_cli::{Ctx, Mode};
use gcp_orgmove_core::fake::FakeGcp;
use gcp_orgmove_core::progress::{Event, Recorder};

fn mode_for(args: &[&str], interactive: bool) -> Mode {
    let mut argv = vec!["gcp-orgmove"];
    argv.extend_from_slice(args);
    argv.push("status");
    let cli = Cli::try_parse_from(argv).unwrap();
    let whoami = || async { Ok::<_, gcp_orgmove_core::Error>(String::new()) }.boxed();
    let gcp = FakeGcp::new();
    let ctx = Ctx {
        global: &cli.global,
        gcp: &gcp,
        whoami: &whoami,
        now: chrono::Utc::now(),
        cancel: Arc::new(AtomicBool::new(false)),
        observer: gcp_orgmove_core::progress::silent(),
        interactive,
        confirm: &NeverConfirm,
    };
    ctx.mode()
}

#[test]
fn the_run_mode_matrix() {
    use Mode::*;
    // (args, interactive, expected)
    let cases: &[(&[&str], bool, Mode)] = &[
        (&[], false, DryRun),
        (&[], true, Ask),
        (&["--yes"], false, Execute),
        (&["--yes"], true, Execute),
        (&["--dry-run"], true, DryRun),
        (&["--dry-run", "--yes"], true, DryRun),
        (&["--dry-run", "--yes"], false, DryRun),
        (&["--format", "json"], true, DryRun),
        (&["--format", "json", "--yes"], true, Execute),
        (&["-q"], true, DryRun),
        (&["-q", "--yes"], true, Execute),
    ];
    for (args, tty, want) in cases {
        assert_eq!(
            mode_for(args, *tty),
            *want,
            "args={args:?} interactive={tty}"
        );
    }
}

async fn planned(g: &FakeGcp, dir: &std::path::Path) {
    write_manifest(dir);
    assert_eq!(cli(g, dir, &["plan"]).await.code.unwrap(), 0);
    g.clear_calls();
}

#[tokio::test]
async fn apply_asks_shows_the_preview_and_proceeds_on_yes() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    planned(&g, dir.path()).await;
    let c = Scripted::new(&[true]);
    let r = cli_ask(&g, dir.path(), &["apply"], &c).await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    assert!(
        r.out.contains("`apply` will do the following") && r.out.contains("move proj-aaaa"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("Dry run"));
    assert_eq!(
        c.questions(),
        vec![("Move 2 project(s) now?".to_string(), false)]
    );
    assert_eq!(g.parent_of("proj-aaaa").to_string(), "folders/20");
    assert!(r.out.contains("Constraints restored"));
}

#[tokio::test]
async fn declining_changes_nothing_and_exits_zero() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    planned(&g, dir.path()).await;
    let r = cli_ask(&g, dir.path(), &["apply"], &Scripted::new(&[false])).await;
    assert_eq!(r.code.unwrap(), 0);
    assert!(r.out.contains("Aborted; nothing was changed."), "{}", r.out);
    assert!(g.mutating_calls().is_empty());
    assert_eq!(g.parent_of("proj-aaaa").to_string(), "folders/10");
}

#[tokio::test]
async fn no_prompt_with_yes_dry_run_json_or_quiet() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    planned(&g, dir.path()).await;
    let none = Scripted::new(&[]); // any prompt would panic ("unexpected prompt")
    for extra in [
        vec!["--dry-run"],
        vec!["--format", "json"],
        vec!["-q"],
        vec!["--dry-run", "--yes"],
    ] {
        let mut args = vec!["apply"];
        args.extend(extra.clone());
        let r = cli_ask(&g, dir.path(), &args, &none).await;
        assert_eq!(r.code.unwrap(), 0, "{extra:?}");
        assert!(
            g.mutating_calls().is_empty(),
            "{extra:?} must stay a dry run"
        );
    }
    let r = cli_ask(&g, dir.path(), &["apply", "--yes"], &none).await;
    assert_eq!(r.code.unwrap(), 0);
    assert!(none.questions().is_empty());
    assert_eq!(g.parent_of("proj-aaaa").to_string(), "folders/20");
}

#[tokio::test]
async fn a_script_without_yes_still_gets_a_dry_run() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    planned(&g, dir.path()).await;
    let r = cli(&g, dir.path(), &["apply"]).await; // non-interactive
    assert!(r.out.contains("Dry run"));
    assert!(g.mutating_calls().is_empty());
}

#[tokio::test]
async fn rollback_demands_the_full_word_yes() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    planned(&g, dir.path()).await;
    cli(&g, dir.path(), &["apply", "--yes"]).await.code.unwrap();

    let no = Scripted::new(&[false]);
    let r = cli_ask(&g, dir.path(), &["rollback", "--all"], &no).await;
    assert!(r.out.contains("Aborted"));
    assert_eq!(
        no.questions(),
        vec![("Roll back 2 project(s)?".to_string(), true)],
        "strict prompt"
    );
    assert_eq!(g.parent_of("proj-aaaa").to_string(), "folders/20");

    let yes = Scripted::new(&[true]);
    let r = cli_ask(&g, dir.path(), &["rollback", "--all"], &yes).await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    assert_eq!(g.parent_of("proj-aaaa").to_string(), "folders/10");
}

fn gap_world() -> FakeGcp {
    let g = world();
    g.grant(
        "organizations/111",
        "roles/compute.viewer",
        "group:eng@x.com",
    );
    g
}

#[tokio::test]
async fn parity_fix_previews_then_asks_then_applies() {
    let (dir, g) = (tempfile::tempdir().unwrap(), gap_world());
    planned(&g, dir.path()).await;
    let c = Scripted::new(&[true]);
    let r = cli_ask(&g, dir.path(), &["parity", "fix"], &c).await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    assert!(
        r.out.contains("Planned changes:") && r.out.contains("would apply"),
        "{}",
        r.out
    );
    assert!(
        r.out.contains("Results:") && r.out.contains("applied"),
        "{}",
        r.out
    );
    assert!(r.out.contains("All gaps are resolved"));
    assert_eq!(
        c.questions(),
        vec![("Apply 2 change(s)?".to_string(), false)]
    );
    assert!(g
        .iam_at("projects/proj-aaaa")
        .bindings
        .iter()
        .any(|b| b.role.as_str() == "roles/compute.viewer"));
}

#[tokio::test]
async fn parity_fix_declined_applies_nothing() {
    let (dir, g) = (tempfile::tempdir().unwrap(), gap_world());
    planned(&g, dir.path()).await;
    let r = cli_ask(&g, dir.path(), &["parity", "fix"], &Scripted::new(&[false])).await;
    assert_eq!(r.code.unwrap(), 0);
    assert!(r.out.contains("Aborted"));
    assert!(g.mutating_calls().is_empty());
}

#[tokio::test]
async fn parity_fix_with_nothing_to_do_does_not_prompt() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    planned(&g, dir.path()).await;
    let none = Scripted::new(&[]);
    let r = cli_ask(&g, dir.path(), &["parity", "fix"], &none).await;
    assert_eq!(r.code.unwrap(), 0);
    assert!(r.out.contains("Nothing to apply"));
}

#[tokio::test]
async fn widening_access_needs_its_consent_flag_before_any_prompt_and_a_strict_yes_after() {
    let (dir, g) = (tempfile::tempdir().unwrap(), gap_world());
    planned(&g, dir.path()).await;
    let none = Scripted::new(&[]);
    let e = cli_ask(
        &g,
        dir.path(),
        &["parity", "fix", "--iam-fix", "folder"],
        &none,
    )
    .await
    .code
    .unwrap_err();
    assert_eq!(e.exit_code(), 2);
    assert!(none.questions().is_empty(), "refused before asking");

    let c = Scripted::new(&[true]);
    let r = cli_ask(
        &g,
        dir.path(),
        &["parity", "fix", "--iam-fix", "folder", "--yes-widen-access"],
        &c,
    )
    .await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    assert!(c.questions()[0].1, "widening asks for the full word yes");
    assert!(g
        .iam_at("folders/20")
        .bindings
        .iter()
        .any(|b| b.role.as_str() == "roles/compute.viewer"));
}

#[tokio::test]
async fn parity_prune_demands_the_full_word_yes() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    g.grant("projects/proj-aaaa", "roles/owner", "user:o@x.com");
    g.grant("organizations/111", "roles/viewer", "user:a@x.com");
    write_manifest(dir.path());
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    cli(&g, dir.path(), &["parity", "fix", "--yes"])
        .await
        .code
        .unwrap();
    cli(&g, dir.path(), &["apply", "--yes"]).await.code.unwrap();
    cli(&g, dir.path(), &["parity", "verify"])
        .await
        .code
        .unwrap();
    g.grant("folders/20", "roles/viewer", "user:a@x.com"); // destination now covers it
    g.clear_calls();

    let no = Scripted::new(&[false]);
    let r = cli_ask(&g, dir.path(), &["parity", "prune"], &no).await;
    assert!(
        r.out.contains("will remove exactly this access") && r.out.contains("Aborted"),
        "{}",
        r.out
    );
    assert!(no.questions()[0].1, "prune is strict");
    assert!(g.mutating_calls().is_empty());

    let yes = Scripted::new(&[true]);
    let r = cli_ask(&g, dir.path(), &["parity", "prune"], &yes).await;
    assert_eq!(r.code.unwrap(), 0, "{}", r.out);
    assert!(r.out.contains("removed"));
}

// ---------------------------------------------------------------- progress

async fn observed(g: &FakeGcp, dir: &std::path::Path, args: &[&str]) -> Arc<Recorder> {
    let rec = Recorder::new();
    let r = cli_with(g, dir, args, false, &NeverConfirm, rec.clone()).await;
    r.code.unwrap_or_else(|e| panic!("{args:?}: {e}"));
    rec
}

fn last_is_end(rec: &Recorder) -> bool {
    matches!(rec.events().last(), Some(Event::End))
}

#[tokio::test]
async fn each_long_command_reports_progress_and_closes_it() {
    let (dir, g) = (tempfile::tempdir().unwrap(), gap_world());
    write_manifest(dir.path());

    let rec = observed(&g, dir.path(), &["plan"]).await;
    assert!(rec
        .phases()
        .iter()
        .any(|(n, t)| n == "Analyzing moves" && *t == 2));
    assert!(rec
        .phases()
        .iter()
        .any(|(n, _)| n == "Running parity checks"));
    assert!(last_is_end(&rec));

    let rec = observed(&g, dir.path(), &["parity", "check"]).await;
    assert!(rec
        .phases()
        .iter()
        .any(|(n, _)| n == "Running parity checks"));
    assert!(last_is_end(&rec));

    let rec = observed(&g, dir.path(), &["parity", "fix", "--yes"]).await;
    assert_eq!(rec.phases(), vec![("Applying changes".to_string(), 2)]);
    assert_eq!((rec.ticks(), rec.ends()), (2, 1));

    let rec = observed(&g, dir.path(), &["apply", "--yes"]).await;
    assert_eq!(rec.phases(), vec![("Moving projects".to_string(), 2)]);
    assert_eq!(rec.ticks(), 2);
    assert!(last_is_end(&rec));

    let rec = observed(&g, dir.path(), &["verify"]).await;
    assert_eq!(rec.phases(), vec![("Verifying projects".to_string(), 2)]);
    assert_eq!((rec.ticks(), rec.ends()), (2, 1));

    let rec = observed(&g, dir.path(), &["parity", "verify"]).await;
    assert_eq!(rec.phases(), vec![("Verifying parity".to_string(), 2)]);

    let rec = observed(&g, dir.path(), &["rollback", "--all", "--yes"]).await;
    assert_eq!(rec.phases(), vec![("Rolling back projects".to_string(), 2)]);
    assert_eq!((rec.ticks(), rec.ends()), (2, 1));
}

#[tokio::test]
async fn dry_runs_and_previews_draw_no_progress() {
    let (dir, g) = (tempfile::tempdir().unwrap(), gap_world());
    write_manifest(dir.path());
    cli(&g, dir.path(), &["plan"]).await.code.unwrap();
    for args in [
        vec!["apply"],
        vec!["parity", "fix"],
        vec!["rollback", "--all"],
    ] {
        let rec = Recorder::new();
        let _ = cli_with(&g, dir.path(), &args, false, &NeverConfirm, rec.clone()).await;
        assert!(rec.events().is_empty(), "{args:?}: {:?}", rec.events());
    }
}

#[tokio::test]
async fn progress_never_leaks_into_stdout() {
    let (dir, g) = (tempfile::tempdir().unwrap(), world());
    write_manifest(dir.path());
    let rec = Recorder::new();
    let r = cli_with(
        &g,
        dir.path(),
        &["--format", "json", "plan"],
        false,
        &NeverConfirm,
        rec.clone(),
    )
    .await;
    assert!(rec.ticks() > 0, "events were emitted");
    let v: serde_json::Value =
        serde_json::from_str(&r.out).expect("stdout is still exactly one JSON document");
    assert_eq!(v["command"], "plan");
}
