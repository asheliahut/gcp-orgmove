#![allow(dead_code)]
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

pub const MANIFEST: &str = r#"version: 1
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

pub fn world() -> FakeGcp {
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

pub struct Run {
    pub code: Result<u8>,
    pub out: String,
}

/// Answers prompts from a script and records every question asked.
pub struct Scripted {
    answers: std::sync::Mutex<std::collections::VecDeque<bool>>,
    pub asked: std::sync::Mutex<Vec<(String, bool)>>,
}

impl Scripted {
    pub fn new(answers: &[bool]) -> Self {
        Self {
            answers: std::sync::Mutex::new(answers.iter().copied().collect()),
            asked: Default::default(),
        }
    }
    pub fn questions(&self) -> Vec<(String, bool)> {
        self.asked.lock().unwrap().clone()
    }
}

impl gcp_orgmove_cli::confirm::Confirm for Scripted {
    fn confirm(&self, question: &str, strict: bool) -> gcp_orgmove_core::Result<bool> {
        self.asked
            .lock()
            .unwrap()
            .push((question.to_string(), strict));
        Ok(self
            .answers
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected prompt"))
    }
}

/// Run a command as a script would: not interactive, no progress.
pub async fn cli(gcp: &FakeGcp, dir: &Path, args: &[&str]) -> Run {
    cli_with(
        gcp,
        dir,
        args,
        false,
        &gcp_orgmove_cli::confirm::NeverConfirm,
        gcp_orgmove_core::progress::silent(),
    )
    .await
}

/// Run a command as a person at a terminal would, answering prompts from `confirm`.
pub async fn cli_ask(gcp: &FakeGcp, dir: &Path, args: &[&str], confirm: &Scripted) -> Run {
    cli_with(
        gcp,
        dir,
        args,
        true,
        confirm,
        gcp_orgmove_core::progress::silent(),
    )
    .await
}

pub async fn cli_with(
    gcp: &FakeGcp,
    dir: &Path,
    args: &[&str],
    interactive: bool,
    confirm: &dyn gcp_orgmove_cli::confirm::Confirm,
    observer: gcp_orgmove_core::progress::SharedObserver,
) -> Run {
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
            observer,
            interactive,
            confirm,
        };
        run(&parsed.command, &ctx, &mut printer).await
    };
    Run {
        code,
        out: String::from_utf8(buf).unwrap(),
    }
}

pub fn write_manifest(dir: &Path) {
    std::fs::write(dir.join("orgmove.yaml"), MANIFEST).unwrap();
}
