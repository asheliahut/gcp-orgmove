//! gcp-orgmove command implementations.
//!
//! Commands are plain async functions over `&dyn Gcp`, so they run against
//! the in-memory fake in tests and the official-SDK client in the binary.

pub mod cli;
pub mod commands;
pub mod confirm;
pub mod login;
pub mod manifest_edit;
pub mod output;
pub mod progress_ui;
pub mod signals;

use std::path::Path;

use chrono::{DateTime, Utc};
use cli::{Command, Global, ParityAction};
use confirm::Confirm;
use futures::future::BoxFuture;
use gcp_orgmove_core::apply::CancelFlag;
use gcp_orgmove_core::progress::SharedObserver;
use gcp_orgmove_core::{Error, ErrorKind, Gcp, LoadedManifest, Manifest, Result};
use output::Printer;

/// Everything a command needs from its environment.
pub struct Ctx<'a> {
    pub global: &'a Global,
    pub gcp: &'a dyn Gcp,
    /// Email of the authenticated principal (a network call; only `init` uses it).
    pub whoami: &'a (dyn Fn() -> BoxFuture<'a, Result<String>> + Sync),
    pub now: DateTime<Utc>,
    pub cancel: CancelFlag,
    /// Receives progress events from the engines.
    pub observer: SharedObserver,
    /// Whether a person is at the terminal (stdin and stderr are TTYs).
    pub interactive: bool,
    pub confirm: &'a dyn Confirm,
}

/// How a mutating command should proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Show what would happen; change nothing.
    DryRun,
    /// Do it.
    Execute,
    /// Show what would happen, then ask.
    Ask,
}

impl Ctx<'_> {
    /// `--dry-run` always wins and never prompts. `--yes` executes. Without
    /// either, a person at a terminal is asked; anything else (a script, `-q`,
    /// `--format json`) gets a dry run, because it could not see the preview.
    pub fn mode(&self) -> Mode {
        let g = self.global;
        if g.dry_run {
            Mode::DryRun
        } else if g.yes {
            Mode::Execute
        } else if self.interactive && g.format == cli::Format::Table && !g.quiet {
            Mode::Ask
        } else {
            Mode::DryRun
        }
    }

    /// Call after printing the preview. `true` = go ahead. In `Ask` mode this
    /// prompts; a refusal prints "Aborted" and returns `false`.
    pub fn proceed(&self, p: &mut Printer<'_>, question: &str, strict: bool) -> Result<bool> {
        match self.mode() {
            Mode::Execute => Ok(true),
            Mode::DryRun => Ok(false),
            Mode::Ask => {
                if self.confirm.confirm(question, strict)? {
                    Ok(true)
                } else {
                    p.info("Aborted; nothing was changed.");
                    Ok(false)
                }
            }
        }
    }
}

/// Whether a command needs credentials (and therefore a `Gcp`).
pub fn needs_gcp(cmd: &Command) -> bool {
    !matches!(cmd, Command::Status { .. })
}

pub fn load_manifest(path: &Path) -> Result<LoadedManifest> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("cannot read manifest {}: {e}", path.display()),
        )
        .with_hint("run `gcp-orgmove init` to create one")
    })?;
    Manifest::parse(&text)
}

pub async fn run(cmd: &Command, ctx: &Ctx<'_>, p: &mut Printer<'_>) -> Result<u8> {
    match cmd {
        Command::Init {
            source_org,
            destination_org,
            force,
        } => {
            commands::init::run(
                ctx,
                p,
                source_org.as_deref(),
                destination_org.as_deref(),
                *force,
            )
            .await
        }
        Command::Discover {
            source_folder,
            include_labels,
            exclude_labels,
            write_manifest,
        } => {
            commands::discover::run(
                ctx,
                p,
                source_folder,
                include_labels,
                exclude_labels,
                *write_manifest,
            )
            .await
        }
        Command::Plan { skip, only, strict } => {
            commands::plan::run(ctx, p, skip, only, *strict).await
        }
        Command::Apply {
            keep_constraints,
            project,
            skip_smoke_tests,
            continue_on_error,
        } => {
            commands::apply::run(
                ctx,
                p,
                *keep_constraints,
                project,
                *skip_smoke_tests,
                *continue_on_error,
            )
            .await
        }
        Command::Status {
            project,
            overrides,
            findings,
        } => commands::status::run(ctx, p, project, *overrides, *findings),
        Command::Verify { project, wait } => {
            commands::verify::run(ctx, p, project, wait.as_deref()).await
        }
        Command::Rollback {
            project,
            all,
            revert_remediations,
        } => commands::rollback::run(ctx, p, project, *all, *revert_remediations).await,
        Command::Parity { action } => match action {
            ParityAction::Check { project } => commands::parity::check(ctx, p, project).await,
            ParityAction::Fix {
                project,
                iam_fix,
                policy_fix,
                allow_policy_overrides,
                yes_widen_access,
            } => {
                commands::parity::fix(
                    ctx,
                    p,
                    project,
                    iam_fix.as_deref(),
                    policy_fix.as_deref(),
                    *allow_policy_overrides,
                    *yes_widen_access,
                )
                .await
            }
            ParityAction::Verify { project } => commands::parity::verify(ctx, p, project).await,
            ParityAction::Prune {
                project,
                older_than,
            } => commands::parity::prune(ctx, p, project, older_than.as_deref()).await,
        },
    }
}

/// Render an error for the terminal: message, resource, hint.
pub fn format_error(e: &Error) -> String {
    let mut s = format!("error: {}", e.message);
    if let Some(r) = &e.resource {
        if !e.message.contains(r.as_str()) {
            s.push_str(&format!("\n  resource: {r}"));
        }
    }
    if let Some(h) = &e.hint {
        s.push_str(&format!("\n  hint: {h}"));
    }
    s
}

pub(crate) fn parse_ids<T: std::str::FromStr<Err = Error>>(raw: &[String]) -> Result<Vec<T>> {
    raw.iter().map(|s| s.parse()).collect()
}

/// `k=v` label filters.
pub(crate) fn parse_labels(raw: &[String]) -> Result<Vec<(String, String)>> {
    raw.iter()
        .map(|s| {
            s.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| {
                    Error::invalid(format!("label filter {s:?} must look like key=value"))
                })
        })
        .collect()
}
