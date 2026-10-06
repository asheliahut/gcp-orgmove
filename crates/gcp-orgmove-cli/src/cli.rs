//! Command-line definition (§3).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Table,
    Json,
}

#[derive(Debug, Clone, Args)]
pub struct Global {
    /// Manifest file.
    #[arg(long, global = true, default_value = "./orgmove.yaml")]
    pub manifest: PathBuf,
    /// Plan file.
    #[arg(long, global = true, default_value = "./orgmove.plan.json")]
    pub plan: PathBuf,
    /// State file.
    #[arg(long, global = true, default_value = "./orgmove.state.json")]
    pub state: PathBuf,
    /// Maximum parallel API operations (hard cap 16).
    #[arg(long, global = true, default_value_t = 4, value_parser = clap::value_parser!(u8).range(1..=16))]
    pub concurrency: u8,
    /// Output format. `json` is stable and machine-readable.
    #[arg(long, global = true, value_enum, default_value_t = Format::Table)]
    pub format: Format,
    /// Login for both organizations unless overridden below. One of
    /// `adc[:file]`, `gcloud[:account]`, `env[:VAR]`.
    #[arg(long, global = true, default_value = "adc")]
    pub token_source: String,
    /// Login for the source organization (overrides --token-source).
    #[arg(long, global = true)]
    pub source_auth: Option<String>,
    /// Login for the destination organization (overrides --token-source).
    #[arg(long, global = true)]
    pub destination_auth: Option<String>,
    /// Project billed for API usage (both organizations unless overridden below).
    #[arg(long, global = true)]
    pub quota_project: Option<String>,
    /// Quota project for the source login.
    #[arg(long, global = true)]
    pub source_quota_project: Option<String>,
    /// Quota project for the destination login.
    #[arg(long, global = true)]
    pub destination_quota_project: Option<String>,
    /// Which login performs `projects.move` when the logins differ. It needs
    /// rights on both sides: move on the project, create on the landing parent.
    #[arg(long, global = true, value_parser = ["source", "destination"], default_value = "source")]
    pub move_as: String,
    /// Disable ANSI colors.
    #[arg(long, global = true)]
    pub no_color: bool,
    /// Increase log verbosity (-v, -vv); logs go to stderr.
    #[arg(short = 'v', long = "verbose", global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
    /// Suppress non-error output.
    #[arg(short = 'q', long, global = true)]
    pub quiet: bool,
    /// Skip interactive confirmation on mutating commands.
    #[arg(long, global = true)]
    pub yes: bool,
    /// Print what would happen without mutating (the default unless --yes).
    #[arg(long, global = true)]
    pub dry_run: bool,
}

#[derive(Debug, Parser)]
#[command(
    name = "gcp-orgmove",
    version,
    long_version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("GCP_ORGMOVE_GIT_SHA"), ")"),
    about = "Move Google Cloud projects between organizations safely"
)]
pub struct Cli {
    #[command(flatten)]
    pub global: Global,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a starter manifest and validate authentication
    Init {
        #[arg(long)]
        source_org: Option<String>,
        #[arg(long)]
        destination_org: Option<String>,
        /// Overwrite an existing manifest.
        #[arg(long)]
        force: bool,
    },
    /// List projects in the source org/folder and optionally write them to the manifest
    Discover {
        #[arg(long = "source-folder")]
        source_folder: Vec<String>,
        /// Only projects with this label (k=v); repeatable, all must match.
        #[arg(long = "include-labels")]
        include_labels: Vec<String>,
        /// Skip projects with this label (k=v); repeatable, any match excludes.
        #[arg(long = "exclude-labels")]
        exclude_labels: Vec<String>,
        #[arg(long)]
        write_manifest: bool,
    },
    /// Run preflight and parity checks; write the plan file
    Plan {
        /// Skip a named parity check; repeatable.
        #[arg(long)]
        skip: Vec<String>,
        /// Restrict planning to specific projects; repeatable.
        #[arg(long)]
        only: Vec<String>,
        /// Treat warnings as blockers.
        #[arg(long)]
        strict: bool,
    },
    /// Check, fix, verify, or prune IAM/policy parity
    Parity {
        #[command(subcommand)]
        action: ParityAction,
    },
    /// Execute the plan: constraints, moves, restore
    Apply {
        #[arg(long)]
        keep_constraints: bool,
        #[arg(long)]
        project: Vec<String>,
        #[arg(long)]
        skip_smoke_tests: bool,
        #[arg(long)]
        continue_on_error: bool,
    },
    /// Confirm moved projects are in the expected state
    Verify {
        #[arg(long)]
        project: Vec<String>,
        /// Poll until the parent change is visible, up to this duration (e.g. 10m).
        #[arg(long)]
        wait: Option<String>,
    },
    /// Move projects back to their recorded original parents
    Rollback {
        #[arg(long)]
        project: Vec<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        revert_remediations: bool,
    },
    /// Show per-project state, overrides, and pending cleanup
    Status {
        #[arg(long)]
        project: Vec<String>,
        #[arg(long)]
        overrides: bool,
        #[arg(long)]
        findings: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ParityAction {
    Check {
        #[arg(long)]
        project: Vec<String>,
    },
    Fix {
        #[arg(long)]
        project: Vec<String>,
        #[arg(long)]
        iam_fix: Option<String>,
        #[arg(long)]
        policy_fix: Option<String>,
        #[arg(long)]
        allow_policy_overrides: bool,
        #[arg(long)]
        yes_widen_access: bool,
    },
    Verify {
        #[arg(long)]
        project: Vec<String>,
    },
    Prune {
        #[arg(long)]
        project: Vec<String>,
        #[arg(long)]
        older_than: Option<String>,
    },
}
