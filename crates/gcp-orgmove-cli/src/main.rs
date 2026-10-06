use std::io::IsTerminal;
use std::io::Write;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use clap::Parser;
use futures::FutureExt;
use gcp_orgmove_cli::cli::{Cli, Format};
use gcp_orgmove_cli::confirm::{stdio_is_interactive, StdinConfirm};
use gcp_orgmove_cli::login;
use gcp_orgmove_cli::output::Printer;
use gcp_orgmove_cli::progress_ui::IndicatifObserver;
use gcp_orgmove_cli::{format_error, needs_gcp, run, Ctx};
use gcp_orgmove_core::{Error, Gcp, Result};

const TOKENINFO_URL: &str = "https://oauth2.googleapis.com/tokeninfo";

fn init_logging(verbose: u8, quiet: bool) {
    let level = match (quiet, verbose) {
        (true, _) => "error",
        (_, 0) => "warn",
        (_, 1) => "info",
        _ => "debug",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

async fn real_main(cli: Cli) -> Result<u8> {
    let cancel = Arc::new(AtomicBool::new(false));
    gcp_orgmove_cli::signals::install(cancel.clone());

    // Bars draw on stderr, only for a person watching a terminal; stdout stays
    // a clean table or one JSON document.
    let show_progress =
        std::io::stderr().is_terminal() && !cli.global.quiet && cli.global.format == Format::Table;
    let observer: gcp_orgmove_core::progress::SharedObserver =
        Arc::new(IndicatifObserver::new(show_progress));
    let interactive = stdio_is_interactive();

    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let mut printer = Printer::new(cli.global.format, cli.global.quiet, &mut lock);

    if !needs_gcp(&cli.command) {
        // Read-only commands never touch credentials.
        let unused = gcp_orgmove_core::fake::FakeGcp::new();
        let whoami = || async { Err::<String, Error>(Error::internal("not available")) }.boxed();
        let ctx = Ctx {
            global: &cli.global,
            gcp: &unused,
            whoami: &whoami,
            now: chrono::Utc::now(),
            cancel,
            observer,
            interactive,
            confirm: &StdinConfirm,
        };
        return run(&cli.command, &ctx, &mut printer).await;
    }

    let logins = login::build(&cli.global)?;
    if logins.plan.is_split() && !cli.global.quiet {
        eprintln!("auth: {}", logins.plan.describe());
    }
    login::seed_hints(&logins.gcp, &cli.command, &cli.global.manifest);
    let http = reqwest::Client::new();
    let whoami = || {
        let http = http.clone();
        let logins = &logins;
        async move { logins.whoami(&http, TOKENINFO_URL).await }.boxed()
    };
    let gcp_ref: &dyn Gcp = &logins.gcp;
    let ctx = Ctx {
        global: &cli.global,
        gcp: gcp_ref,
        whoami: &whoami,
        now: chrono::Utc::now(),
        cancel,
        observer,
        interactive,
        confirm: &StdinConfirm,
    };
    run(&cli.command, &ctx, &mut printer).await
}

fn main() -> ExitCode {
    let cli = Cli::parse(); // usage errors exit 2 via clap
    init_logging(cli.global.verbose, cli.global.quiet);
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot start async runtime: {e}");
            return ExitCode::from(1);
        }
    };
    let code = match rt.block_on(real_main(cli)) {
        Ok(code) => code,
        Err(e) => {
            let _ = std::io::stdout().flush();
            eprintln!("{}", format_error(&e));
            e.exit_code()
        }
    };
    ExitCode::from(code)
}
