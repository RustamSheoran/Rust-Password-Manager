mod cli;
mod crypto;
mod error;
mod security;
mod ui;
mod vault;

use std::process::ExitCode;

use clap::Parser;
use error::Result;
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    if let Err(error) = run() {
        eprintln!("{error}");
        tracing::error!(?error, "application exited with an error");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

fn run() -> Result<()> {
    init_tracing();
    let cli = cli::Cli::parse();
    cli::commands::execute(cli)
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .try_init();
}
