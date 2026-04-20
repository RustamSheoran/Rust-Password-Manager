use std::process::ExitCode;

use clap::Parser;
use pass_manager::{cli::Cli, init_tracing, run_cli};

fn main() -> ExitCode {
    init_tracing();

    if let Err(error) = run_cli(Cli::parse()) {
        eprintln!("{error}");
        tracing::error!(?error, "application exited with an error");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
