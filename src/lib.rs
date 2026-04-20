pub mod cli;
pub mod crypto;
pub mod error;
pub mod security;
pub mod ui;
pub mod vault;

use tracing_subscriber::EnvFilter;

pub use error::{AppError, Result};

pub fn run_cli(cli: cli::Cli) -> Result<()> {
    cli::commands::execute(cli)
}

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .try_init();
}
