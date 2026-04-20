pub mod commands;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about = "Secure CLI password vault",
    propagate_version = true
)]
pub struct Cli {
    #[arg(long, global = true, value_name = "PATH", default_value = "db.json")]
    pub vault: PathBuf,
    #[arg(long, global = true, default_value_t = 300, value_name = "SECONDS")]
    pub auto_lock_seconds: u64,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Add(AddArgs),
    Get(GetArgs),
    List,
    Delete(DeleteArgs),
    Generate(GenerateArgs),
    Tui,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    pub site: String,
    #[arg(long)]
    pub force: bool,
    #[arg(long)]
    pub username: Option<String>,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    pub site: String,
}

#[derive(Debug, Args)]
pub struct DeleteArgs {
    pub site: String,
}

#[derive(Debug, Args)]
pub struct GenerateArgs {
    #[arg(long, default_value_t = 24)]
    pub length: usize,
    #[arg(long)]
    pub no_symbols: bool,
}
