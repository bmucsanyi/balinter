mod astrules;
mod config;
mod finding;
mod noqa;
mod report;
mod rules;
mod scan;

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "balinter",
    version,
    about = "Opinionated linter for sprawling research codebases"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check a directory for bloat
    Check {
        /// Directory to check
        #[arg(default_value = ".")]
        path: PathBuf,
        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Check { path, format } => {
            if !path.exists() {
                eprintln!("balinter: path does not exist: {}", path.display());
                return ExitCode::from(2);
            }

            let root = std::fs::canonicalize(&path).unwrap_or(path);
            let cfg = config::Config::load(&root);
            let scan = scan::scan(&root);
            let findings = rules::evaluate(&scan, &cfg);
            report::print(&scan, &findings, matches!(format, OutputFormat::Json));

            if findings.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
