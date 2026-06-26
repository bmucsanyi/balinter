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
    /// Check the given files or directories for bloat
    Check {
        /// Files or directories to check (defaults to the current directory)
        paths: Vec<PathBuf>,
        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        output_format: OutputFormat,
        /// Print per-rule counts instead of individual findings
        #[arg(long)]
        statistics: bool,
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
        Command::Check {
            paths,
            output_format,
            statistics,
        } => {
            let paths = if paths.is_empty() {
                vec![PathBuf::from(".")]
            } else {
                paths
            };
            for path in &paths {
                if !path.exists() {
                    eprintln!("balinter: path does not exist: {}", path.display());
                    return ExitCode::from(2);
                }
            }

            // Config is discovered by walking up from the first path, then applied to all.
            let cfg_root = std::fs::canonicalize(&paths[0]).unwrap_or_else(|_| paths[0].clone());
            let cfg = config::Config::discover(&cfg_root);

            let mut files = Vec::new();
            for path in &paths {
                let root = std::fs::canonicalize(path).unwrap_or_else(|_| path.clone());
                files.extend(scan::scan(&root, &cfg).files);
            }
            let scan = scan::Scan { files };

            let findings = rules::evaluate(&scan, &cfg);
            let json = matches!(output_format, OutputFormat::Json);
            report::print(&scan, &findings, json, statistics);

            if findings.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
