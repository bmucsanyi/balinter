mod astrules;
mod config;
mod finding;
mod noqa;
mod report;
mod rules;
mod scan;

use clap::{Parser, Subcommand, ValueEnum};
use finding::{Rule, ALL_RULES};
use std::path::{Path, PathBuf};
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
    /// Check files or directories
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
    /// Explain one rule, or list every rule when no selector is supplied
    Explain { rule: Option<String> },
    /// Print the effective configuration as JSON
    ShowSettings { path: Option<PathBuf> },
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
    Github,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("balinter: {error}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Command::Explain { rule } => {
            explain(rule.as_deref())?;
            Ok(ExitCode::SUCCESS)
        }
        Command::ShowSettings { path } => {
            let path = path.unwrap_or_else(|| PathBuf::from("."));
            let canonical = canonical_existing(&path)?;
            let start = if canonical.is_file() {
                canonical.parent().unwrap_or(&canonical)
            } else {
                &canonical
            };
            let (root, config) = config::Config::discover(start)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&config.settings_json(&root))
                    .map_err(|error| format!("could not serialize settings: {error}"))?
            );
            Ok(ExitCode::SUCCESS)
        }
        Command::Check {
            paths,
            output_format,
            statistics,
        } => {
            if statistics && matches!(output_format, OutputFormat::Sarif | OutputFormat::Github) {
                return Err("--statistics supports only text and JSON output".to_string());
            }
            let paths = if paths.is_empty() {
                vec![PathBuf::from(".")]
            } else {
                paths
            };
            let common = common_input_root(&paths)?;
            let (root, config) = config::Config::discover(&common)?;
            let scan = scan::scan(&root, &paths, &config)?;
            let findings = rules::evaluate(&scan, &config);
            report::print(&scan, &findings, output_format, statistics)?;
            Ok(if findings.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
    }
}

fn explain(selector: Option<&str>) -> Result<(), String> {
    if let Some(selector) = selector {
        let rule = Rule::parse(selector).ok_or_else(|| format!("unknown rule {selector:?}"))?;
        println!("{} {}\n{}", rule.code(), rule.name(), rule.explanation());
    } else {
        for rule in ALL_RULES {
            println!(
                "{}  {:<22} {}",
                rule.code(),
                rule.name(),
                rule.explanation()
            );
        }
    }
    Ok(())
}

fn common_input_root(paths: &[PathBuf]) -> Result<PathBuf, String> {
    let mut bases = paths
        .iter()
        .map(|path| {
            let canonical = canonical_existing(path)?;
            Ok(if canonical.is_dir() {
                canonical
            } else {
                canonical.parent().unwrap_or(Path::new("/")).to_path_buf()
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let mut common = bases
        .pop()
        .ok_or_else(|| "no input paths were supplied".to_string())?;
    for base in bases {
        while !base.starts_with(&common) {
            if !common.pop() {
                return Err("input paths do not share a filesystem root".to_string());
            }
        }
    }
    Ok(common)
}

fn canonical_existing(path: &Path) -> Result<PathBuf, String> {
    std::fs::canonicalize(path)
        .map_err(|error| format!("could not access {}: {error}", path.display()))
}
