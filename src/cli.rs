use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum OutputFormat {
    #[default]
    Terminal,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum ScanType {
    #[default]
    Skill,
    Hook,
}

#[derive(Parser, Debug)]
#[command(
    name = "cc-audit",
    version,
    about = "Security auditor for Claude Code skills, hooks, and MCP servers",
    long_about = "cc-audit scans Claude Code skills, hooks, and MCP servers for security vulnerabilities before installation."
)]
pub struct Cli {
    /// Paths to scan (files or directories)
    #[arg(required = true)]
    pub paths: Vec<PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,

    /// Strict mode: show medium/low severity findings and treat warnings as errors
    #[arg(short, long)]
    pub strict: bool,

    /// Scan type
    #[arg(short = 't', long = "type", value_enum, default_value_t = ScanType::Skill)]
    pub scan_type: ScanType,

    /// Recursive scan
    #[arg(short, long)]
    pub recursive: bool,

    /// CI mode: non-interactive output
    #[arg(long)]
    pub ci: bool,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn test_parse_basic_args() {
        let cli = Cli::try_parse_from(["cc-audit", "./skill/"]).unwrap();
        assert_eq!(cli.paths.len(), 1);
        assert!(!cli.strict);
        assert!(!cli.recursive);
    }

    #[test]
    fn test_parse_multiple_paths() {
        let cli = Cli::try_parse_from(["cc-audit", "./skill1/", "./skill2/"]).unwrap();
        assert_eq!(cli.paths.len(), 2);
    }

    #[test]
    fn test_parse_format_json() {
        let cli = Cli::try_parse_from(["cc-audit", "--format", "json", "./skill/"]).unwrap();
        assert!(matches!(cli.format, OutputFormat::Json));
    }

    #[test]
    fn test_parse_strict_mode() {
        let cli = Cli::try_parse_from(["cc-audit", "--strict", "./skill/"]).unwrap();
        assert!(cli.strict);
    }

    #[test]
    fn test_parse_recursive() {
        let cli = Cli::try_parse_from(["cc-audit", "-r", "./skills/"]).unwrap();
        assert!(cli.recursive);
    }

    #[test]
    fn test_parse_format_sarif() {
        let cli = Cli::try_parse_from(["cc-audit", "--format", "sarif", "./skill/"]).unwrap();
        assert!(matches!(cli.format, OutputFormat::Sarif));
    }

    #[test]
    fn test_parse_type_hook() {
        let cli = Cli::try_parse_from(["cc-audit", "--type", "hook", "./settings.json"]).unwrap();
        assert!(matches!(cli.scan_type, ScanType::Hook));
    }

    #[test]
    fn test_parse_ci_mode() {
        let cli = Cli::try_parse_from(["cc-audit", "--ci", "./skill/"]).unwrap();
        assert!(cli.ci);
    }

    #[test]
    fn test_parse_verbose() {
        let cli = Cli::try_parse_from(["cc-audit", "-v", "./skill/"]).unwrap();
        assert!(cli.verbose);
    }

    #[test]
    fn test_parse_all_options() {
        let cli = Cli::try_parse_from([
            "cc-audit",
            "--format",
            "json",
            "--strict",
            "--type",
            "hook",
            "--recursive",
            "--ci",
            "--verbose",
            "./path/",
        ])
        .unwrap();
        assert!(matches!(cli.format, OutputFormat::Json));
        assert!(cli.strict);
        assert!(matches!(cli.scan_type, ScanType::Hook));
        assert!(cli.recursive);
        assert!(cli.ci);
        assert!(cli.verbose);
    }

    #[test]
    fn test_default_values() {
        let cli = Cli::try_parse_from(["cc-audit", "./skill/"]).unwrap();
        assert!(matches!(cli.format, OutputFormat::Terminal));
        assert!(matches!(cli.scan_type, ScanType::Skill));
        assert!(!cli.strict);
        assert!(!cli.recursive);
        assert!(!cli.ci);
        assert!(!cli.verbose);
    }
}
