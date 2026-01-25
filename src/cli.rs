use crate::rules::Confidence;
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
    Mcp,
    Command,
    Rules,
    Docker,
    Dependency,
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

    /// Include test directories (tests/, spec/, __tests__, etc.) in scan
    #[arg(long)]
    pub include_tests: bool,

    /// Include node_modules directories in scan
    #[arg(long)]
    pub include_node_modules: bool,

    /// Include vendor directories (vendor/, third_party/) in scan
    #[arg(long)]
    pub include_vendor: bool,

    /// Minimum confidence level for findings to be reported
    #[arg(long, value_enum, default_value_t = Confidence::Tentative)]
    pub min_confidence: Confidence,

    /// Skip comment lines when scanning (lines starting with #, //, --, etc.)
    #[arg(long)]
    pub skip_comments: bool,

    /// Show fix hints in terminal output
    #[arg(long)]
    pub fix_hint: bool,

    /// Watch mode: continuously monitor files for changes and re-scan
    #[arg(short, long)]
    pub watch: bool,

    /// Install cc-audit pre-commit hook in the git repository
    #[arg(long)]
    pub init_hook: bool,

    /// Remove cc-audit pre-commit hook from the git repository
    #[arg(long)]
    pub remove_hook: bool,

    /// Path to a custom malware signatures database (JSON)
    #[arg(long)]
    pub malware_db: Option<PathBuf>,

    /// Disable malware signature scanning
    #[arg(long)]
    pub no_malware_scan: bool,

    /// Path to a custom rules file (YAML format)
    #[arg(long)]
    pub custom_rules: Option<PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Confidence;
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
    fn test_parse_type_mcp() {
        let cli = Cli::try_parse_from(["cc-audit", "--type", "mcp", "./mcp.json"]).unwrap();
        assert!(matches!(cli.scan_type, ScanType::Mcp));
    }

    #[test]
    fn test_parse_type_command() {
        let cli = Cli::try_parse_from(["cc-audit", "--type", "command", "./"]).unwrap();
        assert!(matches!(cli.scan_type, ScanType::Command));
    }

    #[test]
    fn test_parse_type_rules() {
        let cli = Cli::try_parse_from(["cc-audit", "--type", "rules", "./"]).unwrap();
        assert!(matches!(cli.scan_type, ScanType::Rules));
    }

    #[test]
    fn test_parse_type_docker() {
        let cli = Cli::try_parse_from(["cc-audit", "--type", "docker", "./"]).unwrap();
        assert!(matches!(cli.scan_type, ScanType::Docker));
    }

    #[test]
    fn test_parse_type_dependency() {
        let cli = Cli::try_parse_from(["cc-audit", "--type", "dependency", "./"]).unwrap();
        assert!(matches!(cli.scan_type, ScanType::Dependency));
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
        assert!(!cli.include_tests);
        assert!(!cli.include_node_modules);
        assert!(!cli.include_vendor);
        assert!(matches!(cli.min_confidence, Confidence::Tentative));
    }

    #[test]
    fn test_parse_include_tests() {
        let cli = Cli::try_parse_from(["cc-audit", "--include-tests", "./skill/"]).unwrap();
        assert!(cli.include_tests);
    }

    #[test]
    fn test_parse_include_node_modules() {
        let cli = Cli::try_parse_from(["cc-audit", "--include-node-modules", "./skill/"]).unwrap();
        assert!(cli.include_node_modules);
    }

    #[test]
    fn test_parse_include_vendor() {
        let cli = Cli::try_parse_from(["cc-audit", "--include-vendor", "./skill/"]).unwrap();
        assert!(cli.include_vendor);
    }

    #[test]
    fn test_parse_all_include_options() {
        let cli = Cli::try_parse_from([
            "cc-audit",
            "--include-tests",
            "--include-node-modules",
            "--include-vendor",
            "./skill/",
        ])
        .unwrap();
        assert!(cli.include_tests);
        assert!(cli.include_node_modules);
        assert!(cli.include_vendor);
    }

    #[test]
    fn test_parse_min_confidence_tentative() {
        let cli =
            Cli::try_parse_from(["cc-audit", "--min-confidence", "tentative", "./skill/"]).unwrap();
        assert!(matches!(cli.min_confidence, Confidence::Tentative));
    }

    #[test]
    fn test_parse_min_confidence_firm() {
        let cli =
            Cli::try_parse_from(["cc-audit", "--min-confidence", "firm", "./skill/"]).unwrap();
        assert!(matches!(cli.min_confidence, Confidence::Firm));
    }

    #[test]
    fn test_parse_min_confidence_certain() {
        let cli =
            Cli::try_parse_from(["cc-audit", "--min-confidence", "certain", "./skill/"]).unwrap();
        assert!(matches!(cli.min_confidence, Confidence::Certain));
    }

    #[test]
    fn test_parse_skip_comments() {
        let cli = Cli::try_parse_from(["cc-audit", "--skip-comments", "./skill/"]).unwrap();
        assert!(cli.skip_comments);
    }

    #[test]
    fn test_default_skip_comments_false() {
        let cli = Cli::try_parse_from(["cc-audit", "./skill/"]).unwrap();
        assert!(!cli.skip_comments);
    }

    #[test]
    fn test_parse_fix_hint() {
        let cli = Cli::try_parse_from(["cc-audit", "--fix-hint", "./skill/"]).unwrap();
        assert!(cli.fix_hint);
    }

    #[test]
    fn test_default_fix_hint_false() {
        let cli = Cli::try_parse_from(["cc-audit", "./skill/"]).unwrap();
        assert!(!cli.fix_hint);
    }

    #[test]
    fn test_parse_watch() {
        let cli = Cli::try_parse_from(["cc-audit", "--watch", "./skill/"]).unwrap();
        assert!(cli.watch);
    }

    #[test]
    fn test_parse_watch_short() {
        let cli = Cli::try_parse_from(["cc-audit", "-w", "./skill/"]).unwrap();
        assert!(cli.watch);
    }

    #[test]
    fn test_default_watch_false() {
        let cli = Cli::try_parse_from(["cc-audit", "./skill/"]).unwrap();
        assert!(!cli.watch);
    }

    #[test]
    fn test_parse_init_hook() {
        let cli = Cli::try_parse_from(["cc-audit", "--init-hook", "./repo/"]).unwrap();
        assert!(cli.init_hook);
    }

    #[test]
    fn test_parse_remove_hook() {
        let cli = Cli::try_parse_from(["cc-audit", "--remove-hook", "./repo/"]).unwrap();
        assert!(cli.remove_hook);
    }

    #[test]
    fn test_default_init_hook_false() {
        let cli = Cli::try_parse_from(["cc-audit", "./skill/"]).unwrap();
        assert!(!cli.init_hook);
    }

    #[test]
    fn test_default_remove_hook_false() {
        let cli = Cli::try_parse_from(["cc-audit", "./skill/"]).unwrap();
        assert!(!cli.remove_hook);
    }

    #[test]
    fn test_parse_malware_db() {
        let cli =
            Cli::try_parse_from(["cc-audit", "--malware-db", "./custom.json", "./skill/"]).unwrap();
        assert!(cli.malware_db.is_some());
        assert_eq!(cli.malware_db.unwrap().to_str().unwrap(), "./custom.json");
    }

    #[test]
    fn test_default_malware_db_none() {
        let cli = Cli::try_parse_from(["cc-audit", "./skill/"]).unwrap();
        assert!(cli.malware_db.is_none());
    }

    #[test]
    fn test_parse_no_malware_scan() {
        let cli = Cli::try_parse_from(["cc-audit", "--no-malware-scan", "./skill/"]).unwrap();
        assert!(cli.no_malware_scan);
    }

    #[test]
    fn test_default_no_malware_scan_false() {
        let cli = Cli::try_parse_from(["cc-audit", "./skill/"]).unwrap();
        assert!(!cli.no_malware_scan);
    }

    #[test]
    fn test_parse_custom_rules() {
        let cli = Cli::try_parse_from(["cc-audit", "--custom-rules", "./rules.yaml", "./skill/"])
            .unwrap();
        assert!(cli.custom_rules.is_some());
        assert_eq!(cli.custom_rules.unwrap().to_str().unwrap(), "./rules.yaml");
    }

    #[test]
    fn test_default_custom_rules_none() {
        let cli = Cli::try_parse_from(["cc-audit", "./skill/"]).unwrap();
        assert!(cli.custom_rules.is_none());
    }
}
