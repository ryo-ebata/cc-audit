use crate::client::ClientType;
use crate::rules::{Confidence, ParseEnumError, RuleSeverity, Severity};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Terminal,
    Json,
    Sarif,
    Html,
    Markdown,
}

impl std::str::FromStr for OutputFormat {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "terminal" | "term" => Ok(OutputFormat::Terminal),
            "json" => Ok(OutputFormat::Json),
            "sarif" => Ok(OutputFormat::Sarif),
            "html" => Ok(OutputFormat::Html),
            "markdown" | "md" => Ok(OutputFormat::Markdown),
            _ => Err(ParseEnumError::invalid("OutputFormat", s)),
        }
    }
}

/// Badge output format for security badges
#[derive(Debug, Clone, Copy, ValueEnum, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BadgeFormat {
    /// shields.io URL only
    Url,
    /// Markdown badge with link
    #[default]
    Markdown,
    /// HTML image tag
    Html,
}

impl std::str::FromStr for BadgeFormat {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "url" => Ok(BadgeFormat::Url),
            "markdown" | "md" => Ok(BadgeFormat::Markdown),
            "html" => Ok(BadgeFormat::Html),
            _ => Err(ParseEnumError::invalid("BadgeFormat", s)),
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanType {
    #[default]
    Skill,
    Hook,
    Mcp,
    Command,
    Rules,
    Docker,
    Dependency,
    /// Scan .claude/agents/ subagent definitions
    Subagent,
    /// Scan marketplace.json plugin definitions
    Plugin,
}

impl std::str::FromStr for ScanType {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "skill" => Ok(ScanType::Skill),
            "hook" => Ok(ScanType::Hook),
            "mcp" => Ok(ScanType::Mcp),
            "command" | "cmd" => Ok(ScanType::Command),
            "rules" => Ok(ScanType::Rules),
            "docker" => Ok(ScanType::Docker),
            "dependency" | "dep" | "deps" => Ok(ScanType::Dependency),
            "subagent" | "agent" => Ok(ScanType::Subagent),
            "plugin" => Ok(ScanType::Plugin),
            _ => Err(ParseEnumError::invalid("ScanType", s)),
        }
    }
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
    #[arg(required_unless_present_any = ["remote", "remote_list", "awesome_claude_code", "init", "all_clients", "client"])]
    pub paths: Vec<PathBuf>,

    /// Scan all installed AI coding clients (Claude, Cursor, Windsurf, VS Code)
    #[arg(long, conflicts_with_all = ["remote", "remote_list", "awesome_claude_code", "client"])]
    pub all_clients: bool,

    /// Scan a specific AI coding client
    #[arg(long, value_enum, conflicts_with_all = ["remote", "remote_list", "awesome_claude_code", "all_clients"])]
    pub client: Option<ClientType>,

    /// Remote repository URL to scan (e.g., `https://github.com/user/repo`)
    #[arg(long, value_name = "URL")]
    pub remote: Option<String>,

    /// Git ref (branch, tag, or commit) for remote scan
    #[arg(long, default_value = "HEAD")]
    pub git_ref: String,

    /// GitHub token for authentication (or use GITHUB_TOKEN env var)
    #[arg(long, env = "GITHUB_TOKEN", value_name = "TOKEN")]
    pub remote_auth: Option<String>,

    /// File containing list of repository URLs to scan (one per line)
    #[arg(long, conflicts_with = "remote", value_name = "FILE")]
    pub remote_list: Option<PathBuf>,

    /// Scan all repositories from awesome-claude-code
    #[arg(long, conflicts_with_all = ["remote", "remote_list"])]
    pub awesome_claude_code: bool,

    /// Maximum number of parallel repository clones
    #[arg(long, default_value = "4")]
    pub parallel_clones: usize,

    /// Generate security badge
    #[arg(long)]
    pub badge: bool,

    /// Badge output format (url, markdown, html)
    #[arg(long, value_enum, default_value_t = BadgeFormat::Markdown)]
    pub badge_format: BadgeFormat,

    /// Show summary only (for batch scans)
    #[arg(long)]
    pub summary: bool,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Terminal)]
    pub format: OutputFormat,

    /// Strict mode: show medium/low severity findings and treat warnings as errors
    #[arg(short, long)]
    pub strict: bool,

    /// Warn-only mode: treat all findings as warnings (exit code 0)
    #[arg(long)]
    pub warn_only: bool,

    /// Minimum severity level to include in output (critical, high, medium, low)
    #[arg(long, value_enum)]
    pub min_severity: Option<Severity>,

    /// Minimum rule severity to treat as errors (error, warn)
    #[arg(long, value_enum)]
    pub min_rule_severity: Option<RuleSeverity>,

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

    /// Path to a custom CVE database (JSON)
    #[arg(long)]
    pub cve_db: Option<PathBuf>,

    /// Disable CVE vulnerability scanning
    #[arg(long)]
    pub no_cve_scan: bool,

    /// Path to a custom rules file (YAML format)
    #[arg(long)]
    pub custom_rules: Option<PathBuf>,

    /// Create a baseline snapshot for drift detection (rug pull prevention)
    #[arg(long)]
    pub baseline: bool,

    /// Check for drift against saved baseline
    #[arg(long)]
    pub check_drift: bool,

    /// Generate a default configuration file template
    #[arg(long)]
    pub init: bool,

    /// Output file path (for HTML/JSON output)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Save baseline to specified file
    #[arg(long, value_name = "FILE")]
    pub save_baseline: Option<PathBuf>,

    /// Compare against baseline file (show only new findings)
    #[arg(long, value_name = "FILE")]
    pub baseline_file: Option<PathBuf>,

    /// Compare two paths and show differences
    #[arg(long, num_args = 2, value_names = ["PATH1", "PATH2"])]
    pub compare: Option<Vec<PathBuf>>,

    /// Auto-fix issues (where possible)
    #[arg(long)]
    pub fix: bool,

    /// Preview auto-fix changes without applying them
    #[arg(long)]
    pub fix_dry_run: bool,

    /// Run as MCP server
    #[arg(long)]
    pub mcp_server: bool,

    /// Enable deep scan with deobfuscation
    #[arg(long)]
    pub deep_scan: bool,

    /// Load settings from a named profile
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Save current settings as a named profile
    #[arg(long, value_name = "NAME")]
    pub save_profile: Option<String>,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            all_clients: false,
            client: None,
            remote: None,
            git_ref: "HEAD".to_string(),
            remote_auth: None,
            remote_list: None,
            awesome_claude_code: false,
            parallel_clones: 4,
            badge: false,
            badge_format: BadgeFormat::Markdown,
            summary: false,
            format: OutputFormat::Terminal,
            strict: false,
            warn_only: false,
            min_severity: None,
            min_rule_severity: None,
            scan_type: ScanType::Skill,
            recursive: false,
            ci: false,
            verbose: false,
            include_tests: false,
            include_node_modules: false,
            include_vendor: false,
            min_confidence: Confidence::Tentative,
            skip_comments: false,
            fix_hint: false,
            watch: false,
            init_hook: false,
            remove_hook: false,
            malware_db: None,
            no_malware_scan: false,
            cve_db: None,
            no_cve_scan: false,
            custom_rules: None,
            baseline: false,
            check_drift: false,
            init: false,
            output: None,
            save_baseline: None,
            baseline_file: None,
            compare: None,
            fix: false,
            fix_dry_run: false,
            mcp_server: false,
            deep_scan: false,
            profile: None,
            save_profile: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Confidence, RuleSeverity, Severity};
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

    #[test]
    fn test_parse_init() {
        let cli = Cli::try_parse_from(["cc-audit", "--init", "./"]).unwrap();
        assert!(cli.init);
    }

    #[test]
    fn test_default_init_false() {
        let cli = Cli::try_parse_from(["cc-audit", "./skill/"]).unwrap();
        assert!(!cli.init);
    }

    #[test]
    fn test_parse_warn_only() {
        let cli = Cli::try_parse_from(["cc-audit", "--warn-only", "./skill/"]).unwrap();
        assert!(cli.warn_only);
    }

    #[test]
    fn test_default_warn_only_false() {
        let cli = Cli::try_parse_from(["cc-audit", "./skill/"]).unwrap();
        assert!(!cli.warn_only);
    }

    #[test]
    fn test_parse_min_severity_critical() {
        let cli =
            Cli::try_parse_from(["cc-audit", "--min-severity", "critical", "./skill/"]).unwrap();
        assert_eq!(cli.min_severity, Some(Severity::Critical));
    }

    #[test]
    fn test_parse_min_severity_high() {
        let cli = Cli::try_parse_from(["cc-audit", "--min-severity", "high", "./skill/"]).unwrap();
        assert_eq!(cli.min_severity, Some(Severity::High));
    }

    #[test]
    fn test_parse_min_severity_medium() {
        let cli =
            Cli::try_parse_from(["cc-audit", "--min-severity", "medium", "./skill/"]).unwrap();
        assert_eq!(cli.min_severity, Some(Severity::Medium));
    }

    #[test]
    fn test_parse_min_severity_low() {
        let cli = Cli::try_parse_from(["cc-audit", "--min-severity", "low", "./skill/"]).unwrap();
        assert_eq!(cli.min_severity, Some(Severity::Low));
    }

    #[test]
    fn test_default_min_severity_none() {
        let cli = Cli::try_parse_from(["cc-audit", "./skill/"]).unwrap();
        assert!(cli.min_severity.is_none());
    }

    #[test]
    fn test_parse_min_rule_severity_error() {
        let cli =
            Cli::try_parse_from(["cc-audit", "--min-rule-severity", "error", "./skill/"]).unwrap();
        assert_eq!(cli.min_rule_severity, Some(RuleSeverity::Error));
    }

    #[test]
    fn test_parse_min_rule_severity_warn() {
        let cli =
            Cli::try_parse_from(["cc-audit", "--min-rule-severity", "warn", "./skill/"]).unwrap();
        assert_eq!(cli.min_rule_severity, Some(RuleSeverity::Warn));
    }

    #[test]
    fn test_default_min_rule_severity_none() {
        let cli = Cli::try_parse_from(["cc-audit", "./skill/"]).unwrap();
        assert!(cli.min_rule_severity.is_none());
    }

    #[test]
    fn test_warn_only_with_strict_conflict() {
        // Both options can be parsed, but logic will determine behavior
        let cli = Cli::try_parse_from(["cc-audit", "--warn-only", "--strict", "./skill/"]).unwrap();
        assert!(cli.warn_only);
        assert!(cli.strict);
    }

    #[test]
    fn test_parse_all_clients() {
        let cli = Cli::try_parse_from(["cc-audit", "--all-clients"]).unwrap();
        assert!(cli.all_clients);
        assert!(cli.paths.is_empty());
    }

    #[test]
    fn test_parse_client_claude() {
        let cli = Cli::try_parse_from(["cc-audit", "--client", "claude"]).unwrap();
        assert_eq!(cli.client, Some(ClientType::Claude));
        assert!(cli.paths.is_empty());
    }

    #[test]
    fn test_parse_client_cursor() {
        let cli = Cli::try_parse_from(["cc-audit", "--client", "cursor"]).unwrap();
        assert_eq!(cli.client, Some(ClientType::Cursor));
    }

    #[test]
    fn test_parse_client_windsurf() {
        let cli = Cli::try_parse_from(["cc-audit", "--client", "windsurf"]).unwrap();
        assert_eq!(cli.client, Some(ClientType::Windsurf));
    }

    #[test]
    fn test_parse_client_vscode() {
        let cli = Cli::try_parse_from(["cc-audit", "--client", "vscode"]).unwrap();
        assert_eq!(cli.client, Some(ClientType::Vscode));
    }

    #[test]
    fn test_all_clients_conflicts_with_client() {
        let result = Cli::try_parse_from(["cc-audit", "--all-clients", "--client", "claude"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_clients_conflicts_with_remote() {
        let result = Cli::try_parse_from([
            "cc-audit",
            "--all-clients",
            "--remote",
            "https://github.com/x/y",
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn test_default_client_none() {
        let cli = Cli::try_parse_from(["cc-audit", "./skill/"]).unwrap();
        assert!(cli.client.is_none());
        assert!(!cli.all_clients);
    }
}
