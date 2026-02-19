use crate::client::ClientType;
use crate::rules::{Confidence, ParseEnumError, RuleSeverity, Severity};
use crate::run::EffectiveConfig;
use clap::{Args, Parser, Subcommand, ValueEnum};
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

/// Hook subcommand actions
#[derive(Subcommand, Debug, Clone)]
pub enum HookAction {
    /// Install pre-commit hook
    Init {
        /// Path to git repository
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Remove pre-commit hook
    Remove {
        /// Path to git repository
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

/// Arguments for the check subcommand
#[derive(Args, Debug, Clone)]
pub struct CheckArgs {
    /// Paths to scan (files or directories)
    #[arg(required_unless_present_any = ["remote", "remote_list", "awesome_claude_code", "all_clients", "client", "compare"])]
    pub paths: Vec<PathBuf>,

    /// Path to configuration file
    #[arg(short = 'c', long = "config", value_name = "FILE")]
    pub config: Option<PathBuf>,

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
    #[arg(short = 'S', long)]
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

    /// Disable recursive scanning (default: recursive enabled)
    #[arg(long = "no-recursive")]
    pub no_recursive: bool,

    /// CI mode: non-interactive output
    #[arg(long)]
    pub ci: bool,

    /// Minimum confidence level for findings to be reported
    #[arg(long, value_enum)]
    pub min_confidence: Option<Confidence>,

    /// Skip comment lines when scanning (lines starting with #, //, --, etc.)
    #[arg(long)]
    pub skip_comments: bool,

    /// Strict secrets mode: disable dummy key heuristics for test files
    #[arg(long)]
    pub strict_secrets: bool,

    /// Show fix hints in terminal output
    #[arg(long)]
    pub fix_hint: bool,

    /// Use compact output format (disable friendly advice)
    #[arg(long)]
    pub compact: bool,

    /// Watch mode: continuously monitor files for changes and re-scan
    #[arg(short, long)]
    pub watch: bool,

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

    /// Run as Claude Code Hook (reads from stdin, writes to stdout)
    #[arg(long)]
    pub hook_mode: bool,

    /// Pin MCP tool configurations for rug-pull detection
    #[arg(long)]
    pub pin: bool,

    /// Verify MCP tool pins against current configuration
    #[arg(long)]
    pub pin_verify: bool,

    /// Update MCP tool pins with current configuration
    #[arg(long)]
    pub pin_update: bool,

    /// Force overwrite existing pins
    #[arg(long)]
    pub pin_force: bool,

    /// Skip pin verification during scan
    #[arg(long)]
    pub ignore_pin: bool,

    /// Enable deep scan with deobfuscation
    #[arg(long)]
    pub deep_scan: bool,

    /// Load settings from a named profile
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Save current settings as a named profile
    #[arg(long, value_name = "NAME")]
    pub save_profile: Option<String>,

    /// Report a false positive finding
    #[arg(long)]
    pub report_fp: bool,

    /// Dry run mode for false positive reporting (print without submitting)
    #[arg(long)]
    pub report_fp_dry_run: bool,

    /// Custom endpoint URL for false positive reporting
    #[arg(long, value_name = "URL")]
    pub report_fp_endpoint: Option<String>,

    /// Disable telemetry and false positive reporting
    #[arg(long)]
    pub no_telemetry: bool,

    /// Generate SBOM (Software Bill of Materials)
    #[arg(long)]
    pub sbom: bool,

    /// SBOM output format (cyclonedx, spdx)
    #[arg(long, value_name = "FORMAT")]
    pub sbom_format: Option<String>,

    /// Include npm dependencies in SBOM
    #[arg(long)]
    pub sbom_npm: bool,

    /// Include Cargo dependencies in SBOM
    #[arg(long)]
    pub sbom_cargo: bool,
}

/// Arguments for the proxy subcommand
#[derive(Args, Debug, Clone)]
pub struct ProxyArgs {
    /// Proxy listen port
    #[arg(long, default_value = "8080")]
    pub port: u16,

    /// Target MCP server address (host:port)
    #[arg(long, required = true, value_name = "HOST:PORT")]
    pub target: String,

    /// Enable TLS termination in proxy mode
    #[arg(long)]
    pub tls: bool,

    /// Enable blocking mode (block messages with findings)
    #[arg(long)]
    pub block: bool,

    /// Log file for proxy traffic (JSONL format)
    #[arg(long, value_name = "FILE")]
    pub log: Option<PathBuf>,
}

/// Subcommands for cc-audit
#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Generate a default configuration file template
    Init {
        /// Output path for the configuration file (default: .cc-audit.yaml)
        #[arg(default_value = ".cc-audit.yaml")]
        path: PathBuf,
    },

    /// Scan paths for security vulnerabilities
    Check(Box<CheckArgs>),

    /// Manage Git pre-commit hook
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },

    /// Run as MCP server
    Serve,

    /// Run as MCP proxy for runtime monitoring
    Proxy(ProxyArgs),
}

#[derive(Parser, Debug, Default)]
#[command(
    name = "cc-audit",
    version,
    about = "Security auditor for Claude Code skills, hooks, and MCP servers",
    long_about = "cc-audit scans Claude Code skills, hooks, and MCP servers for security vulnerabilities before installation."
)]
pub struct Cli {
    /// Subcommand to run
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,
}

impl Default for CheckArgs {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            config: None,
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
            no_recursive: false,
            ci: false,
            min_confidence: None,
            skip_comments: false,
            strict_secrets: false,
            fix_hint: false,
            compact: false,
            watch: false,
            malware_db: None,
            no_malware_scan: false,
            cve_db: None,
            no_cve_scan: false,
            custom_rules: None,
            baseline: false,
            check_drift: false,
            output: None,
            save_baseline: None,
            baseline_file: None,
            compare: None,
            fix: false,
            fix_dry_run: false,
            hook_mode: false,
            pin: false,
            pin_verify: false,
            pin_update: false,
            pin_force: false,
            ignore_pin: false,
            deep_scan: false,
            profile: None,
            save_profile: None,
            report_fp: false,
            report_fp_dry_run: false,
            report_fp_endpoint: None,
            no_telemetry: false,
            sbom: false,
            sbom_format: None,
            sbom_npm: false,
            sbom_cargo: false,
        }
    }
}

impl CheckArgs {
    /// サブスキャン用の CheckArgs を作成。self と EffectiveConfig から設定を継承する。
    /// remote/compare/baseline 等のサブスキャン不要なフィールドはリセットされる。
    pub fn for_scan(&self, paths: Vec<PathBuf>, effective: &EffectiveConfig) -> Self {
        Self {
            paths,
            config: self.config.clone(),
            remote: None,
            git_ref: effective.git_ref.clone(),
            remote_auth: effective.remote_auth.clone(),
            remote_list: None,
            awesome_claude_code: false,
            parallel_clones: effective.parallel_clones,
            badge: effective.badge,
            badge_format: effective.badge_format,
            summary: effective.summary,
            format: effective.format,
            strict: effective.strict,
            warn_only: effective.warn_only,
            min_severity: effective.min_severity,
            min_rule_severity: effective.min_rule_severity,
            scan_type: effective.scan_type,
            no_recursive: false,
            ci: effective.ci,
            min_confidence: Some(effective.min_confidence),
            watch: false,
            skip_comments: effective.skip_comments,
            strict_secrets: effective.strict_secrets,
            fix_hint: effective.fix_hint,
            compact: effective.compact,
            no_malware_scan: effective.no_malware_scan,
            cve_db: effective.cve_db.as_ref().map(PathBuf::from),
            no_cve_scan: effective.no_cve_scan,
            malware_db: effective.malware_db.as_ref().map(PathBuf::from),
            custom_rules: effective.custom_rules.as_ref().map(PathBuf::from),
            baseline: false,
            check_drift: false,
            output: effective.output.as_ref().map(PathBuf::from),
            save_baseline: None,
            baseline_file: self.baseline_file.clone(),
            compare: None,
            fix: false,
            fix_dry_run: false,
            pin: false,
            pin_verify: false,
            pin_update: false,
            pin_force: false,
            ignore_pin: false,
            deep_scan: effective.deep_scan,
            profile: self.profile.clone(),
            save_profile: None,
            all_clients: false,
            client: None,
            report_fp: false,
            report_fp_dry_run: false,
            report_fp_endpoint: None,
            no_telemetry: self.no_telemetry,
            sbom: false,
            sbom_format: None,
            sbom_npm: false,
            sbom_cargo: false,
            hook_mode: false,
        }
    }

    /// バッチスキャン用の CheckArgs を作成。badge/summary を無効化し、Terminal 形式にする。
    pub fn for_batch_scan(&self, paths: Vec<PathBuf>, effective: &EffectiveConfig) -> Self {
        let mut args = self.for_scan(paths, effective);
        args.badge = false;
        args.badge_format = BadgeFormat::Markdown;
        args.summary = false;
        args.format = OutputFormat::Terminal;
        args.ci = false;
        args.fix_hint = false;
        args.output = None;
        args.baseline_file = None;
        args
    }
}

impl Default for ProxyArgs {
    fn default() -> Self {
        Self {
            port: 8080,
            target: String::new(),
            tls: false,
            block: false,
            log: None,
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

    // ===== Test: No args shows help (command is None) =====

    #[test]
    fn test_no_args_succeeds() {
        let cli = Cli::try_parse_from(["cc-audit"]).unwrap();
        assert!(cli.command.is_none());
    }

    // ===== Test: init subcommand =====

    #[test]
    fn test_parse_init_subcommand() {
        let cli = Cli::try_parse_from(["cc-audit", "init"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Init { .. })));
    }

    #[test]
    fn test_parse_init_subcommand_with_path() {
        let cli = Cli::try_parse_from(["cc-audit", "init", "custom-config.yaml"]).unwrap();
        if let Some(Commands::Init { path }) = cli.command {
            assert_eq!(path.to_str().unwrap(), "custom-config.yaml");
        } else {
            panic!("Expected Init command");
        }
    }

    // ===== Test: check subcommand =====

    #[test]
    fn test_parse_check_subcommand() {
        let cli = Cli::try_parse_from(["cc-audit", "check", "./skill/"]).unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert_eq!(args.paths.len(), 1);
            assert!(!args.strict);
            assert!(!args.no_recursive); // recursive is enabled by default
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_multiple_paths() {
        let cli = Cli::try_parse_from(["cc-audit", "check", "./skill1/", "./skill2/"]).unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert_eq!(args.paths.len(), 2);
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_format_json() {
        let cli =
            Cli::try_parse_from(["cc-audit", "check", "--format", "json", "./skill/"]).unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert!(matches!(args.format, OutputFormat::Json));
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_strict_mode() {
        let cli = Cli::try_parse_from(["cc-audit", "check", "--strict", "./skill/"]).unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert!(args.strict);
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_no_recursive() {
        let cli =
            Cli::try_parse_from(["cc-audit", "check", "--no-recursive", "./skills/"]).unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert!(args.no_recursive);
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_format_sarif() {
        let cli =
            Cli::try_parse_from(["cc-audit", "check", "--format", "sarif", "./skill/"]).unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert!(matches!(args.format, OutputFormat::Sarif));
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_type_hook() {
        let cli = Cli::try_parse_from(["cc-audit", "check", "--type", "hook", "./settings.json"])
            .unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert!(matches!(args.scan_type, ScanType::Hook));
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_type_mcp() {
        let cli =
            Cli::try_parse_from(["cc-audit", "check", "--type", "mcp", "./mcp.json"]).unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert!(matches!(args.scan_type, ScanType::Mcp));
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_ci_mode() {
        let cli = Cli::try_parse_from(["cc-audit", "check", "--ci", "./skill/"]).unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert!(args.ci);
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_verbose() {
        let cli = Cli::try_parse_from(["cc-audit", "-v", "check", "./skill/"]).unwrap();
        assert!(cli.verbose);
    }

    #[test]
    fn test_parse_check_all_options() {
        let cli = Cli::try_parse_from([
            "cc-audit", "check", "--format", "json", "--strict", "--type", "hook", "--ci",
            "./path/",
        ])
        .unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert!(matches!(args.format, OutputFormat::Json));
            assert!(args.strict);
            assert!(matches!(args.scan_type, ScanType::Hook));
            assert!(args.ci);
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_default_values() {
        let cli = Cli::try_parse_from(["cc-audit", "check", "./skill/"]).unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert!(matches!(args.format, OutputFormat::Terminal));
            assert!(matches!(args.scan_type, ScanType::Skill));
            assert!(!args.strict);
            assert!(!args.no_recursive);
            assert!(!args.ci);
            assert!(args.min_confidence.is_none());
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_min_confidence() {
        let cli = Cli::try_parse_from([
            "cc-audit",
            "check",
            "--min-confidence",
            "tentative",
            "./skill/",
        ])
        .unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert!(matches!(args.min_confidence, Some(Confidence::Tentative)));
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_skip_comments() {
        let cli =
            Cli::try_parse_from(["cc-audit", "check", "--skip-comments", "./skill/"]).unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert!(args.skip_comments);
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_watch() {
        let cli = Cli::try_parse_from(["cc-audit", "check", "--watch", "./skill/"]).unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert!(args.watch);
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_watch_short() {
        let cli = Cli::try_parse_from(["cc-audit", "check", "-w", "./skill/"]).unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert!(args.watch);
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_malware_db() {
        let cli = Cli::try_parse_from([
            "cc-audit",
            "check",
            "--malware-db",
            "./custom.json",
            "./skill/",
        ])
        .unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert!(args.malware_db.is_some());
            assert_eq!(args.malware_db.unwrap().to_str().unwrap(), "./custom.json");
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_custom_rules() {
        let cli = Cli::try_parse_from([
            "cc-audit",
            "check",
            "--custom-rules",
            "./rules.yaml",
            "./skill/",
        ])
        .unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert!(args.custom_rules.is_some());
            assert_eq!(args.custom_rules.unwrap().to_str().unwrap(), "./rules.yaml");
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_config_option() {
        let cli =
            Cli::try_parse_from(["cc-audit", "check", "-c", "custom.yaml", "./skill/"]).unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert_eq!(args.config.unwrap().to_str().unwrap(), "custom.yaml");
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_warn_only() {
        let cli = Cli::try_parse_from(["cc-audit", "check", "--warn-only", "./skill/"]).unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert!(args.warn_only);
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_min_severity() {
        let cli = Cli::try_parse_from([
            "cc-audit",
            "check",
            "--min-severity",
            "critical",
            "./skill/",
        ])
        .unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert_eq!(args.min_severity, Some(Severity::Critical));
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_min_rule_severity() {
        let cli = Cli::try_parse_from([
            "cc-audit",
            "check",
            "--min-rule-severity",
            "error",
            "./skill/",
        ])
        .unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert_eq!(args.min_rule_severity, Some(RuleSeverity::Error));
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_all_clients() {
        let cli = Cli::try_parse_from(["cc-audit", "check", "--all-clients"]).unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert!(args.all_clients);
            assert!(args.paths.is_empty());
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_parse_check_client_claude() {
        let cli = Cli::try_parse_from(["cc-audit", "check", "--client", "claude"]).unwrap();
        if let Some(Commands::Check(args)) = cli.command {
            assert_eq!(args.client, Some(ClientType::Claude));
            assert!(args.paths.is_empty());
        } else {
            panic!("Expected Check command");
        }
    }

    #[test]
    fn test_check_all_clients_conflicts_with_client() {
        let result =
            Cli::try_parse_from(["cc-audit", "check", "--all-clients", "--client", "claude"]);
        assert!(result.is_err());
    }

    // ===== Test: hook subcommand =====

    #[test]
    fn test_parse_hook_init() {
        let cli = Cli::try_parse_from(["cc-audit", "hook", "init"]).unwrap();
        if let Some(Commands::Hook { action }) = cli.command {
            assert!(matches!(action, HookAction::Init { .. }));
        } else {
            panic!("Expected Hook command");
        }
    }

    #[test]
    fn test_parse_hook_init_with_path() {
        let cli = Cli::try_parse_from(["cc-audit", "hook", "init", "./repo/"]).unwrap();
        if let Some(Commands::Hook { action }) = cli.command {
            if let HookAction::Init { path } = action {
                assert_eq!(path.to_str().unwrap(), "./repo/");
            } else {
                panic!("Expected HookAction::Init");
            }
        } else {
            panic!("Expected Hook command");
        }
    }

    #[test]
    fn test_parse_hook_remove() {
        let cli = Cli::try_parse_from(["cc-audit", "hook", "remove"]).unwrap();
        if let Some(Commands::Hook { action }) = cli.command {
            assert!(matches!(action, HookAction::Remove { .. }));
        } else {
            panic!("Expected Hook command");
        }
    }

    #[test]
    fn test_parse_hook_remove_with_path() {
        let cli = Cli::try_parse_from(["cc-audit", "hook", "remove", "./repo/"]).unwrap();
        if let Some(Commands::Hook { action }) = cli.command {
            if let HookAction::Remove { path } = action {
                assert_eq!(path.to_str().unwrap(), "./repo/");
            } else {
                panic!("Expected HookAction::Remove");
            }
        } else {
            panic!("Expected Hook command");
        }
    }

    // ===== Test: serve subcommand =====

    #[test]
    fn test_parse_serve() {
        let cli = Cli::try_parse_from(["cc-audit", "serve"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Serve)));
    }

    // ===== Test: proxy subcommand =====

    #[test]
    fn test_parse_proxy() {
        let cli = Cli::try_parse_from(["cc-audit", "proxy", "--target", "localhost:9000"]).unwrap();
        if let Some(Commands::Proxy(args)) = cli.command {
            assert_eq!(args.target, "localhost:9000");
            assert_eq!(args.port, 8080); // default
            assert!(!args.tls);
            assert!(!args.block);
        } else {
            panic!("Expected Proxy command");
        }
    }

    #[test]
    fn test_parse_proxy_with_all_options() {
        let cli = Cli::try_parse_from([
            "cc-audit",
            "proxy",
            "--target",
            "localhost:9000",
            "--port",
            "3000",
            "--tls",
            "--block",
            "--log",
            "proxy.log",
        ])
        .unwrap();
        if let Some(Commands::Proxy(args)) = cli.command {
            assert_eq!(args.target, "localhost:9000");
            assert_eq!(args.port, 3000);
            assert!(args.tls);
            assert!(args.block);
            assert_eq!(args.log.unwrap().to_str().unwrap(), "proxy.log");
        } else {
            panic!("Expected Proxy command");
        }
    }

    #[test]
    fn test_proxy_requires_target() {
        let result = Cli::try_parse_from(["cc-audit", "proxy"]);
        assert!(result.is_err());
    }

    // ===== Test: global verbose flag =====

    #[test]
    fn test_verbose_global_flag() {
        let cli = Cli::try_parse_from(["cc-audit", "-v", "check", "./skill/"]).unwrap();
        assert!(cli.verbose);

        let cli2 = Cli::try_parse_from(["cc-audit", "check", "-v", "./skill/"]).unwrap();
        assert!(cli2.verbose);

        let cli3 = Cli::try_parse_from(["cc-audit", "check", "./skill/", "-v"]).unwrap();
        assert!(cli3.verbose);
    }
}
