pub mod baseline;
pub mod cli;
pub mod client;
pub mod config;
pub mod cve_db;
pub mod deobfuscation;
pub mod error;
pub mod fix;
pub mod handlers;
pub mod hooks;
pub mod ignore;
pub mod malware_db;
pub mod mcp_server;
pub mod profile;
pub mod remote;
pub mod reporter;
pub mod rules;
pub mod run;
pub mod scanner;
pub mod scoring;
pub mod suppression;
pub mod types;
pub mod watch;

#[cfg(test)]
pub mod test_utils;

pub use baseline::{Baseline, DriftEntry, DriftReport};
pub use cli::{BadgeFormat, Cli, OutputFormat, ScanType};
pub use client::{
    ClientType, DetectedClient, detect_client, detect_installed_clients, list_installed_clients,
};
pub use config::{Config, ConfigError, TextFilesConfig, WatchConfig};
pub use cve_db::{CveDatabase, CveDbError, CveEntry};
pub use deobfuscation::{DecodedContent, Deobfuscator};
pub use error::{AuditError, Result};
pub use fix::{AutoFixer, Fix, FixResult};
pub use hooks::{HookError, HookInstaller};
pub use ignore::IgnoreFilter;
pub use malware_db::{MalwareDatabase, MalwareDbError};
pub use mcp_server::McpServer;
pub use profile::{Profile, profile_from_cli};
pub use remote::{ClonedRepo, GitCloner, RemoteError, parse_github_url};
pub use reporter::{
    Reporter, html::HtmlReporter, json::JsonReporter, markdown::MarkdownReporter,
    sarif::SarifReporter, terminal::TerminalReporter,
};
pub use rules::{
    Confidence, CustomRuleError, CustomRuleLoader, DynamicRule, Finding, RuleEngine, RuleSeverity,
    ScanResult, Severity, Summary,
};
pub use run::{
    ScanMode, WatchModeResult, format_result, is_text_file, is_text_file_with_config, run_scan,
    scan_path_with_cve_db, scan_path_with_malware_db, setup_watch_mode, watch_iteration,
};
pub use scanner::{
    CommandScanner, DependencyScanner, DirectoryWalker, DockerScanner, HookScanner, McpScanner,
    PluginScanner, RulesDirScanner, ScanError, Scanner, SkillScanner, SubagentScanner, WalkConfig,
};
pub use scoring::{CategoryScore, RiskLevel, RiskScore, SeverityBreakdown};
pub use types::{AuthToken, FileHash, GitRef, PathValidationError, RuleId, ScanTarget};
pub use watch::FileWatcher;
