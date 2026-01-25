pub mod baseline;
pub mod cli;
pub mod config;
pub mod error;
pub mod hooks;
pub mod ignore;
pub mod malware_db;
pub mod reporter;
pub mod rules;
pub mod run;
pub mod scanner;
pub mod scoring;
pub mod suppression;
pub mod watch;

#[cfg(test)]
pub mod test_utils;

pub use baseline::{Baseline, DriftEntry, DriftReport};
pub use cli::{Cli, OutputFormat, ScanType};
pub use config::{Config, ConfigError, TextFilesConfig, WatchConfig};
pub use error::{AuditError, Result};
pub use hooks::{HookError, HookInstaller};
pub use ignore::IgnoreFilter;
pub use malware_db::{MalwareDatabase, MalwareDbError};
pub use reporter::{
    Reporter, html::HtmlReporter, json::JsonReporter, sarif::SarifReporter,
    terminal::TerminalReporter,
};
pub use rules::{
    Confidence, CustomRuleError, CustomRuleLoader, DynamicRule, Finding, RuleEngine, ScanResult,
    Severity, Summary,
};
pub use run::{
    WatchModeResult, format_result, is_text_file, is_text_file_with_config, run_scan,
    scan_path_with_malware_db, setup_watch_mode, watch_iteration,
};
pub use scanner::{
    CommandScanner, DependencyScanner, DockerScanner, HookScanner, McpScanner, RulesDirScanner,
    Scanner, SkillScanner,
};
pub use scoring::{CategoryScore, RiskLevel, RiskScore, SeverityBreakdown};
pub use watch::FileWatcher;
