//! cc-audit - Security scanner for Claude Code configurations.
//!
//! This crate is organized into the following 7-layer architecture:
//!
//! - **L1 (input/)**: Input handling (CLI, stdin)
//! - **L2 (config/)**: Configuration loading and validation
//! - **L3 (discovery/)**: Target file discovery and filtering
//! - **L4 (parser/)**: Content parsing for various file formats
//! - **L5 (engine/)**: Detection engine and rule matching
//! - **L6 (aggregator/)**: Result aggregation and scoring
//! - **L7 (output/)**: Output formatting and reporting
//!
//! Cross-cutting modules:
//! - **rules/**: Rule definitions and custom rules
//! - **external/**: External integrations (hooks, MCP, watch)
//! - **runtime/**: Execution control and pipeline (v1.x skeleton)
//! - **types/**: Common type definitions

// ============================================
// 7-Layer Architecture Modules
// ============================================

// L1: Input Layer
pub mod cli;
pub mod client;
pub mod input;

// L2: Configuration Layer
pub mod config;
pub mod profile;

// L3: Discovery Layer
pub mod discovery;
pub mod ignore;

// L4: Parser Layer
pub mod parser;

// L5: Detection Engine Layer
pub mod context;
pub mod cve_db;
pub mod deobfuscation;
pub mod engine;
pub mod malware_db;
pub mod rules;
pub mod suppression;

// L6: Aggregation Layer
pub mod aggregator;
pub mod baseline;
pub mod scoring;

// L7: Output Layer
pub mod output;
pub mod reporter;

// ============================================
// Cross-Cutting Modules
// ============================================

pub mod error;
pub mod external;
pub mod runtime;
pub mod types;

// External integrations
pub mod feedback;
pub mod fix;
pub mod hooks;
pub mod mcp_server;
pub mod pinning;
pub mod proxy;
pub mod remote;
pub mod sbom;
pub mod trusted_domains;
pub mod watch;

// Legacy modules (for backward compatibility)
pub mod handlers;
pub mod hook_mode;
pub mod run;
pub mod scanner;

#[cfg(test)]
pub mod test_utils;

// ============================================
// Re-exports for Public API
// ============================================

// L1: Input
pub use cli::{BadgeFormat, Cli, OutputFormat, ScanType};
pub use client::{
    ClientType, DetectedClient, detect_client, detect_installed_clients, list_installed_clients,
};

// L2: Configuration
pub use config::{Config, ConfigError, TextFilesConfig, WatchConfig};
pub use profile::{Profile, profile_from_cli};

// L3: Discovery
pub use discovery::{DirectoryWalker, WalkConfig};
pub use ignore::IgnoreFilter;

// L4: Parser
pub use parser::{
    ContentParser, ContentType, DockerfileParser, FrontmatterParser, JsonParser, MarkdownParser,
    ParsedContent, ParserRegistry, TomlParser, YamlParser,
};

// L5: Detection Engine
pub use context::{ContentContext, ContextDetector};
pub use cve_db::{CveDatabase, CveDbError, CveEntry};
pub use deobfuscation::{DecodedContent, Deobfuscator};
pub use engine::traits::{AnalysisMetadata, AnalysisResult, DetectionEngine, EngineConfig};
pub use engine::{
    CommandScanner, ContentScanner, DependencyScanner, DockerScanner, HookScanner, McpScanner,
    PluginScanner, RulesDirScanner, ScanError, Scanner, ScannerConfig, SkillScanner,
    SubagentScanner,
};
pub use malware_db::{MalwareDatabase, MalwareDbError};
pub use rules::{
    Confidence, CustomRuleError, CustomRuleLoader, DynamicRule, Finding, RuleEngine, RuleSeverity,
    ScanResult, Severity, Summary,
};

// L6: Aggregation
pub use aggregator::{FindingCollector, SummaryBuilder};
pub use baseline::{Baseline, DriftEntry, DriftReport};
pub use scoring::{CategoryScore, RiskLevel, RiskScore, SeverityBreakdown};

// L7: Output
pub use output::OutputFormatter;
pub use reporter::{
    Reporter, html::HtmlReporter, json::JsonReporter, markdown::MarkdownReporter,
    sarif::SarifReporter, terminal::TerminalReporter,
};

// Runtime & Orchestration
pub use run::{
    ScanMode, WatchModeResult, format_result, is_text_file, is_text_file_with_config, run_scan,
    scan_path_with_cve_db, scan_path_with_malware_db, setup_watch_mode, watch_iteration,
};
pub use runtime::{HookRunner, Pipeline, PipelineStage, ScanContext, ScanExecutor};

// External Integrations
pub use error::{AuditError, Result};
pub use feedback::{FalsePositiveReport, ReportSubmitter, SubmitResult, SubmitTarget};
pub use fix::{AutoFixer, Fix, FixResult};
pub use hooks::{HookError, HookInstaller};
pub use mcp_server::McpServer;
pub use pinning::{PinMismatch, PinVerifyResult, PinnedTool, ToolPins};
pub use proxy::{InterceptAction, MessageInterceptor, ProxyConfig, ProxyLogger, ProxyServer};
pub use remote::{ClonedRepo, GitCloner, RemoteError, parse_github_url};
pub use sbom::{
    Component, ComponentType, CycloneDxBom, DependencyExtractor, SbomBuilder, SbomFormat,
};
pub use trusted_domains::{TrustedDomain, TrustedDomainMatcher};
pub use types::{AuthToken, FileHash, GitRef, PathValidationError, RuleId, ScanTarget};
pub use watch::FileWatcher;
