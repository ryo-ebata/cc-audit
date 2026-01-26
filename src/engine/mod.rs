//! Detection engine layer (L5).
//!
//! This module provides the core detection functionality:
//! - Scanner traits for file/directory scanning
//! - Rule engine for pattern matching
//! - Content matcher utilities
//! - Suppression handling
//! - Malware database scanning
//! - CVE database scanning
//! - Content deobfuscation
//! - Context detection
//!
//! The detection engine takes parsed content from L4 and produces
//! raw findings for the aggregator (L6).

pub mod scanner;
pub mod scanners;
pub mod traits;

// Re-export scanner traits and config
pub use scanner::{ContentScanner, Scanner, ScannerConfig};

// Re-export scanner implementations
pub use scanners::{
    CommandScanner, DependencyScanner, DirectoryWalker, DockerScanner, FrontmatterParser,
    HookScanner, ManifestScanner, McpScanner, PluginScanner, RulesDirScanner, ScanError,
    ScanResult, SkillFileFilter, SkillScanner, SubagentScanner, WalkConfig,
    scan_manifest_directory,
};

// Re-export from existing modules (will be moved here in Phase 10)
pub use crate::context::{ContentContext, ContextDetector};
pub use crate::cve_db::{CveDatabase, CveDbError, CveEntry};
pub use crate::deobfuscation::{DecodedContent, Deobfuscator};
pub use crate::malware_db::{MalwareDatabase, MalwareDbError};
pub use crate::rules::{
    Confidence, CustomRuleError, CustomRuleLoader, DynamicRule, Finding, RuleEngine, RuleSeverity,
    Severity,
};
pub use crate::suppression::{
    SuppressionManager, SuppressionType, parse_inline_suppression, parse_next_line_suppression,
};
