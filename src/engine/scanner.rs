//! Scanner traits and configuration for the detection layer (L5).
//!
//! This module provides file-system oriented scanning interfaces:
//! - `Scanner` trait for scanning files and directories
//! - `ContentScanner` trait for content-based scanning
//! - `ScannerConfig` for common scanner configuration

use crate::error::{AuditError, Result};
use crate::ignore::IgnoreFilter;
use crate::rules::{DynamicRule, Finding, RuleEngine};
use std::fs;
use std::path::Path;
use tracing::{debug, trace};

/// Core trait for all security scanners.
///
/// Scanners implement this trait to provide file and directory scanning capabilities.
/// The default `scan_path` implementation handles path validation and delegates to
/// either `scan_file` or `scan_directory` based on the path type.
pub trait Scanner {
    /// Scan a single file and return findings.
    fn scan_file(&self, path: &Path) -> Result<Vec<Finding>>;

    /// Scan a directory and return findings.
    fn scan_directory(&self, dir: &Path) -> Result<Vec<Finding>>;

    /// Scan a path (file or directory).
    ///
    /// This is the main entry point for scanning. It validates the path
    /// and delegates to either `scan_file` or `scan_directory`.
    fn scan_path(&self, path: &Path) -> Result<Vec<Finding>> {
        trace!(path = %path.display(), "Scanning path");

        if !path.exists() {
            debug!(path = %path.display(), "Path not found");
            return Err(AuditError::FileNotFound(path.display().to_string()));
        }

        if path.is_file() {
            trace!(path = %path.display(), "Scanning as file");
            return self.scan_file(path);
        }

        if !path.is_dir() {
            debug!(path = %path.display(), "Path is not a directory");
            return Err(AuditError::NotADirectory(path.display().to_string()));
        }

        trace!(path = %path.display(), "Scanning as directory");
        self.scan_directory(path)
    }
}

/// Extended trait for scanners that support content-based scanning.
///
/// This trait provides a unified interface for scanning raw content strings,
/// which is useful for testing and for scanners that parse structured files
/// (like JSON) before applying rules.
pub trait ContentScanner: Scanner {
    /// Returns a reference to the scanner's configuration.
    fn config(&self) -> &ScannerConfig;

    /// Scans content and returns findings.
    ///
    /// Default implementation delegates to ScannerConfig::check_content.
    /// Override this method for scanners that need custom content processing
    /// (e.g., JSON parsing, frontmatter extraction).
    fn scan_content(&self, content: &str, file_path: &str) -> Result<Vec<Finding>> {
        Ok(self.config().check_content(content, file_path))
    }
}

/// Common configuration shared by all scanners.
///
/// This struct provides a unified way to manage RuleEngine settings,
/// ignore filters, and common file operations across different scanner implementations.
pub struct ScannerConfig {
    engine: RuleEngine,
    ignore_filter: Option<IgnoreFilter>,
    skip_comments: bool,
    strict_secrets: bool,
    recursive: bool,
}

impl ScannerConfig {
    /// Creates a new ScannerConfig with default settings.
    pub fn new() -> Self {
        Self {
            engine: RuleEngine::new(),
            ignore_filter: None,
            skip_comments: false,
            strict_secrets: false,
            recursive: false,
        }
    }

    /// Enables or disables recursive scanning.
    /// When disabled, only scans the immediate directory (max_depth = 1).
    pub fn with_recursive(mut self, recursive: bool) -> Self {
        self.recursive = recursive;
        self
    }

    /// Returns whether recursive scanning is enabled.
    pub fn is_recursive(&self) -> bool {
        self.recursive
    }

    /// Returns the max_depth for directory walking based on recursive setting.
    /// - recursive = true: None (unlimited depth)
    /// - recursive = false: Some(1) (immediate directory only)
    pub fn max_depth(&self) -> Option<usize> {
        if self.recursive { None } else { Some(1) }
    }

    /// Enables or disables comment skipping during scanning.
    pub fn with_skip_comments(mut self, skip: bool) -> Self {
        self.skip_comments = skip;
        self.engine = self.engine.with_skip_comments(skip);
        self
    }

    /// Enables or disables strict secrets mode.
    /// When enabled, dummy key heuristics are disabled for test files.
    pub fn with_strict_secrets(mut self, strict: bool) -> Self {
        self.strict_secrets = strict;
        self.engine = self.engine.with_strict_secrets(strict);
        self
    }

    /// Sets an ignore filter for file filtering.
    pub fn with_ignore_filter(mut self, filter: IgnoreFilter) -> Self {
        self.ignore_filter = Some(filter);
        self
    }

    /// Adds dynamic rules loaded from custom YAML files.
    pub fn with_dynamic_rules(mut self, rules: Vec<DynamicRule>) -> Self {
        self.engine = self.engine.with_dynamic_rules(rules);
        self
    }

    /// Returns whether the given path should be ignored.
    pub fn is_ignored(&self, path: &Path) -> bool {
        self.ignore_filter
            .as_ref()
            .is_some_and(|f| f.is_ignored(path))
    }

    /// Reads a file and returns its content as a string.
    pub fn read_file(&self, path: &Path) -> Result<String> {
        trace!(path = %path.display(), "Reading file");
        fs::read_to_string(path).map_err(|e| {
            debug!(path = %path.display(), error = %e, "Failed to read file");
            AuditError::ReadError {
                path: path.display().to_string(),
                source: e,
            }
        })
    }

    /// Checks the content against all rules and returns findings.
    pub fn check_content(&self, content: &str, file_path: &str) -> Vec<Finding> {
        trace!(
            file = file_path,
            content_len = content.len(),
            "Checking content"
        );
        let findings = self.engine.check_content(content, file_path);
        if !findings.is_empty() {
            debug!(file = file_path, count = findings.len(), "Found issues");
        }
        findings
    }

    /// Checks YAML frontmatter for specific rules (e.g., OP-001).
    pub fn check_frontmatter(&self, frontmatter: &str, file_path: &str) -> Vec<Finding> {
        self.engine.check_frontmatter(frontmatter, file_path)
    }

    /// Returns whether skip_comments is enabled.
    pub fn skip_comments(&self) -> bool {
        self.skip_comments
    }

    /// Returns whether strict_secrets is enabled.
    pub fn strict_secrets(&self) -> bool {
        self.strict_secrets
    }

    /// Returns a reference to the underlying RuleEngine.
    pub fn engine(&self) -> &RuleEngine {
        &self.engine
    }
}

impl Default for ScannerConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_new_config() {
        let config = ScannerConfig::new();
        assert!(!config.skip_comments());
    }

    #[test]
    fn test_with_skip_comments() {
        let config = ScannerConfig::new().with_skip_comments(true);
        assert!(config.skip_comments());
    }

    #[test]
    fn test_default_config() {
        let config = ScannerConfig::default();
        assert!(!config.skip_comments());
    }

    #[test]
    fn test_is_ignored_without_filter() {
        let config = ScannerConfig::new();
        assert!(!config.is_ignored(Path::new("test.rs")));
    }

    #[test]
    fn test_read_file_success() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "test content").unwrap();

        let config = ScannerConfig::new();
        let content = config.read_file(&file_path).unwrap();
        assert_eq!(content, "test content");
    }

    #[test]
    fn test_read_file_not_found() {
        let config = ScannerConfig::new();
        let result = config.read_file(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_check_content_detects_sudo() {
        let config = ScannerConfig::new();
        let findings = config.check_content("sudo rm -rf /", "test.sh");
        assert!(findings.iter().any(|f| f.id == "PE-001"));
    }

    #[test]
    fn test_check_content_skip_comments() {
        let config = ScannerConfig::new().with_skip_comments(true);
        let findings = config.check_content("# sudo rm -rf /", "test.sh");
        assert!(findings.iter().all(|f| f.id != "PE-001"));
    }

    #[test]
    fn test_check_frontmatter_wildcard() {
        let config = ScannerConfig::new();
        let findings = config.check_frontmatter("allowed-tools: *", "SKILL.md");
        assert!(findings.iter().any(|f| f.id == "OP-001"));
    }

    #[test]
    fn test_engine_accessor() {
        let config = ScannerConfig::new();
        let _engine = config.engine();
    }
}
