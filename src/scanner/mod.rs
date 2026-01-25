pub mod command;
pub mod common;
pub mod dependency;
pub mod dockerfile;
pub mod hook;
pub mod mcp;
pub mod rules_dir;
pub mod skill;

use crate::error::{AuditError, Result};
use crate::rules::Finding;
use std::path::Path;

pub use command::CommandScanner;
pub use common::ScannerConfig;
pub use dependency::DependencyScanner;
pub use dockerfile::DockerScanner;
pub use hook::HookScanner;
pub use mcp::McpScanner;
pub use rules_dir::RulesDirScanner;
pub use skill::{FrontmatterParser, SkillFileFilter, SkillScanner};

/// Core trait for all security scanners.
pub trait Scanner {
    fn scan_file(&self, path: &Path) -> Result<Vec<Finding>>;
    fn scan_directory(&self, dir: &Path) -> Result<Vec<Finding>>;

    fn scan_path(&self, path: &Path) -> Result<Vec<Finding>> {
        if !path.exists() {
            return Err(AuditError::FileNotFound(path.display().to_string()));
        }

        if path.is_file() {
            return self.scan_file(path);
        }

        if !path.is_dir() {
            return Err(AuditError::NotADirectory(path.display().to_string()));
        }

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
