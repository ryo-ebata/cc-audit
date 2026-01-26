pub mod command;
pub mod common;
pub mod dependency;
pub mod dockerfile;
pub mod error;
pub mod hook;
#[macro_use]
pub mod macros;
pub mod manifest;
pub mod mcp;
pub mod plugin;
pub mod rules_dir;
pub mod skill;
pub mod subagent;
pub mod walker;

use crate::error::{AuditError, Result};
use crate::rules::Finding;
pub use error::{ScanError, ScanResult};
use std::path::Path;
use tracing::{debug, trace};

pub use command::CommandScanner;
pub use common::ScannerConfig;
pub use dependency::DependencyScanner;
pub use dockerfile::DockerScanner;
pub use hook::HookScanner;
pub use manifest::{ManifestScanner, scan_manifest_directory};
pub use mcp::McpScanner;
pub use plugin::PluginScanner;
pub use rules_dir::RulesDirScanner;
pub use skill::{FrontmatterParser, SkillFileFilter, SkillScanner};
pub use subagent::SubagentScanner;
pub use walker::{DirectoryWalker, WalkConfig};

/// Core trait for all security scanners.
pub trait Scanner {
    fn scan_file(&self, path: &Path) -> Result<Vec<Finding>>;
    fn scan_directory(&self, dir: &Path) -> Result<Vec<Finding>>;

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
