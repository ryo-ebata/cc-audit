//! Scan context management.
//!
//! Note: This is a skeleton for v1.x.

use crate::config::Config;
use std::path::PathBuf;

/// Context for a scan operation.
#[derive(Debug, Clone)]
pub struct ScanContext {
    /// Root paths to scan.
    pub paths: Vec<PathBuf>,
    /// Configuration for the scan.
    pub config: Config,
    /// Whether to run in verbose mode.
    pub verbose: bool,
    /// Whether to run in strict mode.
    pub strict: bool,
}

impl ScanContext {
    /// Create a new scan context.
    pub fn new(paths: Vec<PathBuf>, config: Config) -> Self {
        Self {
            paths,
            config,
            verbose: false,
            strict: false,
        }
    }

    /// Set verbose mode.
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Set strict mode.
    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }
}

impl Default for ScanContext {
    fn default() -> Self {
        Self::new(Vec::new(), Config::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_context_builder() {
        let ctx = ScanContext::new(vec![PathBuf::from(".")], Config::default())
            .with_verbose(true)
            .with_strict(true);

        assert!(ctx.verbose);
        assert!(ctx.strict);
    }

    #[test]
    fn test_scan_context_default() {
        let ctx = ScanContext::default();
        assert!(ctx.paths.is_empty());
        assert!(!ctx.verbose);
        assert!(!ctx.strict);
    }

    #[test]
    fn test_scan_context_new() {
        let paths = vec![PathBuf::from("/test/path")];
        let ctx = ScanContext::new(paths.clone(), Config::default());
        assert_eq!(ctx.paths, paths);
        assert!(!ctx.verbose);
        assert!(!ctx.strict);
    }

    #[test]
    fn test_scan_context_debug() {
        let ctx = ScanContext::default();
        let debug_str = format!("{:?}", ctx);
        assert!(debug_str.contains("ScanContext"));
    }

    #[test]
    fn test_scan_context_clone() {
        let ctx = ScanContext::new(vec![PathBuf::from(".")], Config::default()).with_verbose(true);
        let cloned = ctx.clone();
        assert_eq!(ctx.paths, cloned.paths);
        assert_eq!(ctx.verbose, cloned.verbose);
    }
}
