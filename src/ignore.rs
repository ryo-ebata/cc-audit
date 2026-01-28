//! Ignore filter for scanning.
//!
//! Simple regex-based filtering for paths during scanning.

use crate::config::IgnoreConfig;
use regex::Regex;
use std::path::Path;
use tracing::warn;

/// Filter for ignoring paths during scanning.
///
/// Uses regex patterns to determine which paths to skip.
#[derive(Default)]
pub struct IgnoreFilter {
    /// Compiled regex patterns for ignoring paths.
    patterns: Vec<Regex>,
}

impl IgnoreFilter {
    /// Create a new empty IgnoreFilter.
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Create IgnoreFilter from config.
    pub fn from_config(config: &IgnoreConfig) -> Self {
        let patterns = config
            .patterns
            .iter()
            .filter_map(|p| match Regex::new(p) {
                Ok(regex) => Some(regex),
                Err(e) => {
                    warn!(pattern = %p, error = %e, "Invalid ignore pattern");
                    None
                }
            })
            .collect();

        Self { patterns }
    }

    /// Add a regex pattern to the filter.
    pub fn add_pattern(&mut self, pattern: &str) -> Result<(), regex::Error> {
        let regex = Regex::new(pattern)?;
        self.patterns.push(regex);
        Ok(())
    }

    /// Check if a path should be ignored.
    pub fn is_ignored(&self, path: &Path) -> bool {
        if self.patterns.is_empty() {
            return false;
        }

        let path_str = path.to_string_lossy();
        self.patterns.iter().any(|p| p.is_match(&path_str))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_filter() {
        let filter = IgnoreFilter::new();
        assert!(!filter.is_ignored(Path::new("/project/src/main.rs")));
    }

    #[test]
    fn test_simple_pattern() {
        let config = IgnoreConfig {
            patterns: vec!["node_modules".to_string()],
        };
        let filter = IgnoreFilter::from_config(&config);

        assert!(filter.is_ignored(Path::new("/project/node_modules/pkg/index.js")));
        assert!(!filter.is_ignored(Path::new("/project/src/main.rs")));
    }

    #[test]
    fn test_regex_pattern() {
        let config = IgnoreConfig {
            patterns: vec![r"\.test\.(js|ts)$".to_string()],
        };
        let filter = IgnoreFilter::from_config(&config);

        assert!(filter.is_ignored(Path::new("/project/src/app.test.js")));
        assert!(filter.is_ignored(Path::new("/project/src/app.test.ts")));
        assert!(!filter.is_ignored(Path::new("/project/src/app.js")));
    }

    #[test]
    fn test_multiple_patterns() {
        let config = IgnoreConfig {
            patterns: vec![
                "node_modules".to_string(),
                "target".to_string(),
                r"\.git/".to_string(),
            ],
        };
        let filter = IgnoreFilter::from_config(&config);

        assert!(filter.is_ignored(Path::new("/project/node_modules/pkg")));
        assert!(filter.is_ignored(Path::new("/project/target/debug/main")));
        assert!(filter.is_ignored(Path::new("/project/.git/config")));
        assert!(!filter.is_ignored(Path::new("/project/src/main.rs")));
    }

    #[test]
    fn test_invalid_pattern_is_skipped() {
        let config = IgnoreConfig {
            patterns: vec![
                "valid".to_string(),
                "[invalid".to_string(), // Invalid regex
                "also_valid".to_string(),
            ],
        };
        let filter = IgnoreFilter::from_config(&config);

        // Should have only 2 valid patterns
        assert_eq!(filter.patterns.len(), 2);
        assert!(filter.is_ignored(Path::new("/project/valid/file")));
        assert!(filter.is_ignored(Path::new("/project/also_valid/file")));
    }

    #[test]
    fn test_add_pattern() {
        let mut filter = IgnoreFilter::new();
        filter.add_pattern("node_modules").unwrap();

        assert!(filter.is_ignored(Path::new("/project/node_modules/pkg")));
    }

    #[test]
    fn test_directory_pattern() {
        let config = IgnoreConfig {
            patterns: vec![r"/tests?/".to_string()],
        };
        let filter = IgnoreFilter::from_config(&config);

        assert!(filter.is_ignored(Path::new("/project/tests/unit.rs")));
        assert!(filter.is_ignored(Path::new("/project/test/unit.rs")));
        assert!(!filter.is_ignored(Path::new("/project/src/contest.rs")));
    }

    #[test]
    fn test_extension_pattern() {
        let config = IgnoreConfig {
            patterns: vec![r"\.(log|tmp|bak)$".to_string()],
        };
        let filter = IgnoreFilter::from_config(&config);

        assert!(filter.is_ignored(Path::new("/project/debug.log")));
        assert!(filter.is_ignored(Path::new("/project/session.tmp")));
        assert!(filter.is_ignored(Path::new("/project/config.bak")));
        assert!(!filter.is_ignored(Path::new("/project/main.rs")));
    }
}
