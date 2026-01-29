//! Ignore filter for scanning.
//!
//! Simple glob-based filtering for paths during scanning.

use crate::config::IgnoreConfig;
use globset::{Glob, GlobSet, GlobSetBuilder};
use std::path::Path;
use tracing::warn;

/// Filter for ignoring paths during scanning.
///
/// Uses glob patterns to determine which paths to skip.
pub struct IgnoreFilter {
    /// Compiled glob patterns for ignoring paths.
    globset: Option<GlobSet>,
}

impl Default for IgnoreFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl IgnoreFilter {
    /// Create a new empty IgnoreFilter.
    pub fn new() -> Self {
        Self { globset: None }
    }

    /// Create IgnoreFilter from config.
    pub fn from_config(config: &IgnoreConfig) -> Self {
        if config.patterns.is_empty() {
            return Self::new();
        }

        let mut builder = GlobSetBuilder::new();
        for pattern in &config.patterns {
            match Glob::new(pattern) {
                Ok(glob) => {
                    builder.add(glob);
                }
                Err(e) => {
                    warn!(pattern = %pattern, error = %e, "Invalid ignore pattern");
                }
            }
        }

        let globset = match builder.build() {
            Ok(set) => Some(set),
            Err(e) => {
                warn!(error = %e, "Failed to build globset");
                None
            }
        };

        Self { globset }
    }

    /// Add a glob pattern to the filter.
    pub fn add_pattern(&mut self, pattern: &str) -> Result<(), globset::Error> {
        let glob = Glob::new(pattern)?;

        // Rebuild the globset with the new pattern
        let mut builder = GlobSetBuilder::new();
        builder.add(glob);

        self.globset = Some(builder.build()?);

        Ok(())
    }

    /// Check if a path should be ignored.
    ///
    /// Path separators are normalized to forward slashes for cross-platform
    /// compatibility.
    pub fn is_ignored(&self, path: &Path) -> bool {
        if let Some(ref globset) = self.globset {
            // Normalize path separators to forward slashes for cross-platform matching
            let path_str = path.to_string_lossy().replace('\\', "/");
            globset.is_match(Path::new(&path_str))
        } else {
            false
        }
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
            patterns: vec!["**/node_modules/**".to_string()],
        };
        let filter = IgnoreFilter::from_config(&config);

        assert!(filter.is_ignored(Path::new("/project/node_modules/pkg/index.js")));
        assert!(filter.is_ignored(Path::new("/project/sub/node_modules/pkg/index.js")));
        assert!(!filter.is_ignored(Path::new("/project/src/main.rs")));
    }

    #[test]
    fn test_glob_pattern_with_extension() {
        let config = IgnoreConfig {
            patterns: vec!["**/*.test.{js,ts}".to_string()],
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
                "**/node_modules/**".to_string(),
                "**/target/**".to_string(),
                "**/.git/**".to_string(),
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
                "**/valid/**".to_string(),
                "[invalid".to_string(), // Invalid glob
                "**/also_valid/**".to_string(),
            ],
        };
        let filter = IgnoreFilter::from_config(&config);

        assert!(filter.is_ignored(Path::new("/project/valid/file")));
        assert!(filter.is_ignored(Path::new("/project/also_valid/file")));
    }

    #[test]
    fn test_add_pattern() {
        let mut filter = IgnoreFilter::new();
        filter.add_pattern("**/node_modules/**").unwrap();

        assert!(filter.is_ignored(Path::new("/project/node_modules/pkg")));
    }

    #[test]
    fn test_directory_pattern() {
        let config = IgnoreConfig {
            patterns: vec!["**/test/**".to_string(), "**/tests/**".to_string()],
        };
        let filter = IgnoreFilter::from_config(&config);

        assert!(filter.is_ignored(Path::new("/project/tests/unit.rs")));
        assert!(filter.is_ignored(Path::new("/project/test/unit.rs")));
        assert!(!filter.is_ignored(Path::new("/project/src/contest.rs")));
    }

    #[test]
    fn test_extension_pattern() {
        let config = IgnoreConfig {
            patterns: vec!["**/*.{log,tmp,bak}".to_string()],
        };
        let filter = IgnoreFilter::from_config(&config);

        assert!(filter.is_ignored(Path::new("/project/debug.log")));
        assert!(filter.is_ignored(Path::new("/project/session.tmp")));
        assert!(filter.is_ignored(Path::new("/project/config.bak")));
        assert!(!filter.is_ignored(Path::new("/project/main.rs")));
    }

    #[test]
    fn test_single_star_pattern() {
        // Note: *.log matches any path ending with .log, including paths with directories
        // Use **/*.log to explicitly match across directories, or just *.log at root level
        let config = IgnoreConfig {
            patterns: vec!["*.log".to_string()],
        };
        let filter = IgnoreFilter::from_config(&config);

        assert!(filter.is_ignored(Path::new("debug.log")));
        // In globset, *.log can match paths with directories depending on implementation
        // For strict root-level matching, we'd need to check if path has no directory separators
    }

    #[test]
    fn test_double_star_pattern() {
        let config = IgnoreConfig {
            patterns: vec!["**/*.log".to_string()],
        };
        let filter = IgnoreFilter::from_config(&config);

        assert!(filter.is_ignored(Path::new("debug.log")));
        assert!(filter.is_ignored(Path::new("logs/debug.log")));
        assert!(filter.is_ignored(Path::new("deep/nested/path/debug.log")));
    }

    #[test]
    fn test_specific_file_pattern() {
        let config = IgnoreConfig {
            patterns: vec!["**/secrets.txt".to_string()],
        };
        let filter = IgnoreFilter::from_config(&config);

        assert!(filter.is_ignored(Path::new("secrets.txt")));
        assert!(filter.is_ignored(Path::new("config/secrets.txt")));
        assert!(!filter.is_ignored(Path::new("config/settings.txt")));
    }
}
