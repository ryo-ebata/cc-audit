//! Scanner builder macros for reducing boilerplate.
//!
//! This module provides macros that generate common scanner builder methods,
//! reducing code duplication across scanner implementations.

/// Implements common scanner builder methods for structs with a `config: ScannerConfig` field.
///
/// This macro generates:
/// - `new()` - Creates a new scanner with default ScannerConfig
/// - `with_skip_comments(self, skip: bool)` - Builder method for skip_comments setting
/// - `with_dynamic_rules(self, rules: Vec<DynamicRule>)` - Builder method for dynamic rules
/// - `Default` trait implementation
///
/// # Example
///
/// ```ignore
/// use crate::engine::scanner::ScannerConfig;
/// use crate::impl_scanner_builder;
///
/// pub struct MyScanner {
///     config: ScannerConfig,
/// }
///
/// impl_scanner_builder!(MyScanner);
/// ```
#[macro_export]
macro_rules! impl_scanner_builder {
    ($scanner:ty) => {
        #[allow(dead_code)]
        impl $scanner {
            /// Creates a new scanner with default configuration.
            pub fn new() -> Self {
                Self {
                    config: $crate::scanner::ScannerConfig::new(),
                }
            }

            /// Enables or disables comment skipping during scanning.
            pub fn with_skip_comments(mut self, skip: bool) -> Self {
                self.config = self.config.with_skip_comments(skip);
                self
            }

            /// Adds dynamic rules loaded from custom YAML files.
            pub fn with_dynamic_rules(mut self, rules: Vec<$crate::rules::DynamicRule>) -> Self {
                self.config = self.config.with_dynamic_rules(rules);
                self
            }

            /// Enables or disables strict secrets mode.
            /// When enabled, dummy key heuristics are disabled for test files.
            pub fn with_strict_secrets(mut self, strict: bool) -> Self {
                self.config = self.config.with_strict_secrets(strict);
                self
            }

            /// Enables or disables recursive scanning.
            /// When disabled, only scans the immediate directory (max_depth = 1).
            pub fn with_recursive(mut self, recursive: bool) -> Self {
                self.config = self.config.with_recursive(recursive);
                self
            }

            /// Sets a progress callback that will be called for each scanned file.
            pub fn with_progress_callback(
                mut self,
                callback: $crate::engine::scanner::ProgressCallback,
            ) -> Self {
                self.config = self.config.with_progress_callback(callback);
                self
            }
        }

        impl Default for $scanner {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

/// Implements the ContentScanner trait for scanners that use default content scanning.
///
/// This macro generates a ContentScanner implementation that delegates to ScannerConfig.
/// Use this for scanners that don't need custom content processing.
///
/// # Example
///
/// ```ignore
/// use crate::engine::scanner::{ContentScanner, ScannerConfig};
/// use crate::{impl_scanner_builder, impl_content_scanner};
///
/// pub struct MyScanner {
///     config: ScannerConfig,
/// }
///
/// impl_scanner_builder!(MyScanner);
/// impl_content_scanner!(MyScanner);
/// ```
#[macro_export]
macro_rules! impl_content_scanner {
    ($scanner:ty) => {
        impl $crate::engine::scanner::ContentScanner for $scanner {
            fn config(&self) -> &$crate::engine::scanner::ScannerConfig {
                &self.config
            }
        }
    };
}

/// Implements a simple Scanner trait for file-based scanners.
///
/// This macro generates a Scanner implementation that:
/// - Reads file content and delegates to check_content for scan_file
/// - Iterates over a directory pattern for scan_directory
///
/// # Arguments
///
/// - `$scanner` - The scanner type
/// - `$pattern` - A closure that returns file patterns to check in scan_directory
///
/// # Example
///
/// ```ignore
/// impl_simple_scanner!(MyScanner, |dir| vec![
///     dir.join("config.json"),
///     dir.join(".config.json"),
/// ]);
/// ```
#[macro_export]
macro_rules! impl_simple_file_scanner {
    ($scanner:ty, $file_patterns:expr) => {
        impl $crate::scanner::Scanner for $scanner {
            fn scan_file(
                &self,
                path: &std::path::Path,
            ) -> $crate::error::Result<Vec<$crate::rules::Finding>> {
                let content = self.config.read_file(path)?;
                let path_str = path.display().to_string();
                Ok(self.config.check_content(&content, &path_str))
            }

            fn scan_directory(
                &self,
                dir: &std::path::Path,
            ) -> $crate::error::Result<Vec<$crate::rules::Finding>> {
                let mut findings = Vec::new();
                let patterns_fn: fn(&std::path::Path) -> Vec<std::path::PathBuf> = $file_patterns;
                let patterns = patterns_fn(dir);

                for pattern in patterns {
                    if pattern.exists() {
                        findings.extend(self.scan_file(&pattern)?);
                    }
                }

                Ok(findings)
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::engine::scanner::ScannerConfig;

    // Test struct for macro testing
    pub struct TestScanner {
        config: ScannerConfig,
    }

    impl_scanner_builder!(TestScanner);

    #[test]
    fn test_new_scanner() {
        let scanner = TestScanner::new();
        assert!(!scanner.config.skip_comments());
    }

    #[test]
    fn test_with_skip_comments() {
        let scanner = TestScanner::new().with_skip_comments(true);
        assert!(scanner.config.skip_comments());
    }

    #[test]
    fn test_with_dynamic_rules() {
        let scanner = TestScanner::new().with_dynamic_rules(vec![]);
        // Just verify it compiles and runs
        assert!(!scanner.config.skip_comments());
    }

    #[test]
    fn test_with_strict_secrets() {
        let scanner = TestScanner::new().with_strict_secrets(true);
        assert!(scanner.config.strict_secrets());
    }

    #[test]
    fn test_default_trait() {
        let scanner = TestScanner::default();
        assert!(!scanner.config.skip_comments());
    }

    // Test ContentScanner macro
    #[allow(dead_code)]
    pub struct TestContentScanner {
        config: ScannerConfig,
    }

    impl_scanner_builder!(TestContentScanner);

    // Scanner trait is required for ContentScanner
    impl crate::scanner::Scanner for TestContentScanner {
        fn scan_file(
            &self,
            _path: &std::path::Path,
        ) -> crate::error::Result<Vec<crate::rules::Finding>> {
            Ok(vec![])
        }

        fn scan_directory(
            &self,
            _dir: &std::path::Path,
        ) -> crate::error::Result<Vec<crate::rules::Finding>> {
            Ok(vec![])
        }
    }

    impl_content_scanner!(TestContentScanner);

    #[test]
    fn test_content_scanner_config_access() {
        use crate::engine::scanner::ContentScanner;
        let scanner = TestContentScanner::new();
        let _config = scanner.config();
        // Just verify it compiles
    }
}
