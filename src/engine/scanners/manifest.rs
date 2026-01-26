//! Manifest scanner trait for JSON/YAML based scanners.

use crate::engine::scanner::{Scanner, ScannerConfig};
use crate::error::Result;
use crate::rules::Finding;
use serde::de::DeserializeOwned;
use std::path::Path;

/// Trait for scanners that parse structured manifest files.
///
/// This trait provides a common interface for scanners that:
/// 1. Parse a manifest file (JSON, YAML, etc.)
/// 2. Extract findings from the parsed structure
/// 3. Also check raw content for pattern-based rules
pub trait ManifestScanner: Scanner {
    /// The manifest type to parse.
    type Manifest: DeserializeOwned;

    /// Returns a reference to the scanner configuration.
    fn scanner_config(&self) -> &ScannerConfig;

    /// Extract findings from the parsed manifest.
    fn scan_manifest(&self, manifest: &Self::Manifest, file_path: &str) -> Vec<Finding>;

    /// Returns the manifest file patterns to look for (e.g., ["mcp.json", ".mcp.json"]).
    fn manifest_patterns(&self) -> &[&'static str];

    /// Parse and scan content with the default implementation.
    ///
    /// This method:
    /// 1. Parses the content as the manifest type
    /// 2. Extracts findings from the manifest structure
    /// 3. Also checks raw content for pattern-based rules
    fn scan_manifest_content(&self, content: &str, file_path: &str) -> Result<Vec<Finding>> {
        // Try to parse as JSON first
        let manifest: Self::Manifest =
            serde_json::from_str(content).map_err(|e| crate::error::AuditError::ParseError {
                path: file_path.to_string(),
                message: e.to_string(),
            })?;

        let mut findings = self.scan_manifest(&manifest, file_path);

        // Also check raw content for pattern-based rules
        findings.extend(self.scanner_config().check_content(content, file_path));

        Ok(findings)
    }
}

/// Scan a directory for manifest files using a ManifestScanner.
pub fn scan_manifest_directory<S: ManifestScanner>(
    scanner: &S,
    dir: &Path,
) -> Result<Vec<Finding>> {
    let mut findings = Vec::new();

    for pattern in scanner.manifest_patterns() {
        let path = dir.join(pattern);
        if path.exists() && path.is_file() {
            findings.extend(scanner.scan_file(&path)?);
        }
    }

    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::scanner::ScannerConfig;
    use serde::Deserialize;
    use std::fs;
    use tempfile::TempDir;

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct TestManifest {
        name: String,
        #[serde(default)]
        dangerous: bool,
    }

    struct TestScanner {
        config: ScannerConfig,
    }

    impl TestScanner {
        fn new() -> Self {
            Self {
                config: ScannerConfig::new(),
            }
        }
    }

    impl Scanner for TestScanner {
        fn scan_file(&self, path: &Path) -> Result<Vec<Finding>> {
            let content = self.config.read_file(path)?;
            self.scan_manifest_content(&content, &path.display().to_string())
        }

        fn scan_directory(&self, dir: &Path) -> Result<Vec<Finding>> {
            scan_manifest_directory(self, dir)
        }
    }

    impl ManifestScanner for TestScanner {
        type Manifest = TestManifest;

        fn scanner_config(&self) -> &ScannerConfig {
            &self.config
        }

        fn scan_manifest(&self, manifest: &Self::Manifest, file_path: &str) -> Vec<Finding> {
            let mut findings = Vec::new();
            if manifest.dangerous {
                findings.push(Finding {
                    id: "TEST-001".to_string(),
                    name: "Dangerous flag".to_string(),
                    severity: crate::rules::Severity::High,
                    confidence: crate::rules::Confidence::Certain,
                    category: crate::rules::Category::PrivilegeEscalation,
                    location: crate::rules::Location {
                        file: file_path.to_string(),
                        line: 1,
                        column: None,
                    },
                    code: "dangerous: true".to_string(),
                    message: "Dangerous flag is set".to_string(),
                    recommendation: "Remove dangerous flag".to_string(),
                    fix_hint: None,
                    cwe_ids: Vec::new(),
                    rule_severity: Some(crate::rules::RuleSeverity::Error),
                    client: None,
                    context: None,
                });
            }
            findings
        }

        fn manifest_patterns(&self) -> &[&'static str] {
            &["test.json", ".test.json"]
        }
    }

    #[test]
    fn test_manifest_scanner_safe() {
        let dir = TempDir::new().unwrap();
        let manifest_path = dir.path().join("test.json");
        fs::write(&manifest_path, r#"{"name": "safe"}"#).unwrap();

        let scanner = TestScanner::new();
        let findings = scanner.scan_file(&manifest_path).unwrap();

        assert!(findings.is_empty());
    }

    #[test]
    fn test_manifest_scanner_dangerous() {
        let dir = TempDir::new().unwrap();
        let manifest_path = dir.path().join("test.json");
        fs::write(&manifest_path, r#"{"name": "unsafe", "dangerous": true}"#).unwrap();

        let scanner = TestScanner::new();
        let findings = scanner.scan_file(&manifest_path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "TEST-001");
    }

    #[test]
    fn test_scan_manifest_directory() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("test.json"), r#"{"name": "test"}"#).unwrap();

        let scanner = TestScanner::new();
        let findings = scanner.scan_directory(dir.path()).unwrap();

        assert!(findings.is_empty());
    }
}
