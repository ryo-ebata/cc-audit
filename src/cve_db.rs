//! CVE database for known vulnerabilities in AI coding tools.
//!
//! This module provides functionality to load and query a database of known CVEs
//! affecting MCP servers, AI coding assistants, and related tools.

use crate::rules::{Category, Confidence, Finding, Location, Severity};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

/// Built-in CVE database (embedded at compile time)
const BUILTIN_DATABASE: &str = include_str!("../data/cve-database.json");

#[derive(Debug, Error)]
pub enum CveDbError {
    #[error("Failed to read CVE database file: {0}")]
    ReadFile(#[from] std::io::Error),

    #[error("Failed to parse CVE database JSON: {0}")]
    ParseJson(#[from] serde_json::Error),

    #[error("Failed to parse version requirement for {cve_id}: {version}")]
    InvalidVersion { cve_id: String, version: String },
}

/// Affected product information in a CVE entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedProduct {
    pub vendor: String,
    pub product: String,
    pub version_affected: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_fixed: Option<String>,
}

/// A CVE entry in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f32>,
    pub affected_products: Vec<AffectedProduct>,
    #[serde(default)]
    pub cwe_ids: Vec<String>,
    #[serde(default)]
    pub references: Vec<String>,
    pub published_at: String,
}

/// CVE database file format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveDatabaseFile {
    pub version: String,
    pub updated_at: String,
    pub entries: Vec<CveEntry>,
}

/// CVE database for querying known vulnerabilities
pub struct CveDatabase {
    entries: Vec<CveEntry>,
    version: String,
    updated_at: String,
}

impl CveDatabase {
    /// Load the built-in CVE database
    pub fn builtin() -> Result<Self, CveDbError> {
        Self::from_json(BUILTIN_DATABASE)
    }

    /// Load CVE database from a JSON file
    pub fn from_file(path: &Path) -> Result<Self, CveDbError> {
        let content = fs::read_to_string(path)?;
        Self::from_json(&content)
    }

    /// Load CVE database from a JSON string
    pub fn from_json(json: &str) -> Result<Self, CveDbError> {
        let file: CveDatabaseFile = serde_json::from_str(json)?;
        Ok(Self {
            entries: file.entries,
            version: file.version,
            updated_at: file.updated_at,
        })
    }

    /// Get database version
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Get last update timestamp
    pub fn updated_at(&self) -> &str {
        &self.updated_at
    }

    /// Get all entries
    pub fn entries(&self) -> &[CveEntry] {
        &self.entries
    }

    /// Get entry count
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if database is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Check if a product/version combination is affected by any CVE
    /// Returns matching CVE entries
    pub fn check_product(&self, vendor: &str, product: &str, version: &str) -> Vec<&CveEntry> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.affected_products.iter().any(|p| {
                    p.vendor.eq_ignore_ascii_case(vendor)
                        && p.product.eq_ignore_ascii_case(product)
                        && Self::version_matches(&p.version_affected, version)
                })
            })
            .collect()
    }

    /// Check if a version string matches a version requirement
    /// Supports: "< X.Y.Z", "<= X.Y.Z", "= X.Y.Z", ">= X.Y.Z", "> X.Y.Z"
    fn version_matches(requirement: &str, version: &str) -> bool {
        let requirement = requirement.trim();

        // Parse the operator and version from the requirement
        let (op, req_version) = if let Some(rest) = requirement.strip_prefix("<=") {
            ("<=", rest.trim())
        } else if let Some(rest) = requirement.strip_prefix(">=") {
            (">=", rest.trim())
        } else if let Some(rest) = requirement.strip_prefix('<') {
            ("<", rest.trim())
        } else if let Some(rest) = requirement.strip_prefix('>') {
            (">", rest.trim())
        } else if let Some(rest) = requirement.strip_prefix('=') {
            ("=", rest.trim())
        } else {
            ("=", requirement) // Default to exact match
        };

        // Parse versions into comparable parts
        let version_parts = Self::parse_version(version);
        let req_parts = Self::parse_version(req_version);

        match op {
            "<" => Self::compare_versions(&version_parts, &req_parts) < 0,
            "<=" => Self::compare_versions(&version_parts, &req_parts) <= 0,
            ">" => Self::compare_versions(&version_parts, &req_parts) > 0,
            ">=" => Self::compare_versions(&version_parts, &req_parts) >= 0,
            _ => Self::compare_versions(&version_parts, &req_parts) == 0,
        }
    }

    /// Parse version string into comparable parts
    fn parse_version(version: &str) -> Vec<u32> {
        version
            .split(['.', '-', '_'])
            .filter_map(|s| {
                // Extract leading numeric part
                let num_str: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
                num_str.parse().ok()
            })
            .collect()
    }

    /// Compare two parsed versions
    /// Returns: -1 if a < b, 0 if a == b, 1 if a > b
    fn compare_versions(a: &[u32], b: &[u32]) -> i32 {
        let max_len = a.len().max(b.len());
        for i in 0..max_len {
            let av = a.get(i).copied().unwrap_or(0);
            let bv = b.get(i).copied().unwrap_or(0);
            if av < bv {
                return -1;
            }
            if av > bv {
                return 1;
            }
        }
        0
    }

    /// Create findings for matching CVEs
    pub fn create_findings(
        &self,
        vendor: &str,
        product: &str,
        version: &str,
        file_path: &str,
        line: usize,
    ) -> Vec<Finding> {
        let matches = self.check_product(vendor, product, version);

        matches
            .into_iter()
            .map(|cve| Finding {
                id: cve.id.clone(),
                severity: Self::parse_severity(&cve.severity),
                category: Category::SupplyChain,
                confidence: Confidence::Certain,
                name: cve.title.clone(),
                location: Location {
                    file: file_path.to_string(),
                    line,
                    column: None,
                },
                code: format!("{}/{} v{}", vendor, product, version),
                message: cve.description.clone(),
                recommendation: if let Some(ref fixed) = cve
                    .affected_products
                    .iter()
                    .find(|p| {
                        p.vendor.eq_ignore_ascii_case(vendor)
                            && p.product.eq_ignore_ascii_case(product)
                    })
                    .and_then(|p| p.version_fixed.clone())
                {
                    format!("Update to version {} or later", fixed)
                } else {
                    "Check for security updates from the vendor".to_string()
                },
                fix_hint: None,
                cwe_ids: cve.cwe_ids.clone(),
                rule_severity: None,
                client: None,
                context: None,
            })
            .collect()
    }

    fn parse_severity(s: &str) -> Severity {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Medium,
        }
    }
}

impl Default for CveDatabase {
    fn default() -> Self {
        Self::builtin().expect("Built-in CVE database should be valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_builtin_database() {
        let db = CveDatabase::builtin().unwrap();
        assert!(!db.is_empty());
        assert_eq!(db.version(), "1.0.0");
    }

    #[test]
    fn test_version_comparison_less_than() {
        assert!(CveDatabase::version_matches("< 1.5.0", "1.4.9"));
        assert!(CveDatabase::version_matches("< 1.5.0", "1.4.0"));
        assert!(CveDatabase::version_matches("< 1.5.0", "0.9.0"));
        assert!(!CveDatabase::version_matches("< 1.5.0", "1.5.0"));
        assert!(!CveDatabase::version_matches("< 1.5.0", "1.5.1"));
        assert!(!CveDatabase::version_matches("< 1.5.0", "2.0.0"));
    }

    #[test]
    fn test_version_comparison_less_than_or_equal() {
        assert!(CveDatabase::version_matches("<= 1.5.0", "1.4.9"));
        assert!(CveDatabase::version_matches("<= 1.5.0", "1.5.0"));
        assert!(!CveDatabase::version_matches("<= 1.5.0", "1.5.1"));
    }

    #[test]
    fn test_version_comparison_greater_than() {
        assert!(CveDatabase::version_matches("> 1.5.0", "1.5.1"));
        assert!(CveDatabase::version_matches("> 1.5.0", "2.0.0"));
        assert!(!CveDatabase::version_matches("> 1.5.0", "1.5.0"));
        assert!(!CveDatabase::version_matches("> 1.5.0", "1.4.9"));
    }

    #[test]
    fn test_version_comparison_equal() {
        assert!(CveDatabase::version_matches("= 1.5.0", "1.5.0"));
        assert!(!CveDatabase::version_matches("= 1.5.0", "1.5.1"));
        assert!(!CveDatabase::version_matches("= 1.5.0", "1.4.9"));
    }

    #[test]
    fn test_check_product_matches() {
        let db = CveDatabase::builtin().unwrap();
        let matches = db.check_product("anthropic", "claude-code-vscode", "1.4.0");
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|e| e.id == "CVE-2025-52882"));
    }

    #[test]
    fn test_check_product_no_match_fixed_version() {
        let db = CveDatabase::builtin().unwrap();
        let matches = db.check_product("anthropic", "claude-code-vscode", "1.5.0");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_check_product_case_insensitive() {
        let db = CveDatabase::builtin().unwrap();
        let matches = db.check_product("Anthropic", "Claude-Code-VSCode", "1.4.0");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_create_findings() {
        let db = CveDatabase::builtin().unwrap();
        let findings = db.create_findings(
            "anthropic",
            "claude-code-vscode",
            "1.4.0",
            "package.json",
            10,
        );
        assert!(!findings.is_empty());

        let finding = &findings[0];
        assert_eq!(finding.id, "CVE-2025-52882");
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.category, Category::SupplyChain);
        assert!(finding.recommendation.contains("1.5.0"));
    }

    #[test]
    fn test_parse_version_with_prerelease() {
        let parts = CveDatabase::parse_version("1.5.0-beta.1");
        assert_eq!(parts, vec![1, 5, 0, 1]);
    }

    #[test]
    fn test_entry_count() {
        let db = CveDatabase::builtin().unwrap();
        assert_eq!(db.len(), 7); // 7 CVEs in built-in database
    }

    #[test]
    fn test_updated_at() {
        let db = CveDatabase::builtin().unwrap();
        let updated = db.updated_at();
        // Should be a date string like "2025-01-XX"
        assert!(!updated.is_empty());
        assert!(updated.starts_with("2025-") || updated.starts_with("2024-"));
    }

    #[test]
    fn test_entries() {
        let db = CveDatabase::builtin().unwrap();
        let entries = db.entries();
        assert!(!entries.is_empty());
        // First entry should have a CVE ID
        assert!(entries[0].id.starts_with("CVE-"));
    }

    #[test]
    fn test_from_file() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a temporary file with valid CVE database JSON
        let mut temp_file = NamedTempFile::new().unwrap();
        let json = r#"{
            "version": "1.0.0",
            "updated_at": "2025-01-01",
            "entries": []
        }"#;
        temp_file.write_all(json.as_bytes()).unwrap();

        let db = CveDatabase::from_file(temp_file.path()).unwrap();
        assert_eq!(db.version(), "1.0.0");
        assert!(db.is_empty());
    }

    #[test]
    fn test_from_file_invalid_path() {
        let result = CveDatabase::from_file(Path::new("/nonexistent/file.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_version_comparison_greater_than_or_equal() {
        // Test >= operator (line 140)
        assert!(CveDatabase::version_matches(">= 1.5.0", "1.5.0"));
        assert!(CveDatabase::version_matches(">= 1.5.0", "1.5.1"));
        assert!(CveDatabase::version_matches(">= 1.5.0", "2.0.0"));
        assert!(!CveDatabase::version_matches(">= 1.5.0", "1.4.9"));
        assert!(!CveDatabase::version_matches(">= 1.5.0", "1.4.0"));
    }

    #[test]
    fn test_version_comparison_exact_match_no_operator() {
        // Test default exact match without operator (line 148)
        assert!(CveDatabase::version_matches("1.5.0", "1.5.0"));
        assert!(!CveDatabase::version_matches("1.5.0", "1.5.1"));
        assert!(!CveDatabase::version_matches("1.5.0", "1.4.9"));
    }
}
