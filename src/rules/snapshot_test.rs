//! Snapshot testing helpers for rules.
//!
//! This module provides utilities for snapshot testing of individual rules,
//! allowing regression detection when rule behavior changes.

use crate::rules::types::{Category, Confidence, Finding, Location, Rule, Severity};
use serde::Serialize;

/// Macro for asserting rule snapshots with co-located snapshot files.
///
/// This macro stores snapshots in `tests/fixtures/rules/` alongside the test case files,
/// making it easy to see both input and expected output together.
///
/// # Usage
/// ```ignore
/// assert_rule_snapshot!("ex_001", findings);
/// ```
#[macro_export]
macro_rules! assert_rule_snapshot {
    ($name:expr, $value:expr) => {
        insta::with_settings!({
            snapshot_path => concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/rules"),
            prepend_module_to_snapshot => false,
        }, {
            insta::assert_json_snapshot!($name, $value);
        });
    };
}

/// A normalized finding for snapshot testing.
/// This struct excludes volatile fields like file paths that would change between test runs.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SnapshotFinding {
    pub id: String,
    pub severity: String,
    pub category: String,
    pub confidence: String,
    pub name: String,
    pub line: usize,
    pub code: String,
    pub message: String,
    pub recommendation: String,
}

impl From<&Finding> for SnapshotFinding {
    fn from(f: &Finding) -> Self {
        Self {
            id: f.id.clone(),
            severity: f.severity.as_str().to_string(),
            category: f.category.as_str().to_string(),
            confidence: f.confidence.as_str().to_string(),
            name: f.name.clone(),
            line: f.location.line,
            code: f.code.clone(),
            message: f.message.clone(),
            recommendation: f.recommendation.clone(),
        }
    }
}

/// Scan content with a single rule and return normalized findings for snapshot testing.
///
/// # Arguments
/// * `rule` - The rule to test
/// * `content` - The content to scan (multi-line string)
///
/// # Returns
/// A vector of `SnapshotFinding` that can be used with insta's `assert_json_snapshot!`
pub fn scan_with_rule(rule: &Rule, content: &str) -> Vec<SnapshotFinding> {
    let mut findings = Vec::new();

    for (line_number, line) in content.lines().enumerate() {
        let line_num = line_number + 1;

        // Skip empty lines and comments
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Check if any pattern matches
        let pattern_match = rule.patterns.iter().any(|p| p.is_match(line));
        if !pattern_match {
            continue;
        }

        // Check if any exclusion matches
        let excluded = rule.exclusions.iter().any(|e| e.is_match(line));
        if excluded {
            continue;
        }

        // Create finding
        let finding = Finding::new(
            rule,
            Location {
                file: "test_input.txt".to_string(),
                line: line_num,
                column: None,
            },
            line.to_string(),
        );

        findings.push(SnapshotFinding::from(&finding));
    }

    findings
}

/// Scan content with a rule and return findings only for the specified rule ID.
/// This is useful when testing rules in modules that have multiple rules.
pub fn scan_with_rule_id(rule: &Rule, content: &str, expected_id: &str) -> Vec<SnapshotFinding> {
    scan_with_rule(rule, content)
        .into_iter()
        .filter(|f| f.id == expected_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;

    fn create_test_rule() -> Rule {
        Rule {
            id: "TEST-001",
            name: "Test Rule",
            description: "A test rule for testing",
            severity: Severity::High,
            category: Category::Exfiltration,
            confidence: Confidence::Firm,
            patterns: vec![Regex::new(r"secret_pattern").unwrap()],
            exclusions: vec![Regex::new(r"# safe").unwrap()],
            message: "Test message",
            recommendation: "Test recommendation",
            fix_hint: None,
            cwe_ids: &[],
        }
    }

    #[test]
    fn test_scan_with_rule_detects_pattern() {
        let rule = create_test_rule();
        let content = "line 1\nsecret_pattern here\nline 3";

        let findings = scan_with_rule(&rule, content);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "TEST-001");
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].code, "secret_pattern here");
    }

    #[test]
    fn test_scan_with_rule_respects_exclusions() {
        let rule = create_test_rule();
        let content = "secret_pattern # safe context";

        let findings = scan_with_rule(&rule, content);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_with_rule_skips_comments() {
        let rule = create_test_rule();
        let content = "# secret_pattern in comment\nsecret_pattern real";

        let findings = scan_with_rule(&rule, content);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
    }

    #[test]
    fn test_scan_with_rule_skips_empty_lines() {
        let rule = create_test_rule();
        let content = "\n\nsecret_pattern\n\n";

        let findings = scan_with_rule(&rule, content);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 3);
    }

    #[test]
    fn test_snapshot_finding_serialization() {
        let finding = SnapshotFinding {
            id: "TEST-001".to_string(),
            severity: "high".to_string(),
            category: "exfiltration".to_string(),
            confidence: "firm".to_string(),
            name: "Test".to_string(),
            line: 1,
            code: "test code".to_string(),
            message: "message".to_string(),
            recommendation: "recommendation".to_string(),
        };

        let json = serde_json::to_string_pretty(&finding).unwrap();
        assert!(json.contains("\"id\": \"TEST-001\""));
        assert!(json.contains("\"line\": 1"));
    }

    #[test]
    fn test_scan_with_rule_multiple_matches() {
        let rule = create_test_rule();
        let content = "secret_pattern first\nsome other line\nsecret_pattern second";

        let findings = scan_with_rule(&rule, content);

        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].line, 1);
        assert_eq!(findings[1].line, 3);
    }
}
