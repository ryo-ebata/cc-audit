//! Finding collector for aggregating scan results.

use crate::rules::{Finding, Severity};
use std::collections::HashMap;

/// Collects and aggregates findings from multiple scans.
#[derive(Debug, Default)]
pub struct FindingCollector {
    findings: Vec<Finding>,
    by_file: HashMap<String, Vec<Finding>>,
    by_severity: HashMap<Severity, Vec<Finding>>,
    by_rule: HashMap<String, Vec<Finding>>,
}

impl FindingCollector {
    /// Create a new finding collector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a finding to the collector.
    pub fn add(&mut self, finding: Finding) {
        // Index by file
        self.by_file
            .entry(finding.location.file.clone())
            .or_default()
            .push(finding.clone());

        // Index by severity
        self.by_severity
            .entry(finding.severity)
            .or_default()
            .push(finding.clone());

        // Index by rule
        self.by_rule
            .entry(finding.id.clone())
            .or_default()
            .push(finding.clone());

        self.findings.push(finding);
    }

    /// Add multiple findings.
    pub fn add_all(&mut self, findings: impl IntoIterator<Item = Finding>) {
        for finding in findings {
            self.add(finding);
        }
    }

    /// Get all findings.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Get findings for a specific file.
    pub fn by_file(&self, file: &str) -> &[Finding] {
        self.by_file.get(file).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get findings for a specific severity.
    pub fn by_severity(&self, severity: Severity) -> &[Finding] {
        self.by_severity
            .get(&severity)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get findings for a specific rule.
    pub fn by_rule(&self, rule_id: &str) -> &[Finding] {
        self.by_rule
            .get(rule_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get the total number of findings.
    pub fn total(&self) -> usize {
        self.findings.len()
    }

    /// Get the number of unique files with findings.
    pub fn files_count(&self) -> usize {
        self.by_file.len()
    }

    /// Get the number of unique rules that matched.
    pub fn rules_count(&self) -> usize {
        self.by_rule.len()
    }

    /// Check if there are any findings.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Get the highest severity among all findings.
    pub fn highest_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Consume the collector and return all findings.
    pub fn into_findings(self) -> Vec<Finding> {
        self.findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Category, Confidence, Location};

    fn make_finding(id: &str, file: &str, severity: Severity) -> Finding {
        Finding {
            id: id.to_string(),
            severity,
            category: Category::PromptInjection,
            confidence: Confidence::Firm,
            name: "Test".to_string(),
            location: Location {
                file: file.to_string(),
                line: 1,
                column: None,
            },
            code: "test".to_string(),
            message: "test".to_string(),
            recommendation: "fix".to_string(),
            fix_hint: None,
            cwe_ids: Vec::new(),
            rule_severity: None,
            client: None,
            context: None,
        }
    }

    #[test]
    fn test_collector_add() {
        let mut collector = FindingCollector::new();
        collector.add(make_finding("RULE-001", "test.md", Severity::High));
        collector.add(make_finding("RULE-002", "test.md", Severity::Medium));

        assert_eq!(collector.total(), 2);
        assert_eq!(collector.files_count(), 1);
        assert_eq!(collector.rules_count(), 2);
    }

    #[test]
    fn test_collector_by_severity() {
        let mut collector = FindingCollector::new();
        collector.add(make_finding("RULE-001", "a.md", Severity::High));
        collector.add(make_finding("RULE-002", "b.md", Severity::Medium));
        collector.add(make_finding("RULE-003", "c.md", Severity::High));

        assert_eq!(collector.by_severity(Severity::High).len(), 2);
        assert_eq!(collector.by_severity(Severity::Medium).len(), 1);
        assert_eq!(collector.by_severity(Severity::Critical).len(), 0);
    }

    #[test]
    fn test_collector_highest_severity() {
        let mut collector = FindingCollector::new();
        collector.add(make_finding("RULE-001", "a.md", Severity::Low));
        assert_eq!(collector.highest_severity(), Some(Severity::Low));

        collector.add(make_finding("RULE-002", "b.md", Severity::Critical));
        assert_eq!(collector.highest_severity(), Some(Severity::Critical));
    }

    #[test]
    fn test_collector_is_empty() {
        let collector = FindingCollector::new();
        assert!(collector.is_empty());

        let mut collector2 = FindingCollector::new();
        collector2.add(make_finding("RULE-001", "a.md", Severity::Low));
        assert!(!collector2.is_empty());
    }

    #[test]
    fn test_collector_by_file() {
        let mut collector = FindingCollector::new();
        collector.add(make_finding("RULE-001", "file1.md", Severity::High));
        collector.add(make_finding("RULE-002", "file1.md", Severity::Medium));
        collector.add(make_finding("RULE-003", "file2.md", Severity::Low));

        assert_eq!(collector.by_file("file1.md").len(), 2);
        assert_eq!(collector.by_file("file2.md").len(), 1);
        assert_eq!(collector.by_file("nonexistent.md").len(), 0);
    }

    #[test]
    fn test_collector_by_rule() {
        let mut collector = FindingCollector::new();
        collector.add(make_finding("RULE-001", "file1.md", Severity::High));
        collector.add(make_finding("RULE-001", "file2.md", Severity::High));
        collector.add(make_finding("RULE-002", "file3.md", Severity::Medium));

        assert_eq!(collector.by_rule("RULE-001").len(), 2);
        assert_eq!(collector.by_rule("RULE-002").len(), 1);
        assert_eq!(collector.by_rule("NONEXISTENT").len(), 0);
    }

    #[test]
    fn test_collector_add_all() {
        let mut collector = FindingCollector::new();
        let findings = vec![
            make_finding("RULE-001", "a.md", Severity::High),
            make_finding("RULE-002", "b.md", Severity::Medium),
            make_finding("RULE-003", "c.md", Severity::Low),
        ];
        collector.add_all(findings);

        assert_eq!(collector.total(), 3);
        assert_eq!(collector.files_count(), 3);
        assert_eq!(collector.rules_count(), 3);
    }

    #[test]
    fn test_collector_findings() {
        let mut collector = FindingCollector::new();
        collector.add(make_finding("RULE-001", "a.md", Severity::High));

        let findings = collector.findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "RULE-001");
    }

    #[test]
    fn test_collector_into_findings() {
        let mut collector = FindingCollector::new();
        collector.add(make_finding("RULE-001", "a.md", Severity::High));
        collector.add(make_finding("RULE-002", "b.md", Severity::Medium));

        let findings = collector.into_findings();
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn test_collector_highest_severity_empty() {
        let collector = FindingCollector::new();
        assert_eq!(collector.highest_severity(), None);
    }

    #[test]
    fn test_collector_debug() {
        let collector = FindingCollector::new();
        let debug_str = format!("{:?}", collector);
        assert!(debug_str.contains("FindingCollector"));
    }

    #[test]
    fn test_collector_default() {
        let collector = FindingCollector::default();
        assert!(collector.is_empty());
    }
}
