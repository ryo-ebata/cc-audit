//! Summary builder for scan results.

use crate::rules::{Finding, Severity, Summary};
use std::collections::HashMap;

/// Builder for creating scan summaries.
#[derive(Debug, Default)]
pub struct SummaryBuilder {
    findings: Vec<Finding>,
    files_scanned: usize,
    scan_duration_ms: u64,
}

impl SummaryBuilder {
    /// Create a new summary builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add findings to the summary.
    pub fn with_findings(mut self, findings: Vec<Finding>) -> Self {
        self.findings = findings;
        self
    }

    /// Set the number of files scanned.
    pub fn with_files_scanned(mut self, count: usize) -> Self {
        self.files_scanned = count;
        self
    }

    /// Set the scan duration in milliseconds.
    pub fn with_duration_ms(mut self, duration: u64) -> Self {
        self.scan_duration_ms = duration;
        self
    }

    /// Build the summary.
    pub fn build(self) -> Summary {
        let mut by_severity: HashMap<Severity, usize> = HashMap::new();

        for finding in &self.findings {
            *by_severity.entry(finding.severity).or_default() += 1;
        }

        let critical = by_severity.get(&Severity::Critical).copied().unwrap_or(0);
        let high = by_severity.get(&Severity::High).copied().unwrap_or(0);
        let medium = by_severity.get(&Severity::Medium).copied().unwrap_or(0);
        let low = by_severity.get(&Severity::Low).copied().unwrap_or(0);

        Summary {
            critical,
            high,
            medium,
            low,
            passed: critical == 0 && high == 0,
            errors: 0,
            warnings: 0,
        }
    }

    /// Get the number of files scanned.
    pub fn files_scanned(&self) -> usize {
        self.files_scanned
    }

    /// Get the total number of findings.
    pub fn total_findings(&self) -> usize {
        self.findings.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Category, Confidence, Location};

    fn make_finding(severity: Severity) -> Finding {
        Finding {
            id: "TEST-001".to_string(),
            severity,
            category: Category::PromptInjection,
            confidence: Confidence::Firm,
            name: "Test".to_string(),
            location: Location {
                file: "test.md".to_string(),
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
    fn test_summary_builder() {
        let findings = vec![
            make_finding(Severity::Critical),
            make_finding(Severity::High),
            make_finding(Severity::High),
            make_finding(Severity::Medium),
        ];

        let builder = SummaryBuilder::new()
            .with_findings(findings)
            .with_files_scanned(10);

        assert_eq!(builder.total_findings(), 4);
        assert_eq!(builder.files_scanned(), 10);

        let summary = builder.build();
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 2);
        assert_eq!(summary.medium, 1);
        assert_eq!(summary.low, 0);
        assert!(!summary.passed); // Has critical finding
    }

    #[test]
    fn test_empty_summary() {
        let builder = SummaryBuilder::new().with_files_scanned(5);

        assert_eq!(builder.total_findings(), 0);
        assert_eq!(builder.files_scanned(), 5);

        let summary = builder.build();
        assert_eq!(summary.critical, 0);
        assert!(summary.passed); // No findings
    }
}
