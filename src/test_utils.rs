#[cfg(test)]
pub mod fixtures {
    use crate::rules::{Category, Confidence, Finding, Location, ScanResult, Severity, Summary};
    use crate::scoring::RiskScore;

    pub fn create_test_result(findings: Vec<Finding>) -> ScanResult {
        let summary = Summary::from_findings(&findings);
        let risk_score = if findings.is_empty() {
            None
        } else {
            Some(RiskScore::from_findings(&findings))
        };
        ScanResult {
            version: "0.2.0".to_string(),
            scanned_at: "2026-01-25T12:00:00Z".to_string(),
            target: "./test-skill/".to_string(),
            summary,
            findings,
            risk_score,
        }
    }

    pub fn create_finding(
        id: &str,
        severity: Severity,
        category: Category,
        name: &str,
        file: &str,
        line: usize,
    ) -> Finding {
        Finding {
            id: id.to_string(),
            severity,
            category,
            confidence: Confidence::Firm,
            name: name.to_string(),
            location: Location {
                file: file.to_string(),
                line,
                column: None,
            },
            code: "test".to_string(),
            message: "test message".to_string(),
            recommendation: "test recommendation".to_string(),
            fix_hint: None,
            cwe_ids: vec![],
            rule_severity: None,
            client: None,
        }
    }

    pub fn critical_exfil_finding() -> Finding {
        create_finding(
            "EX-001",
            Severity::Critical,
            Category::Exfiltration,
            "Network request with environment variable",
            "scripts/setup.sh",
            42,
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_create_test_result_empty() {
            let result = create_test_result(vec![]);
            assert!(result.findings.is_empty());
            assert!(result.summary.passed);
            assert_eq!(result.version, "0.2.0");
        }

        #[test]
        fn test_create_test_result_with_findings() {
            let finding = critical_exfil_finding();
            let result = create_test_result(vec![finding]);
            assert_eq!(result.findings.len(), 1);
            assert!(!result.summary.passed);
            assert_eq!(result.summary.critical, 1);
        }

        #[test]
        fn test_create_finding() {
            let finding = create_finding(
                "TEST-001",
                Severity::High,
                Category::PrivilegeEscalation,
                "Test Name",
                "test.txt",
                10,
            );
            assert_eq!(finding.id, "TEST-001");
            assert_eq!(finding.severity, Severity::High);
            assert_eq!(finding.category, Category::PrivilegeEscalation);
            assert_eq!(finding.name, "Test Name");
            assert_eq!(finding.location.file, "test.txt");
            assert_eq!(finding.location.line, 10);
            assert!(finding.location.column.is_none());
        }

        #[test]
        fn test_critical_exfil_finding() {
            let finding = critical_exfil_finding();
            assert_eq!(finding.id, "EX-001");
            assert_eq!(finding.severity, Severity::Critical);
            assert_eq!(finding.category, Category::Exfiltration);
            assert_eq!(finding.location.file, "scripts/setup.sh");
            assert_eq!(finding.location.line, 42);
        }
    }
}
