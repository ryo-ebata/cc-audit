#[cfg(test)]
pub mod fixtures {
    use crate::rules::{Category, Finding, Location, ScanResult, Severity, Summary};

    pub fn create_test_result(findings: Vec<Finding>) -> ScanResult {
        let summary = Summary::from_findings(&findings);
        ScanResult {
            version: "0.2.0".to_string(),
            scanned_at: "2026-01-25T12:00:00Z".to_string(),
            target: "./test-skill/".to_string(),
            summary,
            findings,
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
            name: name.to_string(),
            location: Location {
                file: file.to_string(),
                line,
                column: None,
            },
            code: "test".to_string(),
            message: "test message".to_string(),
            recommendation: "test recommendation".to_string(),
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
}
