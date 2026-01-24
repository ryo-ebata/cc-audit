use crate::reporter::Reporter;
use crate::rules::ScanResult;

pub struct JsonReporter;

impl JsonReporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for JsonReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for JsonReporter {
    fn report(&self, result: &ScanResult) -> String {
        serde_json::to_string_pretty(result)
            .unwrap_or_else(|e| format!(r#"{{"error": "Failed to serialize result: {}"}}"#, e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Category, Severity};
    use crate::test_utils::fixtures::{create_finding, create_test_result};

    #[test]
    fn test_json_output_structure() {
        let reporter = JsonReporter::new();
        let result = create_test_result(vec![]);
        let output = reporter.report(&result);

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["version"], "0.2.0");
        assert_eq!(parsed["target"], "./test-skill/");
        assert!(parsed["summary"]["passed"].as_bool().unwrap());
    }

    #[test]
    fn test_json_output_with_findings() {
        let reporter = JsonReporter::new();
        let mut finding = create_finding(
            "EX-001",
            Severity::Critical,
            Category::Exfiltration,
            "Test finding",
            "test.sh",
            10,
        );
        finding.code = "curl $SECRET".to_string();
        let result = create_test_result(vec![finding]);
        let output = reporter.report(&result);

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["findings"][0]["id"], "EX-001");
        assert_eq!(parsed["findings"][0]["severity"], "critical");
        assert_eq!(parsed["summary"]["critical"], 1);
        assert!(!parsed["summary"]["passed"].as_bool().unwrap());
    }

    #[test]
    #[allow(clippy::default_constructed_unit_structs)]
    fn test_json_default_trait() {
        let reporter = JsonReporter::default();
        let result = create_test_result(vec![]);
        let output = reporter.report(&result);
        assert!(output.contains("\"passed\": true"));
    }
}
