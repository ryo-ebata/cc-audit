use crate::rules::types::{Category, Confidence, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![op_001()]
}

fn op_001() -> Rule {
    Rule {
        id: "OP-001",
        name: "Wildcard tool permission",
        description: "Detects allowed-tools: * which grants access to all tools",
        severity: Severity::High,
        category: Category::Overpermission,
        confidence: Confidence::Certain,
        patterns: vec![
            Regex::new(r"allowed-tools:\s*\*").unwrap(),
            Regex::new(r#"allowed-tools:\s*["']\*["']"#).unwrap(),
            Regex::new(r#""allowed-tools"\s*:\s*"\*""#).unwrap(),
        ],
        exclusions: vec![],
        message: "Overpermission: wildcard tool access grants unrestricted capabilities",
        recommendation: "Specify only required tools (e.g., \"Read, Write, Bash\")",
        fix_hint: Some(
            "Replace 'allowed-tools: *' with specific tools: 'allowed-tools: Read, Write'",
        ),
        cwe_ids: &["CWE-250"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_op_001_detects_wildcard_tools() {
        let rule = op_001();
        let test_cases = vec![
            ("allowed-tools: *", true),
            ("allowed-tools: \"*\"", true),
            ("allowed-tools: '*'", true),
            (r#""allowed-tools": "*""#, true),
            ("allowed-tools: Read, Write, Bash", false),
            ("allowed-tools: Bash", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }

    // Snapshot tests
    #[test]
    fn snapshot_op_001() {
        let rule = op_001();
        let content = include_str!("../../../tests/fixtures/rules/op_001.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("op_001", findings);
    }
}
