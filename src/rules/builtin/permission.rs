use crate::rules::types::{Category, Confidence, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![op_001(), op_002(), op_003(), op_004(), op_005(), op_006()]
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
            Regex::new(r"allowed-tools:\s*\*").expect("OP-001: invalid regex"),
            Regex::new(r#"allowed-tools:\s*["']\*["']"#).expect("OP-001: invalid regex"),
            Regex::new(r#""allowed-tools"\s*:\s*"\*""#).expect("OP-001: invalid regex"),
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

fn op_002() -> Rule {
    Rule {
        id: "OP-002",
        name: "Unrestricted file system access",
        description: "Detects patterns allowing access to entire file system or sensitive paths",
        severity: Severity::Critical,
        category: Category::Overpermission,
        confidence: Confidence::Firm,
        patterns: vec![
            // Root directory access
            Regex::new(r#"path[s]?\s*[=:]\s*["']/["']"#).expect("OP-002: invalid regex"),
            Regex::new(r#"allowed-paths:\s*/\s*$"#).expect("OP-002: invalid regex"),
            // Home directory access without restriction
            Regex::new(r#"path[s]?\s*[=:]\s*["']~/["']"#).expect("OP-002: invalid regex"),
            // Sensitive system paths
            Regex::new(r#"path[s]?\s*[=:]\s*["']/etc["']"#).expect("OP-002: invalid regex"),
            Regex::new(r#"path[s]?\s*[=:]\s*["']/var["']"#).expect("OP-002: invalid regex"),
        ],
        exclusions: vec![],
        message: "Unrestricted file system access detected. May allow reading/writing sensitive files.",
        recommendation: "Restrict file access to specific directories needed for the task.",
        fix_hint: Some("Use specific paths: allowed-paths: ./src, ./config"),
        cwe_ids: &["CWE-732", "CWE-250"],
    }
}

fn op_003() -> Rule {
    Rule {
        id: "OP-003",
        name: "Network permission without restriction",
        description: "Detects unrestricted network permissions that may allow data exfiltration",
        severity: Severity::High,
        category: Category::Overpermission,
        confidence: Confidence::Firm,
        patterns: vec![
            // Unrestricted network access
            Regex::new(r#"network[_-]?access\s*[=:]\s*["']?\*["']?"#)
                .expect("OP-003: invalid regex"),
            Regex::new(r#"allow[_-]?network\s*[=:]\s*(true|yes|\*)"#)
                .expect("OP-003: invalid regex"),
            // Bash with curl/wget without domain restriction
            Regex::new(r#"Bash\(curl:\*\)|Bash\(wget:\*\)"#).expect("OP-003: invalid regex"),
        ],
        exclusions: vec![],
        message: "Unrestricted network permission detected. May allow data exfiltration.",
        recommendation: "Restrict network access to specific domains or disable if not needed.",
        fix_hint: Some("Use domain restrictions: Bash(curl:api.github.com)"),
        cwe_ids: &["CWE-250", "CWE-200"],
    }
}

fn op_004() -> Rule {
    Rule {
        id: "OP-004",
        name: "Shell execution without command restriction",
        description: "Detects unrestricted shell execution permissions",
        severity: Severity::Critical,
        category: Category::Overpermission,
        confidence: Confidence::Firm,
        patterns: vec![
            Regex::new(r#"Bash\s*[=:]\s*\*"#).expect("OP-004: invalid regex"),
            Regex::new(r#"allowed-tools:.*Bash\s*[^(]"#).expect("OP-004: invalid regex"),
            Regex::new(r#"shell[_-]?access\s*[=:]\s*(true|yes|\*)"#)
                .expect("OP-004: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"Bash\([^)]+\)").expect("OP-004: invalid regex"), // Restricted Bash is OK
        ],
        message: "Unrestricted shell execution detected. Allows running arbitrary commands.",
        recommendation: "Restrict shell commands to specific allowed patterns.",
        fix_hint: Some("Use pattern restrictions: Bash(npm:*), Bash(git:*)"),
        cwe_ids: &["CWE-78", "CWE-250"],
    }
}

fn op_005() -> Rule {
    Rule {
        id: "OP-005",
        name: "Sudo/admin permission",
        description: "Detects requests for elevated privileges or sudo access",
        severity: Severity::Critical,
        category: Category::Overpermission,
        confidence: Confidence::Certain,
        patterns: vec![
            Regex::new(r"\bsudo\s").expect("OP-005: invalid regex"),
            Regex::new(r"runas\s+/user:administrator").expect("OP-005: invalid regex"),
            Regex::new(r#"privilege[sd]?\s*[=:]\s*["']?(admin|root|elevated)"#)
                .expect("OP-005: invalid regex"),
            Regex::new(r"chmod\s+[0-7]*7[0-7]*\s").expect("OP-005: invalid regex"), // world-writable
        ],
        exclusions: vec![Regex::new(r"test|mock|example").expect("OP-005: invalid regex")],
        message: "Elevated privilege request detected. May allow system-wide changes.",
        recommendation: "Avoid using sudo or elevated privileges in automated tools.",
        fix_hint: Some("Remove sudo/admin privileges and run with minimal permissions"),
        cwe_ids: &["CWE-250", "CWE-269"],
    }
}

fn op_006() -> Rule {
    Rule {
        id: "OP-006",
        name: "Environment variable access",
        description: "Detects access to all environment variables which may leak secrets",
        severity: Severity::Medium,
        category: Category::Overpermission,
        confidence: Confidence::Tentative,
        patterns: vec![
            // Full env object access (not specific property)
            Regex::new(r"JSON\.stringify\s*\(\s*process\.env\s*\)").expect("OP-006: invalid regex"),
            Regex::new(r"console\.log\s*\(\s*process\.env\s*\)").expect("OP-006: invalid regex"),
            Regex::new(r"Object\.keys\s*\(\s*process\.env\s*\)").expect("OP-006: invalid regex"),
            // Commands to dump all env vars
            Regex::new(r"\bprintenv\s*$").expect("OP-006: invalid regex"),
            Regex::new(r"\bexport\s+-p\s*$").expect("OP-006: invalid regex"),
            Regex::new(r"\benv\s*\|\s*").expect("OP-006: invalid regex"),
            Regex::new(r"\bset\s*\|\s*grep").expect("OP-006: invalid regex"),
        ],
        exclusions: vec![],
        message: "Full environment variable access detected. May expose secrets.",
        recommendation: "Access only specific required environment variables.",
        fix_hint: Some("Use specific env vars: process.env.API_KEY instead of process.env"),
        cwe_ids: &["CWE-200", "CWE-532"],
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
