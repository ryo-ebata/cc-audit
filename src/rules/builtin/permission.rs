use crate::rules::types::{Category, Confidence, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![
        op_001(),
        op_002(),
        op_003(),
        op_004(),
        op_005(),
        op_006(),
        op_007(),
        op_008(),
        op_009(),
    ]
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
        exclusions: vec![
            // Schema/type definitions (describing structure, not granting permissions)
            Regex::new(r"(?i)schema|interface|type\s+\w+|typedef").expect("OP-003: invalid regex"),
            // JSON Schema format
            Regex::new(r#""type"\s*:\s*"(string|boolean|object|array)""#)
                .expect("OP-003: invalid regex"),
            // Comments
            Regex::new(r"^\s*(#|//|/\*|\*)").expect("OP-003: invalid regex"),
            // Example/documentation context
            Regex::new(r"(?i)example|documentation|readme|docs/").expect("OP-003: invalid regex"),
            // Test context
            Regex::new(r"(?i)test|spec|mock").expect("OP-003: invalid regex"),
        ],
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
            // Restricted Bash is OK
            Regex::new(r"Bash\([^)]+\)").expect("OP-004: invalid regex"),
            // Schema/type definitions
            Regex::new(r"(?i)schema|interface|type\s+\w+|typedef").expect("OP-004: invalid regex"),
            // Comments
            Regex::new(r"^\s*(#|//|/\*|\*)").expect("OP-004: invalid regex"),
            // Documentation context
            Regex::new(r"(?i)example|documentation|readme|docs/").expect("OP-004: invalid regex"),
            // Test context
            Regex::new(r"(?i)test|spec|mock").expect("OP-004: invalid regex"),
            // Description of permission (not actual grant)
            Regex::new(r"(?i)requires?|needs?|wants?\s+.*(bash|shell)")
                .expect("OP-004: invalid regex"),
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

fn op_007() -> Rule {
    Rule {
        id: "OP-007",
        name: "Subagent excessive permission delegation",
        description: "Detects subagent definitions with overly permissive tool access",
        severity: Severity::High,
        category: Category::Overpermission,
        confidence: Confidence::Firm,
        patterns: vec![
            // Subagent with all tools
            Regex::new(r#"subagent_type.*allowed-tools:\s*\*"#).expect("OP-007: invalid regex"),
            Regex::new(r#""subagent"[^}]*"allowed-tools"\s*:\s*"\*""#)
                .expect("OP-007: invalid regex"),
            // Agent definition with wildcard tools
            Regex::new(r#"\.claude/agents/.*allowed-tools:\s*\*"#).expect("OP-007: invalid regex"),
            // Task tool with full access
            Regex::new(r#"Task\s*\([^)]*tools\s*=\s*\*"#).expect("OP-007: invalid regex"),
            // Subagent with Bash access
            Regex::new(r#"subagent.*allowed-tools:.*Bash[^(]"#).expect("OP-007: invalid regex"),
            // Agent spawning with inherited permissions
            Regex::new(r#"spawn_agent.*inherit_permissions\s*[:=]\s*(true|True)"#)
                .expect("OP-007: invalid regex"),
            // Subagent with unrestricted Write
            Regex::new(r#"subagent.*allowed-tools:.*Write[^(]"#).expect("OP-007: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"^\s*#").expect("OP-007: invalid regex"),
            Regex::new(r"Bash\([^)]+\)").expect("OP-007: invalid regex"), // Restricted Bash is OK
            Regex::new(r"Write\([^)]+\)").expect("OP-007: invalid regex"), // Restricted Write is OK
        ],
        message: "Excessive permission delegation to subagent detected. Subagents should have minimal required permissions.",
        recommendation: "Restrict subagent permissions to only required tools with specific patterns.",
        fix_hint: Some(
            "Use specific tool permissions: allowed-tools: Read, Grep instead of wildcard",
        ),
        cwe_ids: &["CWE-250", "CWE-269"],
    }
}

fn op_008() -> Rule {
    Rule {
        id: "OP-008",
        name: "MCP tool unrestricted access",
        description: "Detects MCP server configurations with unrestricted tool access",
        severity: Severity::Critical,
        category: Category::Overpermission,
        confidence: Confidence::Certain,
        patterns: vec![
            // MCP server with all tools auto-approved
            Regex::new(r#""mcpServers"[^}]*"autoApprove"\s*:\s*\[\s*"\*"\s*\]"#)
                .expect("OP-008: invalid regex"),
            Regex::new(r#""mcpServers"[^}]*"autoApproveTools"\s*:\s*true"#)
                .expect("OP-008: invalid regex"),
            // Trust all tools from server
            Regex::new(r#""trustTools"\s*:\s*(true|\[\s*"\*"\s*\])"#)
                .expect("OP-008: invalid regex"),
            // Allow all MCP capabilities
            Regex::new(r#""capabilities"\s*:\s*\[\s*"\*"\s*\]"#).expect("OP-008: invalid regex"),
            // Unrestricted MCP tool patterns
            Regex::new(r#"mcp.*tool.*permission.*\*"#).expect("OP-008: invalid regex"),
            // MCP server running with elevated privileges
            Regex::new(r#""command"\s*:\s*"sudo"#).expect("OP-008: invalid regex"),
            // No sandbox for MCP
            Regex::new(r#""sandbox"\s*:\s*false"#).expect("OP-008: invalid regex"),
            Regex::new(r#""disableSandbox"\s*:\s*true"#).expect("OP-008: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"^\s*#").expect("OP-008: invalid regex"),
            Regex::new(r"^\s*//").expect("OP-008: invalid regex"),
        ],
        message: "MCP server with unrestricted tool access detected. This allows the server to execute any tool without approval.",
        recommendation: "Explicitly list allowed tools and require approval for sensitive operations.",
        fix_hint: Some(
            "Remove autoApprove: ['*'] and specify individual tools that can be auto-approved",
        ),
        cwe_ids: &["CWE-250", "CWE-269"],
    }
}

fn op_009() -> Rule {
    Rule {
        id: "OP-009",
        name: "Bash wildcard permission",
        description: "Detects Bash permissions with overly broad wildcard patterns",
        severity: Severity::High,
        category: Category::Overpermission,
        confidence: Confidence::Firm,
        patterns: vec![
            // Bash with single wildcard (too broad)
            Regex::new(r"Bash\s*\(\s*\*\s*\)").expect("OP-009: invalid regex"),
            Regex::new(r#"Bash\s*\(\s*["']\*["']\s*\)"#).expect("OP-009: invalid regex"),
            // Bash with trailing wildcard on dangerous commands
            Regex::new(r"Bash\s*\(\s*(curl|wget|nc|netcat|ssh|scp)\s*:\s*\*\s*\)")
                .expect("OP-009: invalid regex"),
            // Bash with leading wildcard
            Regex::new(r"Bash\s*\(\s*\*\s*:").expect("OP-009: invalid regex"),
            // Permission string with overly broad Bash
            Regex::new(r#"permissions.*Bash\s*\(\s*[^)]{0,5}\*[^)]{0,5}\s*\)"#)
                .expect("OP-009: invalid regex"),
            // Shell commands with wildcards
            Regex::new(r"Bash\s*\(\s*(sh|bash|zsh)\s*:\s*\*\s*\)").expect("OP-009: invalid regex"),
            // Package managers with wildcards (can install anything)
            Regex::new(r"Bash\s*\(\s*(npm|pip|cargo|apt|brew|yum)\s+install\s*:\s*\*\s*\)")
                .expect("OP-009: invalid regex"),
        ],
        exclusions: vec![
            // Specific command with wildcard arguments is safer
            Regex::new(r"Bash\s*\(\s*[a-z]+\s+[a-z]+\s*:\s*\*\s*\)")
                .expect("OP-009: invalid regex"),
        ],
        message: "Bash wildcard permission detected. This allows execution of a broad range of commands.",
        recommendation: "Use specific command patterns instead of wildcards.",
        fix_hint: Some("Replace Bash(*) with specific patterns: Bash(npm test:*), Bash(git:*)"),
        cwe_ids: &["CWE-78", "CWE-250"],
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
