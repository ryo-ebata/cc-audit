use crate::rules::types::{Category, Confidence, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![
        pe_001(),
        pe_002(),
        pe_003(),
        pe_004(),
        pe_005(),
        pe_006(),
        pe_007(),
    ]
}

fn pe_001() -> Rule {
    Rule {
        id: "PE-001",
        name: "Sudo execution",
        description: "Detects sudo commands which could be used for privilege escalation",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Certain,
        patterns: vec![Regex::new(r"\bsudo\s+").expect("PE-001: invalid regex")],
        exclusions: vec![],
        message: "Privilege escalation: sudo command detected",
        recommendation: "Skills should not require sudo. Review why elevated privileges are needed",
        fix_hint: Some("Remove sudo or run the skill with appropriate user permissions"),
        cwe_ids: &["CWE-250"],
    }
}

fn pe_002() -> Rule {
    Rule {
        id: "PE-002",
        name: "Destructive root deletion",
        description: "Detects rm -rf / or similar commands that could destroy the entire filesystem",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Certain,
        patterns: vec![
            Regex::new(r"rm\s+(-[rfRF]+\s+)+/\s*$").expect("PE-002: invalid regex"),
            Regex::new(r"rm\s+(-[rfRF]+\s+)+/[^a-zA-Z]").expect("PE-002: invalid regex"),
            Regex::new(r"rm\s+(-[rfRF]+\s+)+\*").expect("PE-002: invalid regex"),
            Regex::new(r"rm\s+.*--no-preserve-root").expect("PE-002: invalid regex"),
        ],
        exclusions: vec![],
        message: "Destructive command: potential filesystem destruction detected",
        recommendation: "Never use rm -rf on root or with wildcards in skills",
        fix_hint: Some("Specify exact paths instead of wildcards: rm -rf /tmp/specific-dir"),
        cwe_ids: &["CWE-250", "CWE-73"],
    }
}

fn pe_003() -> Rule {
    Rule {
        id: "PE-003",
        name: "Insecure permission change",
        description: "Detects chmod 777 which makes files world-writable, a security risk",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Certain,
        patterns: vec![
            Regex::new(r"chmod\s+777\b").expect("PE-003: invalid regex"),
            Regex::new(r"chmod\s+[0-7]?777\b").expect("PE-003: invalid regex"),
            Regex::new(r"chmod\s+-R\s+777\b").expect("PE-003: invalid regex"),
            Regex::new(r"chmod\s+a\+rwx\b").expect("PE-003: invalid regex"),
        ],
        exclusions: vec![],
        message: "Insecure permissions: chmod 777 makes files world-writable",
        recommendation: "Use more restrictive permissions (e.g., 755 for directories, 644 for files)",
        fix_hint: Some("chmod 755 for directories, chmod 644 for files"),
        cwe_ids: &["CWE-732"],
    }
}

fn pe_004() -> Rule {
    Rule {
        id: "PE-004",
        name: "System password file access",
        description: "Detects access to /etc/passwd, /etc/shadow, or other sensitive system files",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Firm,
        patterns: vec![
            Regex::new(r"/etc/passwd\b").expect("PE-004: invalid regex"),
            Regex::new(r"/etc/shadow\b").expect("PE-004: invalid regex"),
            Regex::new(r"/etc/sudoers").expect("PE-004: invalid regex"),
            Regex::new(r"/etc/gshadow").expect("PE-004: invalid regex"),
            Regex::new(r"/etc/master\.passwd").expect("PE-004: invalid regex"),
        ],
        exclusions: vec![],
        message: "Sensitive file access: system password file access detected",
        recommendation: "Skills should never access system authentication files",
        fix_hint: Some("Remove any references to /etc/passwd, /etc/shadow, or /etc/sudoers"),
        cwe_ids: &["CWE-200", "CWE-522"],
    }
}

fn pe_005() -> Rule {
    Rule {
        id: "PE-005",
        name: "SSH directory access",
        description: "Detects access to ~/.ssh/ directory which contains sensitive authentication keys",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Firm,
        patterns: vec![
            Regex::new(r"~/\.ssh/").expect("PE-005: invalid regex"),
            Regex::new(r"\$HOME/\.ssh/").expect("PE-005: invalid regex"),
            Regex::new(r"/home/[^/]+/\.ssh/").expect("PE-005: invalid regex"),
            Regex::new(r"\.ssh/id_").expect("PE-005: invalid regex"),
            Regex::new(r"\.ssh/authorized_keys").expect("PE-005: invalid regex"),
            Regex::new(r"\.ssh/known_hosts").expect("PE-005: invalid regex"),
        ],
        exclusions: vec![],
        message: "Sensitive file access: SSH directory access detected",
        recommendation: "Skills should never access SSH keys or configuration",
        fix_hint: Some("Remove any references to ~/.ssh/ or SSH key files"),
        cwe_ids: &["CWE-200", "CWE-522"],
    }
}

fn pe_006() -> Rule {
    Rule {
        id: "PE-006",
        name: "Setuid/setgid manipulation",
        description: "Detects setuid/setgid bit manipulation which can grant elevated privileges to executables",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Certain,
        patterns: vec![
            // chmod with setuid bit
            Regex::new(r"chmod\s+[0-7]*4[0-7]{3}\b").expect("PE-006: invalid regex"),
            Regex::new(r"chmod\s+u\+s\b").expect("PE-006: invalid regex"),
            // chmod with setgid bit
            Regex::new(r"chmod\s+[0-7]*2[0-7]{3}\b").expect("PE-006: invalid regex"),
            Regex::new(r"chmod\s+g\+s\b").expect("PE-006: invalid regex"),
            // chmod with both setuid and setgid
            Regex::new(r"chmod\s+[0-7]*6[0-7]{3}\b").expect("PE-006: invalid regex"),
            // find with -perm for setuid/setgid (suid discovery)
            Regex::new(r"find\s+.*-perm\s+.*[/-]4000").expect("PE-006: invalid regex"),
            Regex::new(r"find\s+.*-perm\s+.*[/-]2000").expect("PE-006: invalid regex"),
            Regex::new(r"find\s+.*-perm\s+.*[/-]6000").expect("PE-006: invalid regex"),
            // chown to root (often combined with setuid)
            Regex::new(r"chown\s+root[:\s]").expect("PE-006: invalid regex"),
        ],
        exclusions: vec![Regex::new(r"^\s*#").expect("PE-006: invalid regex")],
        message: "Setuid/setgid manipulation detected. This can grant elevated privileges to executables.",
        recommendation: "Avoid setting setuid/setgid bits. Use capability-based permissions instead.",
        fix_hint: Some(
            "Remove setuid/setgid: chmod u-s,g-s <file>. Use capabilities if elevated privileges are needed.",
        ),
        cwe_ids: &["CWE-250", "CWE-269"],
    }
}

fn pe_007() -> Rule {
    Rule {
        id: "PE-007",
        name: "Linux capabilities manipulation",
        description: "Detects manipulation of Linux capabilities which can grant specific elevated privileges",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Firm,
        patterns: vec![
            // setcap to add capabilities
            Regex::new(r"\bsetcap\s+").expect("PE-007: invalid regex"),
            // Dangerous capabilities
            Regex::new(r"cap_setuid").expect("PE-007: invalid regex"),
            Regex::new(r"cap_setgid").expect("PE-007: invalid regex"),
            Regex::new(r"cap_sys_admin").expect("PE-007: invalid regex"),
            Regex::new(r"cap_sys_ptrace").expect("PE-007: invalid regex"),
            Regex::new(r"cap_net_admin").expect("PE-007: invalid regex"),
            Regex::new(r"cap_net_raw").expect("PE-007: invalid regex"),
            Regex::new(r"cap_dac_override").expect("PE-007: invalid regex"),
            Regex::new(r"cap_dac_read_search").expect("PE-007: invalid regex"),
            Regex::new(r"cap_chown").expect("PE-007: invalid regex"),
            // getcap to discover capabilities (reconnaissance)
            Regex::new(r"\bgetcap\s+-r\s+/").expect("PE-007: invalid regex"),
            // Python capability libraries
            Regex::new(r"prctl\.set_keepcaps").expect("PE-007: invalid regex"),
            Regex::new(r"capng\.|libcap").expect("PE-007: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"^\s*#").expect("PE-007: invalid regex"),
            Regex::new(r"getcap\s+[^/]").expect("PE-007: invalid regex"), // getcap on specific file is less suspicious
        ],
        message: "Linux capabilities manipulation detected. This can grant specific elevated privileges.",
        recommendation: "Avoid manipulating capabilities. Skills should not require elevated privileges.",
        fix_hint: Some("Remove capability operations. Run with minimal privileges required."),
        cwe_ids: &["CWE-250", "CWE-269"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_001_detects_sudo() {
        let rule = pe_001();
        let test_cases = vec![
            ("sudo rm -rf /tmp", true),
            ("sudo apt install something", true),
            ("pseudocode", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_pe_002_detects_rm_rf_root() {
        let rule = pe_002();
        let test_cases = vec![
            ("rm -rf /", true),
            ("rm -rf /*", true),
            ("rm -rf --no-preserve-root /", true),
            ("rm -rf /tmp/test", false),
            ("rm file.txt", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_pe_003_detects_chmod_777() {
        let rule = pe_003();
        let test_cases = vec![
            ("chmod 777 /tmp/file", true),
            ("chmod -R 777 /var/www", true),
            ("chmod a+rwx script.sh", true),
            ("chmod 755 /tmp/file", false),
            ("chmod 644 config.txt", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_pe_004_detects_password_file_access() {
        let rule = pe_004();
        let test_cases = vec![
            ("cat /etc/passwd", true),
            ("cat /etc/shadow", true),
            ("cat /etc/sudoers", true),
            ("grep root /etc/passwd", true),
            ("cat /etc/master.passwd", true), // BSD
            ("echo 'password123'", false),
            ("cat /etc/hosts", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_pe_005_detects_ssh_access() {
        let rule = pe_005();
        let test_cases = vec![
            ("cat ~/.ssh/id_rsa", true),
            ("cat $HOME/.ssh/id_ed25519", true),
            ("cat /home/user/.ssh/authorized_keys", true),
            ("ssh-keygen -t rsa", false),
            ("ssh user@host", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }

    // Snapshot tests
    #[test]
    fn snapshot_pe_001() {
        let rule = pe_001();
        let content = include_str!("../../../tests/fixtures/rules/pe_001.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("pe_001", findings);
    }

    #[test]
    fn snapshot_pe_002() {
        let rule = pe_002();
        let content = include_str!("../../../tests/fixtures/rules/pe_002.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("pe_002", findings);
    }

    #[test]
    fn snapshot_pe_003() {
        let rule = pe_003();
        let content = include_str!("../../../tests/fixtures/rules/pe_003.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("pe_003", findings);
    }

    #[test]
    fn snapshot_pe_004() {
        let rule = pe_004();
        let content = include_str!("../../../tests/fixtures/rules/pe_004.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("pe_004", findings);
    }

    #[test]
    fn snapshot_pe_005() {
        let rule = pe_005();
        let content = include_str!("../../../tests/fixtures/rules/pe_005.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("pe_005", findings);
    }
}
