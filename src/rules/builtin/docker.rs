use crate::rules::types::{Category, Confidence, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![dk_001(), dk_002(), dk_003()]
}

fn dk_001() -> Rule {
    Rule {
        id: "DK-001",
        name: "Privileged container",
        description: "Detects privileged mode containers which have full host access",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Certain,
        patterns: vec![
            // --privileged flag
            Regex::new(r"--privileged").unwrap(),
            // privileged: true in compose
            Regex::new(r"privileged:\s*true").unwrap(),
            // CAP_SYS_ADMIN capability (multiline support with (?s))
            Regex::new(r"(?s)cap_add:.*SYS_ADMIN").unwrap(),
            Regex::new(r"--cap-add\s*=?\s*SYS_ADMIN").unwrap(),
            // All capabilities (multiline support)
            Regex::new(r"(?s)cap_add:.*ALL\b").unwrap(),
            Regex::new(r"--cap-add\s*=?\s*ALL").unwrap(),
            // Individual line match for YAML lists
            Regex::new(r"-\s*SYS_ADMIN\s*$").unwrap(),
            Regex::new(r"-\s*ALL\s*$").unwrap(),
        ],
        exclusions: vec![],
        message: "Privileged container detected. This grants full host access and is a major security risk.",
        recommendation: "Remove --privileged flag. Use specific capabilities instead of full privileges.",
        fix_hint: Some("Remove --privileged. Add only needed caps: --cap-add=NET_ADMIN"),
        cwe_ids: &["CWE-250"],
    }
}

fn dk_002() -> Rule {
    Rule {
        id: "DK-002",
        name: "Running as root user",
        description: "Detects containers that run as root user without explicitly setting a non-root user",
        severity: Severity::High,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Firm,
        patterns: vec![
            // USER root (multiline mode with (?m))
            Regex::new(r"(?im)^USER\s+root\s*$").unwrap(),
            // USER 0
            Regex::new(r"(?m)^USER\s+0\s*$").unwrap(),
            // user: root in compose
            Regex::new(r#"user:\s*["']?root["']?"#).unwrap(),
            Regex::new(r#"user:\s*["']?0["']?"#).unwrap(),
        ],
        exclusions: vec![
            // Comment lines
            Regex::new(r"^\s*#").unwrap(),
        ],
        message: "Container running as root user detected. This increases the attack surface if container is compromised.",
        recommendation: "Add a USER instruction to run as a non-root user. Example: USER nobody or USER 1000:1000",
        fix_hint: Some("Add to Dockerfile: RUN useradd -m appuser && USER appuser"),
        cwe_ids: &["CWE-250"],
    }
}

fn dk_003() -> Rule {
    Rule {
        id: "DK-003",
        name: "Remote script execution in RUN",
        description: "Detects curl/wget piped to shell in Dockerfile RUN instructions",
        severity: Severity::Critical,
        category: Category::SupplyChain,
        confidence: Confidence::Certain,
        patterns: vec![
            // curl | bash/sh in RUN
            Regex::new(r"RUN\s+.*curl\s+[^|]*\|\s*(bash|sh|zsh)").unwrap(),
            // wget with output to stdout piped to shell (various formats)
            Regex::new(r"RUN\s+.*wget\s+[^|]*-[a-zA-Z]*O-[^|]*\|\s*(bash|sh|zsh)").unwrap(),
            Regex::new(r"RUN\s+.*wget\s+[^|]*-O\s*-[^|]*\|\s*(bash|sh|zsh)").unwrap(),
            // wget -qO- pattern (common)
            Regex::new(r"wget\s+-[a-zA-Z]*O-\s+[^|]*\|\s*(bash|sh)").unwrap(),
            // curl ... && bash
            Regex::new(r"RUN\s+.*curl.*&&\s*(bash|sh)\s").unwrap(),
            // Multi-line RUN with pipe to shell (common pattern)
            Regex::new(r"curl\s+-[a-zA-Z]*[sS][a-zA-Z]*\s+[^|]*\|\s*(bash|sh)").unwrap(),
        ],
        exclusions: vec![
            // localhost is generally safe
            Regex::new(r"localhost|127\.0\.0\.1").unwrap(),
        ],
        message: "Remote script execution in Dockerfile RUN instruction. This is a supply chain attack vector.",
        recommendation: "Download scripts first, verify checksums, then execute. Better: use package managers.",
        fix_hint: Some(
            "RUN curl -o script.sh URL && echo 'CHECKSUM script.sh' | sha256sum -c && bash script.sh",
        ),
        cwe_ids: &["CWE-829"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dk_001_detects_privileged() {
        let rule = dk_001();
        let test_cases = vec![
            // Should detect
            ("docker run --privileged nginx", true),
            ("privileged: true", true),
            ("cap_add: [SYS_ADMIN]", true),
            ("--cap-add=SYS_ADMIN", true),
            ("cap_add: [ALL]", true),
            ("--cap-add ALL", true),
            // Should not detect
            ("docker run nginx", false),
            ("privileged: false", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_dk_002_detects_root_user() {
        let rule = dk_002();
        let test_cases = vec![
            // Should detect
            ("USER root", true),
            ("USER 0", true),
            ("user: root", true),
            ("user: \"root\"", true),
            ("user: 0", true),
            // Should not detect
            ("USER nobody", false),
            ("USER 1000", false),
            ("user: app", false),
            ("# USER root", false), // comment
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_dk_003_detects_curl_pipe_in_run() {
        let rule = dk_003();
        let test_cases = vec![
            // Should detect
            ("RUN curl -fsSL https://get.docker.com | bash", true),
            ("RUN wget -qO- https://install.example.com | sh", true),
            ("curl -sSL https://example.com/install.sh | bash", true),
            // Should not detect
            ("RUN apt-get update && apt-get install -y curl", false),
            ("RUN curl -o script.sh https://example.com/script.sh", false),
            (
                "RUN curl -fsSL http://localhost:8080/install.sh | bash",
                false,
            ), // localhost excluded
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_dk_001_compose_patterns() {
        let rule = dk_001();
        let compose_content = r#"
services:
  app:
    image: nginx
    privileged: true
"#;
        let matched = rule.patterns.iter().any(|p| p.is_match(compose_content));
        assert!(matched, "Should detect privileged: true in compose file");
    }

    #[test]
    fn test_dk_002_dockerfile_patterns() {
        let rule = dk_002();
        let dockerfile_content = r#"
FROM node:18
WORKDIR /app
USER root
RUN apt-get update
"#;
        let matched = rule.patterns.iter().any(|p| p.is_match(dockerfile_content));
        assert!(matched, "Should detect USER root in Dockerfile");
    }

    // Snapshot tests
    #[test]
    fn snapshot_dk_001() {
        let rule = dk_001();
        let content = include_str!("../../../tests/fixtures/rules/dk_001.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("dk_001", findings);
    }

    #[test]
    fn snapshot_dk_002() {
        let rule = dk_002();
        let content = include_str!("../../../tests/fixtures/rules/dk_002.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("dk_002", findings);
    }

    #[test]
    fn snapshot_dk_003() {
        let rule = dk_003();
        let content = include_str!("../../../tests/fixtures/rules/dk_003.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("dk_003", findings);
    }
}
