use crate::rules::types::{Category, Confidence, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![
        dk_001(),
        dk_002(),
        dk_003(),
        dk_004(),
        dk_005(),
        dk_006(),
        dk_007(),
        dk_008(),
    ]
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
            Regex::new(r"--privileged").expect("DK-001: invalid regex"),
            // privileged: true in compose
            Regex::new(r"privileged:\s*true").expect("DK-001: invalid regex"),
            // CAP_SYS_ADMIN capability (multiline support with (?s))
            Regex::new(r"(?s)cap_add:.*SYS_ADMIN").expect("DK-001: invalid regex"),
            Regex::new(r"--cap-add\s*=?\s*SYS_ADMIN").expect("DK-001: invalid regex"),
            // All capabilities (multiline support)
            Regex::new(r"(?s)cap_add:.*ALL\b").expect("DK-001: invalid regex"),
            Regex::new(r"--cap-add\s*=?\s*ALL").expect("DK-001: invalid regex"),
            // Individual line match for YAML lists
            Regex::new(r"-\s*SYS_ADMIN\s*$").expect("DK-001: invalid regex"),
            Regex::new(r"-\s*ALL\s*$").expect("DK-001: invalid regex"),
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
            Regex::new(r"(?im)^USER\s+root\s*$").expect("DK-002: invalid regex"),
            // USER 0
            Regex::new(r"(?m)^USER\s+0\s*$").expect("DK-002: invalid regex"),
            // user: root in compose
            Regex::new(r#"user:\s*["']?root["']?"#).expect("DK-002: invalid regex"),
            Regex::new(r#"user:\s*["']?0["']?"#).expect("DK-002: invalid regex"),
        ],
        exclusions: vec![
            // Comment lines
            Regex::new(r"^\s*#").expect("DK-002: invalid regex"),
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
            Regex::new(r"RUN\s+.*curl\s+[^|]*\|\s*(bash|sh|zsh)").expect("DK-003: invalid regex"),
            // wget with output to stdout piped to shell (various formats)
            Regex::new(r"RUN\s+.*wget\s+[^|]*-[a-zA-Z]*O-[^|]*\|\s*(bash|sh|zsh)")
                .expect("DK-003: invalid regex"),
            Regex::new(r"RUN\s+.*wget\s+[^|]*-O\s*-[^|]*\|\s*(bash|sh|zsh)")
                .expect("DK-003: invalid regex"),
            // wget -qO- pattern (common)
            Regex::new(r"wget\s+-[a-zA-Z]*O-\s+[^|]*\|\s*(bash|sh)")
                .expect("DK-003: invalid regex"),
            // curl ... && bash
            Regex::new(r"RUN\s+.*curl.*&&\s*(bash|sh)\s").expect("DK-003: invalid regex"),
            // Multi-line RUN with pipe to shell (common pattern)
            Regex::new(r"curl\s+-[a-zA-Z]*[sS][a-zA-Z]*\s+[^|]*\|\s*(bash|sh)")
                .expect("DK-003: invalid regex"),
        ],
        exclusions: vec![
            // localhost is generally safe
            Regex::new(r"localhost|127\.0\.0\.1").expect("DK-003: invalid regex"),
        ],
        message: "Remote script execution in Dockerfile RUN instruction. This is a supply chain attack vector.",
        recommendation: "Download scripts first, verify checksums, then execute. Better: use package managers.",
        fix_hint: Some(
            "RUN curl -o script.sh URL && echo 'CHECKSUM script.sh' | sha256sum -c && bash script.sh",
        ),
        cwe_ids: &["CWE-829"],
    }
}

fn dk_004() -> Rule {
    Rule {
        id: "DK-004",
        name: "ADD from remote URL",
        description: "Detects ADD instructions fetching from remote URLs (use COPY instead)",
        severity: Severity::High,
        category: Category::SupplyChain,
        confidence: Confidence::Certain,
        patterns: vec![
            Regex::new(r"(?m)^ADD\s+https?://").expect("DK-004: invalid regex"),
            Regex::new(r"(?m)^ADD\s+ftp://").expect("DK-004: invalid regex"),
        ],
        exclusions: vec![],
        message: "ADD from remote URL detected. This bypasses layer caching and may fetch untrusted content.",
        recommendation: "Use RUN curl/wget with checksum verification, or COPY from local files.",
        fix_hint: Some(
            "Replace ADD URL with: RUN curl -o file URL && echo 'checksum file' | sha256sum -c",
        ),
        cwe_ids: &["CWE-829", "CWE-494"],
    }
}

fn dk_005() -> Rule {
    Rule {
        id: "DK-005",
        name: "Using latest tag",
        description: "Detects use of 'latest' tag which can lead to unpredictable builds",
        severity: Severity::Medium,
        category: Category::SupplyChain,
        confidence: Confidence::Certain,
        patterns: vec![
            Regex::new(r"(?m)^FROM\s+[^:]+:latest\s*$").expect("DK-005: invalid regex"),
            Regex::new(r"(?m)^FROM\s+[^\s:]+\s*$").expect("DK-005: invalid regex"), // No tag = latest
            Regex::new(r#"image:\s*[^:]+:latest\s*$"#).expect("DK-005: invalid regex"),
        ],
        exclusions: vec![Regex::new(r"scratch").expect("DK-005: invalid regex")],
        message: "Using 'latest' tag or no tag (defaults to latest). Builds may not be reproducible.",
        recommendation: "Pin to a specific version tag or SHA digest for reproducible builds.",
        fix_hint: Some("Use specific version: FROM node:20.10.0 or FROM node@sha256:..."),
        cwe_ids: &["CWE-1357"],
    }
}

fn dk_006() -> Rule {
    Rule {
        id: "DK-006",
        name: "Sensitive port exposed",
        description: "Detects exposure of sensitive ports like SSH, database, or admin ports",
        severity: Severity::Medium,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Tentative,
        patterns: vec![
            // SSH port
            Regex::new(r"EXPOSE\s+22\b").expect("DK-006: invalid regex"),
            // MySQL
            Regex::new(r"EXPOSE\s+3306\b").expect("DK-006: invalid regex"),
            // PostgreSQL
            Regex::new(r"EXPOSE\s+5432\b").expect("DK-006: invalid regex"),
            // MongoDB
            Regex::new(r"EXPOSE\s+27017\b").expect("DK-006: invalid regex"),
            // Redis
            Regex::new(r"EXPOSE\s+6379\b").expect("DK-006: invalid regex"),
        ],
        exclusions: vec![],
        message: "Sensitive port exposed. Database and SSH ports should not be publicly exposed.",
        recommendation: "Use internal networks for database connections. Avoid exposing SSH in containers.",
        fix_hint: Some(
            "Remove EXPOSE for sensitive ports or use Docker networks for internal communication",
        ),
        cwe_ids: &["CWE-200"],
    }
}

fn dk_007() -> Rule {
    Rule {
        id: "DK-007",
        name: "HEALTHCHECK disabled",
        description: "Detects HEALTHCHECK NONE which disables container health monitoring",
        severity: Severity::Low,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Certain,
        patterns: vec![Regex::new(r"(?im)^HEALTHCHECK\s+NONE\s*$").expect("DK-007: invalid regex")],
        exclusions: vec![],
        message: "HEALTHCHECK is disabled. Container health cannot be monitored.",
        recommendation: "Add a proper HEALTHCHECK instruction to monitor container health.",
        fix_hint: Some("Add: HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1"),
        cwe_ids: &["CWE-778"],
    }
}

fn dk_008() -> Rule {
    Rule {
        id: "DK-008",
        name: "Host volume mount",
        description: "Detects mounting of sensitive host paths into containers",
        severity: Severity::High,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Firm,
        patterns: vec![
            // Docker socket mount
            Regex::new(r"/var/run/docker\.sock").expect("DK-008: invalid regex"),
            // Root filesystem mount
            Regex::new(r#"-v\s+/:/[^/]"#).expect("DK-008: invalid regex"),
            Regex::new(r#"volumes:.*\n\s*-\s*/:/[^/]"#).expect("DK-008: invalid regex"),
            // /etc mount
            Regex::new(r#"-v\s+/etc:"#).expect("DK-008: invalid regex"),
            // /proc mount
            Regex::new(r#"-v\s+/proc:"#).expect("DK-008: invalid regex"),
        ],
        exclusions: vec![],
        message: "Sensitive host path mounted. This may allow container escape or host compromise.",
        recommendation: "Avoid mounting sensitive host paths. Use named volumes or bind mounts to specific directories.",
        fix_hint: Some("Use named volumes: -v mydata:/data instead of host paths"),
        cwe_ids: &["CWE-250", "CWE-732"],
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
