use crate::rules::types::{Category, Confidence, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![
        sl_001(),
        sl_002(),
        sl_003(),
        sl_004(),
        sl_005(),
        sl_006(),
        sl_007(),
        sl_008(),
        sl_009(),
        sl_010(),
    ]
}

fn sl_001() -> Rule {
    Rule {
        id: "SL-001",
        name: "AWS Access Key exposure",
        description: "Detects AWS Access Key IDs that may have been accidentally committed",
        severity: Severity::Critical,
        category: Category::SecretLeak,
        confidence: Confidence::Certain,
        patterns: vec![
            // AWS Access Key ID format: AKIA followed by 16 alphanumeric characters
            Regex::new(r"AKIA[0-9A-Z]{16}").expect("SL-001: invalid regex"),
            // AWS Secret Access Key assignment
            Regex::new(r#"aws_secret_access_key\s*[=:]\s*["'][A-Za-z0-9/+=]{40}["']"#)
                .expect("SL-001: invalid regex"),
            // AWS Access Key ID assignment
            Regex::new(r#"aws_access_key_id\s*[=:]\s*["']AKIA[0-9A-Z]{16}["']"#)
                .expect("SL-001: invalid regex"),
        ],
        exclusions: vec![
            // Example/placeholder keys
            Regex::new(r"AKIAIOSFODNN7EXAMPLE").expect("SL-001: invalid regex"),
            Regex::new(r"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY").expect("SL-001: invalid regex"),
            // Test files
            Regex::new(r"test|mock|fake|dummy|example").expect("SL-001: invalid regex"),
        ],
        message: "AWS Access Key detected. This credential could allow unauthorized access to AWS resources.",
        recommendation: "Remove the key immediately, rotate it in AWS IAM console, and use environment variables or AWS Secrets Manager instead.",
        fix_hint: Some(
            "export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID (use env vars, not hardcoded keys)",
        ),
        cwe_ids: &["CWE-798", "CWE-200"],
    }
}

fn sl_002() -> Rule {
    Rule {
        id: "SL-002",
        name: "GitHub Token exposure",
        description: "Detects GitHub personal access tokens and other GitHub tokens",
        severity: Severity::Critical,
        category: Category::SecretLeak,
        confidence: Confidence::Certain,
        patterns: vec![
            // GitHub Personal Access Token (classic)
            Regex::new(r"ghp_[A-Za-z0-9]{36}").expect("SL-002: invalid regex"),
            // GitHub OAuth Access Token
            Regex::new(r"gho_[A-Za-z0-9]{36}").expect("SL-002: invalid regex"),
            // GitHub User-to-Server Token
            Regex::new(r"ghu_[A-Za-z0-9]{36}").expect("SL-002: invalid regex"),
            // GitHub Server-to-Server Token
            Regex::new(r"ghs_[A-Za-z0-9]{36}").expect("SL-002: invalid regex"),
            // GitHub Refresh Token
            Regex::new(r"ghr_[A-Za-z0-9]{36}").expect("SL-002: invalid regex"),
            // GitHub Fine-grained Personal Access Token
            Regex::new(r"github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}")
                .expect("SL-002: invalid regex"),
        ],
        exclusions: vec![
            // Test/example patterns
            Regex::new(r"test|mock|fake|dummy|example").expect("SL-002: invalid regex"),
        ],
        message: "GitHub Token detected. This token could allow unauthorized access to repositories.",
        recommendation: "Revoke the token immediately in GitHub Settings > Developer settings > Personal access tokens, and use GitHub Actions secrets or environment variables instead.",
        fix_hint: Some("Use $GITHUB_TOKEN env var or gh auth login for CLI authentication"),
        cwe_ids: &["CWE-798", "CWE-200"],
    }
}

fn sl_003() -> Rule {
    Rule {
        id: "SL-003",
        name: "AI API Key exposure",
        description: "Detects OpenAI, Anthropic, and other AI service API keys",
        severity: Severity::Critical,
        category: Category::SecretLeak,
        confidence: Confidence::Firm,
        patterns: vec![
            // OpenAI API Key (starts with sk-)
            Regex::new(r"sk-[A-Za-z0-9]{48}").expect("SL-003: invalid regex"),
            // OpenAI Project API Key
            Regex::new(r"sk-proj-[A-Za-z0-9]{48}").expect("SL-003: invalid regex"),
            // Anthropic API Key
            Regex::new(r"sk-ant-api[0-9]{2}-[A-Za-z0-9-]{86}").expect("SL-003: invalid regex"),
            // Google AI/Gemini API Key
            Regex::new(r"AIza[A-Za-z0-9_-]{35}").expect("SL-003: invalid regex"),
            // Cohere API Key
            Regex::new(r"[A-Za-z0-9]{40}").expect("SL-003: invalid regex"),
        ],
        exclusions: vec![
            // Test/example patterns
            Regex::new(r"test|mock|fake|dummy|example|placeholder").expect("SL-003: invalid regex"),
            // Common non-secret 40-char strings (to reduce false positives for Cohere pattern)
            Regex::new(r"sha1|sha256|commit").expect("SL-003: invalid regex"),
        ],
        message: "AI API Key detected. This key could allow unauthorized API usage and incur costs.",
        recommendation: "Remove the key, rotate it in the respective service dashboard, and use environment variables instead.",
        fix_hint: Some("Use env var: export OPENAI_API_KEY=... or ANTHROPIC_API_KEY=..."),
        cwe_ids: &["CWE-798", "CWE-200"],
    }
}

fn sl_004() -> Rule {
    Rule {
        id: "SL-004",
        name: "Generic secret pattern",
        description: "Detects common patterns for hardcoded secrets, passwords, and API keys",
        severity: Severity::High,
        category: Category::SecretLeak,
        confidence: Confidence::Tentative,
        patterns: vec![
            // API key assignments
            Regex::new(r#"api[_-]?key\s*[=:]\s*["'][A-Za-z0-9_-]{20,}["']"#)
                .expect("SL-004: invalid regex"),
            // Secret key assignments
            Regex::new(r#"secret[_-]?key\s*[=:]\s*["'][A-Za-z0-9_-]{20,}["']"#)
                .expect("SL-004: invalid regex"),
            // Password assignments (but not password prompts)
            Regex::new(r#"password\s*[=:]\s*["'][^"']{8,}["']"#).expect("SL-004: invalid regex"),
            // Access token assignments
            Regex::new(r#"access[_-]?token\s*[=:]\s*["'][A-Za-z0-9_-]{20,}["']"#)
                .expect("SL-004: invalid regex"),
            // Auth token assignments
            Regex::new(r#"auth[_-]?token\s*[=:]\s*["'][A-Za-z0-9_-]{20,}["']"#)
                .expect("SL-004: invalid regex"),
            // Bearer token in code
            Regex::new(r#"[Bb]earer\s+[A-Za-z0-9_-]{20,}"#).expect("SL-004: invalid regex"),
            // Basic auth with credentials
            Regex::new(r#"[Bb]asic\s+[A-Za-z0-9+/=]{20,}"#).expect("SL-004: invalid regex"),
        ],
        exclusions: vec![
            // Environment variable references (these are fine)
            Regex::new(r"\$\{?[A-Z_]+\}?").expect("SL-004: invalid regex"),
            Regex::new(r"process\.env\.[A-Z_]+").expect("SL-004: invalid regex"),
            Regex::new(r"os\.environ").expect("SL-004: invalid regex"),
            // Test/example patterns
            Regex::new(r"test|mock|fake|dummy|example|placeholder|your[_-]?")
                .expect("SL-004: invalid regex"),
            // Common password prompts/labels
            Regex::new(r"enter.*password|password.*prompt|password.*input")
                .expect("SL-004: invalid regex"),
        ],
        message: "Hardcoded secret detected. Storing credentials in code is a security risk.",
        recommendation: "Use environment variables, secret managers (AWS Secrets Manager, HashiCorp Vault), or configuration files excluded from version control.",
        fix_hint: Some("Replace hardcoded values with: ${API_KEY} or process.env.API_KEY"),
        cwe_ids: &["CWE-798"],
    }
}

fn sl_005() -> Rule {
    Rule {
        id: "SL-005",
        name: "Private key exposure",
        description: "Detects private key blocks that should never be committed to version control",
        severity: Severity::Critical,
        category: Category::SecretLeak,
        confidence: Confidence::Certain,
        patterns: vec![
            // RSA Private Key
            Regex::new(r"-----BEGIN RSA PRIVATE KEY-----").expect("SL-005: invalid regex"),
            // EC Private Key
            Regex::new(r"-----BEGIN EC PRIVATE KEY-----").expect("SL-005: invalid regex"),
            // OpenSSH Private Key
            Regex::new(r"-----BEGIN OPENSSH PRIVATE KEY-----").expect("SL-005: invalid regex"),
            // Generic Private Key
            Regex::new(r"-----BEGIN PRIVATE KEY-----").expect("SL-005: invalid regex"),
            // DSA Private Key
            Regex::new(r"-----BEGIN DSA PRIVATE KEY-----").expect("SL-005: invalid regex"),
            // PGP Private Key
            Regex::new(r"-----BEGIN PGP PRIVATE KEY BLOCK-----").expect("SL-005: invalid regex"),
        ],
        exclusions: vec![
            // Test/example files
            Regex::new(r"test|mock|fake|dummy|example").expect("SL-005: invalid regex"),
        ],
        message: "Private key detected. Private keys should never be committed to version control.",
        recommendation: "Remove the key from the repository history using git filter-branch or BFG Repo-Cleaner. Store keys securely outside of version control.",
        fix_hint: Some(
            "git filter-branch --force --index-filter 'git rm --cached --ignore-unmatch PATH' HEAD",
        ),
        cwe_ids: &["CWE-321", "CWE-522"],
    }
}

fn sl_006() -> Rule {
    Rule {
        id: "SL-006",
        name: "JWT token hardcoded",
        description: "Detects hardcoded JWT tokens in source code",
        severity: Severity::High,
        category: Category::SecretLeak,
        confidence: Confidence::Firm,
        patterns: vec![
            // JWT format: header.payload.signature (base64url encoded)
            Regex::new(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
                .expect("SL-006: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"test|mock|fake|dummy|example").expect("SL-006: invalid regex"),
        ],
        message: "Hardcoded JWT token detected. This token may grant unauthorized access.",
        recommendation: "Remove the JWT token and use environment variables or secure token generation.",
        fix_hint: Some("Use process.env.JWT_TOKEN or generate tokens dynamically"),
        cwe_ids: &["CWE-798", "CWE-200"],
    }
}

fn sl_007() -> Rule {
    Rule {
        id: "SL-007",
        name: "Slack webhook URL",
        description: "Detects Slack incoming webhook URLs",
        severity: Severity::High,
        category: Category::SecretLeak,
        confidence: Confidence::Certain,
        patterns: vec![
            Regex::new(
                r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}",
            )
            .expect("SL-007: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"test|mock|fake|dummy|example").expect("SL-007: invalid regex"),
        ],
        message: "Slack webhook URL detected. Anyone with this URL can post to your Slack channel.",
        recommendation: "Rotate the webhook URL in Slack and use environment variables.",
        fix_hint: Some("Use $SLACK_WEBHOOK_URL environment variable"),
        cwe_ids: &["CWE-798", "CWE-200"],
    }
}

fn sl_008() -> Rule {
    Rule {
        id: "SL-008",
        name: "Discord webhook URL",
        description: "Detects Discord webhook URLs",
        severity: Severity::High,
        category: Category::SecretLeak,
        confidence: Confidence::Certain,
        patterns: vec![
            Regex::new(r"https://discord(app)?\.com/api/webhooks/\d{17,}/[A-Za-z0-9_-]{60,}")
                .expect("SL-008: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"test|mock|fake|dummy|example").expect("SL-008: invalid regex"),
        ],
        message: "Discord webhook URL detected. Anyone with this URL can post to your Discord channel.",
        recommendation: "Regenerate the webhook in Discord and use environment variables.",
        fix_hint: Some("Use $DISCORD_WEBHOOK_URL environment variable"),
        cwe_ids: &["CWE-798", "CWE-200"],
    }
}

fn sl_009() -> Rule {
    Rule {
        id: "SL-009",
        name: "Telegram bot token",
        description: "Detects Telegram bot API tokens",
        severity: Severity::High,
        category: Category::SecretLeak,
        confidence: Confidence::Firm,
        patterns: vec![
            // Telegram bot token format: bot_id:secret
            Regex::new(r"\b\d{8,10}:[A-Za-z0-9_-]{35}\b").expect("SL-009: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"test|mock|fake|dummy|example").expect("SL-009: invalid regex"),
        ],
        message: "Telegram bot token detected. This token provides full control over the bot.",
        recommendation: "Revoke the token via @BotFather and use environment variables.",
        fix_hint: Some("Use $TELEGRAM_BOT_TOKEN environment variable"),
        cwe_ids: &["CWE-798", "CWE-200"],
    }
}

fn sl_010() -> Rule {
    Rule {
        id: "SL-010",
        name: "Database connection string",
        description: "Detects database connection strings with embedded credentials",
        severity: Severity::Critical,
        category: Category::SecretLeak,
        confidence: Confidence::Firm,
        patterns: vec![
            // MongoDB connection string with credentials
            Regex::new(r"mongodb(\+srv)?://[^:]+:[^@]+@[^/]+").expect("SL-010: invalid regex"),
            // PostgreSQL connection string with credentials
            Regex::new(r"postgres(ql)?://[^:]+:[^@]+@[^/]+").expect("SL-010: invalid regex"),
            // MySQL connection string with credentials
            Regex::new(r"mysql://[^:]+:[^@]+@[^/]+").expect("SL-010: invalid regex"),
            // Redis connection string with password
            Regex::new(r"redis://:[^@]+@[^/]+").expect("SL-010: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"test|mock|fake|dummy|example|localhost|127\.0\.0\.1")
                .expect("SL-010: invalid regex"),
            Regex::new(r"password|secret|\$\{").expect("SL-010: invalid regex"),
        ],
        message: "Database connection string with embedded credentials detected.",
        recommendation: "Use environment variables for database connection strings.",
        fix_hint: Some("Use $DATABASE_URL environment variable"),
        cwe_ids: &["CWE-798", "CWE-259"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sl_001_detects_aws_keys() {
        let rule = sl_001();
        let test_cases = vec![
            // Should detect
            ("AKIAIOSFODNN7ABCDEFG", true), // Valid format AWS key
            (r#"aws_access_key_id = "AKIAIOSFODNN7ABCDEFG""#, true),
            // Should not detect (examples/test)
            ("AKIAIOSFODNN7EXAMPLE", false), // AWS example key
            ("test AKIAIOSFODNN7ABCDEFG in test file", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_sl_002_detects_github_tokens() {
        let rule = sl_002();
        let test_cases = vec![
            // Should detect (36 characters after prefix)
            ("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", true),
            ("gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", true),
            ("ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", true),
            // Should not detect
            ("ghp_", false), // Too short
            ("not a github token", false),
            ("test ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", false), // In test context
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_sl_003_detects_ai_api_keys() {
        let rule = sl_003();
        let test_cases = vec![
            // Should detect (OpenAI-like keys)
            ("sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv", true),
            // Should not detect
            ("sk-", false), // Too short
            ("not an api key", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_sl_004_detects_generic_secrets() {
        let rule = sl_004();
        let test_cases = vec![
            // Should detect
            (r#"api_key = "abc123def456ghi789jkl012mno""#, true),
            (r#"secret_key: "ABCDEFGHIJKLMNOPabcdefghijklmnop""#, true),
            (r#"password = "mysecretpassword123""#, true),
            (r#"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"#, true),
            // Should not detect (env vars, examples)
            (r#"api_key = "${API_KEY}""#, false),
            (r#"api_key = process.env.API_KEY"#, false),
            (r#"api_key = "your_api_key_here""#, false), // placeholder
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_sl_005_detects_private_keys() {
        let rule = sl_005();
        let test_cases = vec![
            // Should detect
            ("-----BEGIN RSA PRIVATE KEY-----", true),
            ("-----BEGIN EC PRIVATE KEY-----", true),
            ("-----BEGIN OPENSSH PRIVATE KEY-----", true),
            ("-----BEGIN PRIVATE KEY-----", true),
            // Should not detect
            ("-----BEGIN PUBLIC KEY-----", false),
            ("-----BEGIN CERTIFICATE-----", false),
            ("test -----BEGIN RSA PRIVATE KEY----- in test", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_sl_004_excludes_env_var_references() {
        let rule = sl_004();
        // These should NOT be flagged (they use environment variables)
        let safe_patterns = vec![
            r#"api_key = os.environ.get("API_KEY")"#,
            r#"const apiKey = process.env.API_KEY"#,
            r#"api_key: ${API_KEY}"#,
        ];

        for pattern in safe_patterns {
            let matched = rule.patterns.iter().any(|p| p.is_match(pattern));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(pattern));
            let result = matched && !excluded;
            assert!(!result, "Should NOT detect env var reference: {}", pattern);
        }
    }

    // Snapshot tests
    #[test]
    fn snapshot_sl_001() {
        let rule = sl_001();
        let content = include_str!("../../../tests/fixtures/rules/sl_001.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("sl_001", findings);
    }

    #[test]
    fn snapshot_sl_002() {
        let rule = sl_002();
        let content = include_str!("../../../tests/fixtures/rules/sl_002.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("sl_002", findings);
    }

    #[test]
    fn snapshot_sl_003() {
        let rule = sl_003();
        let content = include_str!("../../../tests/fixtures/rules/sl_003.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("sl_003", findings);
    }

    #[test]
    fn snapshot_sl_004() {
        let rule = sl_004();
        let content = include_str!("../../../tests/fixtures/rules/sl_004.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("sl_004", findings);
    }

    #[test]
    fn snapshot_sl_005() {
        let rule = sl_005();
        let content = include_str!("../../../tests/fixtures/rules/sl_005.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("sl_005", findings);
    }
}
