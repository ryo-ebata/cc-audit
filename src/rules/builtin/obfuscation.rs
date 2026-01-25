use crate::rules::types::{Category, Confidence, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![ob_001(), ob_002(), ob_003(), ob_004(), ob_005(), ob_006()]
}

fn ob_001() -> Rule {
    Rule {
        id: "OB-001",
        name: "Eval with variable expansion",
        description: "Detects eval commands with variable expansion that could execute arbitrary code",
        severity: Severity::High,
        category: Category::Obfuscation,
        confidence: Confidence::Firm,
        patterns: vec![
            Regex::new(r"eval\s+.*\$").unwrap(),
            Regex::new(r#"eval\s+["'].*\$"#).unwrap(),
            Regex::new(r"eval\s*\(.*\$").unwrap(),
            Regex::new(r"exec\s*\(.*\$").unwrap(),
            Regex::new(r"Function\s*\(.*\$").unwrap(),
        ],
        exclusions: vec![],
        message: "Potential obfuscation: eval with variable expansion can execute arbitrary code",
        recommendation: "Avoid using eval with variables. Use direct command execution instead",
        fix_hint: Some(
            "Replace eval with direct command: instead of eval \"$CMD\" use $CMD directly",
        ),
        cwe_ids: &["CWE-95"],
    }
}

fn ob_002() -> Rule {
    Rule {
        id: "OB-002",
        name: "Base64 decode execution",
        description: "Detects base64 decoding piped to execution, commonly used to hide malicious commands",
        severity: Severity::High,
        category: Category::Obfuscation,
        confidence: Confidence::Firm,
        patterns: vec![
            Regex::new(r"base64\s+(-d|--decode).*\|\s*(bash|sh|zsh|python|perl|ruby|node)")
                .unwrap(),
            Regex::new(r"base64\s+(-d|--decode).*\|\s*eval").unwrap(),
            Regex::new(r"echo\s+.*\|\s*base64\s+(-d|--decode)\s*\|").unwrap(),
            Regex::new(r"atob\s*\(").unwrap(),
            Regex::new(r#"Buffer\.from\s*\([^,]+,\s*['"]base64['"]"#).unwrap(),
        ],
        exclusions: vec![Regex::new(r"#.*base64").unwrap()],
        message: "Potential obfuscation: base64 decode piped to execution",
        recommendation: "Decode and review the base64 content before execution",
        fix_hint: Some("Decode first: base64 -d file.txt > script.sh, review, then execute"),
        cwe_ids: &["CWE-95"],
    }
}

fn ob_003() -> Rule {
    Rule {
        id: "OB-003",
        name: "Hex/Octal encoded execution",
        description: "Detects execution of hex or octal encoded commands, commonly used to evade detection",
        severity: Severity::High,
        category: Category::Obfuscation,
        confidence: Confidence::Firm,
        patterns: vec![
            // echo -e with hex escape sequences piped to execution
            Regex::new(r"echo\s+-e\s+.*\\x[0-9a-fA-F]{2}.*\|\s*(bash|sh|zsh)").unwrap(),
            // bash -c with hex encoded content
            Regex::new(r"bash\s+-c\s+.*\\x[0-9a-fA-F]{2}").unwrap(),
            // $'...' quoting with escape sequences
            Regex::new(r"\$'.*\\x[0-9a-fA-F]{2}").unwrap(),
            // Octal encoding
            Regex::new(r"echo\s+-e\s+.*\\[0-7]{3}.*\|\s*(bash|sh|zsh)").unwrap(),
            // printf with hex/octal
            Regex::new(r"printf\s+.*\\x[0-9a-fA-F]{2}.*\)\s*(https?:|[A-Za-z])").unwrap(),
            // xxd reverse (hex to binary)
            Regex::new(r"xxd\s+-r.*\|\s*(bash|sh|zsh|eval)").unwrap(),
            // Python chr() obfuscation
            Regex::new(r"''.join\s*\(\s*\[\s*chr\s*\(").unwrap(),
            Regex::new(r"exec\s*\(\s*''.join").unwrap(),
        ],
        exclusions: vec![
            // Comments
            Regex::new(r"^\s*#").unwrap(),
        ],
        message: "Potential obfuscation: hex/octal encoded command execution detected. This technique is commonly used to hide malicious commands.",
        recommendation: "Decode the hex/octal content to inspect the actual command. Avoid executing encoded content.",
        fix_hint: Some(
            "Decode first: echo -e '\\x...' to see the content, review before execution",
        ),
        cwe_ids: &["CWE-95", "CWE-116"],
    }
}

fn ob_004() -> Rule {
    Rule {
        id: "OB-004",
        name: "String manipulation obfuscation",
        description: "Detects command construction via string manipulation techniques like rev, cut, or array joining",
        severity: Severity::Medium,
        category: Category::Obfuscation,
        confidence: Confidence::Tentative,
        patterns: vec![
            // rev trick to reverse command names
            Regex::new(r"\$\(.*\|\s*rev\s*\)").unwrap(),
            Regex::new(r"`.*\|\s*rev`").unwrap(),
            // String slicing in bash: ${var:start:length}
            Regex::new(r"\$\{[^}]+:[0-9]+:[0-9]+\}.*https?://").unwrap(),
            // Array joining to build commands
            Regex::new(r#""\$\{[^}]+\[\*\]\}"\s+https?://"#).unwrap(),
            // IFS manipulation
            Regex::new(r"IFS\s*=.*read.*<<<").unwrap(),
            // Indirect variable reference
            Regex::new(r"\$\{![^}]+\}.*https?://").unwrap(),
            // tr for character substitution building commands
            Regex::new(r"tr\s+.*\|\s*(bash|sh|eval)").unwrap(),
            // sed/awk for command transformation
            Regex::new(r"(sed|awk).*\|\s*(bash|sh|eval)").unwrap(),
        ],
        exclusions: vec![
            Regex::new(r"^\s*#").unwrap(),
            // Common legitimate uses
            Regex::new(r"rev\s+<\s*[^|]+$").unwrap(),
        ],
        message: "Potential obfuscation: command construction via string manipulation detected. This technique can hide the actual command being executed.",
        recommendation: "Review the string manipulation to understand what command is being constructed.",
        fix_hint: Some("Use direct command names instead of constructing them dynamically"),
        cwe_ids: &["CWE-95"],
    }
}

fn ob_005() -> Rule {
    Rule {
        id: "OB-005",
        name: "Dynamic code execution patterns",
        description: "Detects dynamic code execution patterns that can hide malicious intent",
        severity: Severity::High,
        category: Category::Obfuscation,
        confidence: Confidence::Firm,
        patterns: vec![
            // Python compile() for dynamic execution
            Regex::new(r#"compile\s*\([^)]*['\"][^'\"]*os\.(system|popen|exec)"#).unwrap(),
            Regex::new(r#"compile\s*\([^)]*['\"][^'\"]*subprocess"#).unwrap(),
            // Python __import__ for dynamic imports
            Regex::new(r#"__import__\s*\(\s*['\"]os['\"]"#).unwrap(),
            Regex::new(r#"__import__\s*\(\s*['\"]subprocess['\"]"#).unwrap(),
            Regex::new(r#"__import__\s*\(\s*['\"]socket['\"]"#).unwrap(),
            // Python getattr for method access obfuscation
            Regex::new(r#"getattr\s*\([^)]*,\s*['\"]system['\"]"#).unwrap(),
            Regex::new(r#"getattr\s*\([^)]*,\s*['\"]popen['\"]"#).unwrap(),
            // Node.js vm module
            Regex::new(r"vm\.run(In(This)?Context|InNewContext)\s*\(").unwrap(),
            // Node.js new Function
            Regex::new(r"new\s+Function\s*\([^)]*require").unwrap(),
            // Node.js dynamic require
            Regex::new(r#"require\s*\(\s*[^'"][^)]+\)"#).unwrap(),
            // Python globals/locals manipulation
            Regex::new(r#"globals\s*\(\s*\)\s*\[.*exec"#).unwrap(),
            Regex::new(r#"locals\s*\(\s*\)\s*\["#).unwrap(),
            // Python pickle (code execution via deserialization)
            Regex::new(r"pickle\.loads?\s*\(").unwrap(),
        ],
        exclusions: vec![
            Regex::new(r"^\s*#").unwrap(),
            Regex::new(r"^\s*//").unwrap(),
            // Safe require patterns
            Regex::new(r#"require\s*\(\s*['\"]"#).unwrap(),
        ],
        message: "Dynamic code execution pattern detected. This can be used to hide malicious intent or execute arbitrary code.",
        recommendation: "Avoid dynamic code execution. Use explicit imports and direct function calls instead.",
        fix_hint: Some(
            "Replace dynamic execution with static: instead of __import__('os') use 'import os'",
        ),
        cwe_ids: &["CWE-95", "CWE-502"],
    }
}

fn ob_006() -> Rule {
    Rule {
        id: "OB-006",
        name: "Alternative encoding execution",
        description: "Detects execution of alternatively encoded content like base32, rot13, or compressed data",
        severity: Severity::High,
        category: Category::Obfuscation,
        confidence: Confidence::Firm,
        patterns: vec![
            // base32 decode and execute
            Regex::new(r"base32\s+(-d|--decode).*\|\s*(bash|sh|zsh|eval)").unwrap(),
            Regex::new(r"\|\s*base32\s+(-d|--decode)\s*\|\s*(bash|sh)").unwrap(),
            // ROT13 (tr command)
            Regex::new(r#"tr\s+['"]A-Za-z['"]\s+['"]N-ZA-Mn-za-m['"]\s*\|\s*(bash|sh)"#).unwrap(),
            // gzip/gunzip pipe to execution
            Regex::new(r"(gunzip|gzip\s+-d|zcat).*\|\s*(bash|sh|zsh|eval)").unwrap(),
            // bzip2 pipe to execution
            Regex::new(r"(bunzip2|bzip2\s+-d|bzcat).*\|\s*(bash|sh|zsh|eval)").unwrap(),
            // xz/unxz pipe to execution
            Regex::new(r"(unxz|xz\s+-d|xzcat).*\|\s*(bash|sh|zsh|eval)").unwrap(),
            // openssl encoding
            Regex::new(r"openssl\s+(enc|base64)\s+-d.*\|\s*(bash|sh|eval)").unwrap(),
            // uudecode
            Regex::new(r"uudecode.*\|\s*(bash|sh|eval)").unwrap(),
        ],
        exclusions: vec![Regex::new(r"^\s*#").unwrap()],
        message: "Alternative encoding execution detected. Content is decoded and executed, potentially hiding malicious commands.",
        recommendation: "Decode the content first and review before execution. Avoid executing encoded content.",
        fix_hint: Some("Decode and review: base32 -d file.txt, then inspect before executing"),
        cwe_ids: &["CWE-95", "CWE-116"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ob_001_detects_eval_with_variables() {
        let rule = ob_001();
        let test_cases = vec![
            ("eval $CMD", true),
            ("eval \"$PAYLOAD\"", true),
            ("eval($variable)", true),
            ("exec($code)", true),
            ("Function($body)", true),
            ("eval 'literal string'", false),
            ("echo $VAR", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_ob_002_detects_base64_execution() {
        let rule = ob_002();
        let test_cases = vec![
            ("echo 'SGVsbG8=' | base64 -d | bash", true),
            ("base64 --decode payload.txt | sh", true),
            ("echo 'cmd' | base64 -d | eval", true),
            ("atob('SGVsbG8=')", true),
            ("Buffer.from(data, 'base64')", true),
            ("base64 -d file.txt", false),
            ("# base64 decode example", false),
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
    fn snapshot_ob_001() {
        let rule = ob_001();
        let content = include_str!("../../../tests/fixtures/rules/ob_001.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ob_001", findings);
    }

    #[test]
    fn snapshot_ob_002() {
        let rule = ob_002();
        let content = include_str!("../../../tests/fixtures/rules/ob_002.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ob_002", findings);
    }

    #[test]
    fn snapshot_ob_003() {
        let rule = ob_003();
        let content = include_str!("../../../tests/fixtures/rules/ob_003.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ob_003", findings);
    }

    #[test]
    fn snapshot_ob_004() {
        let rule = ob_004();
        let content = include_str!("../../../tests/fixtures/rules/ob_004.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ob_004", findings);
    }

    #[test]
    fn snapshot_ob_005() {
        let rule = ob_005();
        let content = include_str!("../../../tests/fixtures/rules/ob_005.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ob_005", findings);
    }

    #[test]
    fn snapshot_ob_006() {
        let rule = ob_006();
        let content = include_str!("../../../tests/fixtures/rules/ob_006.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ob_006", findings);
    }
}
