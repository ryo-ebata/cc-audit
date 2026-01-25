use crate::rules::types::{Category, Confidence, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![
        ob_001(),
        ob_002(),
        ob_003(),
        ob_004(),
        ob_005(),
        ob_006(),
        ob_007(),
        ob_008(),
    ]
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
            Regex::new(r"eval\s+.*\$").expect("OB-001: invalid regex"),
            Regex::new(r#"eval\s+["'].*\$"#).expect("OB-001: invalid regex"),
            Regex::new(r"eval\s*\(.*\$").expect("OB-001: invalid regex"),
            Regex::new(r"exec\s*\(.*\$").expect("OB-001: invalid regex"),
            Regex::new(r"Function\s*\(.*\$").expect("OB-001: invalid regex"),
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
                .expect("OB-002: invalid regex"),
            Regex::new(r"base64\s+(-d|--decode).*\|\s*eval").expect("OB-002: invalid regex"),
            Regex::new(r"echo\s+.*\|\s*base64\s+(-d|--decode)\s*\|")
                .expect("OB-002: invalid regex"),
            Regex::new(r"atob\s*\(").expect("OB-002: invalid regex"),
            Regex::new(r#"Buffer\.from\s*\([^,]+,\s*['"]base64['"]"#)
                .expect("OB-002: invalid regex"),
        ],
        exclusions: vec![Regex::new(r"#.*base64").expect("OB-002: invalid regex")],
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
            Regex::new(r"echo\s+-e\s+.*\\x[0-9a-fA-F]{2}.*\|\s*(bash|sh|zsh)")
                .expect("OB-003: invalid regex"),
            // bash -c with hex encoded content
            Regex::new(r"bash\s+-c\s+.*\\x[0-9a-fA-F]{2}").expect("OB-003: invalid regex"),
            // $'...' quoting with escape sequences
            Regex::new(r"\$'.*\\x[0-9a-fA-F]{2}").expect("OB-003: invalid regex"),
            // Octal encoding
            Regex::new(r"echo\s+-e\s+.*\\[0-7]{3}.*\|\s*(bash|sh|zsh)")
                .expect("OB-003: invalid regex"),
            // printf with hex/octal
            Regex::new(r"printf\s+.*\\x[0-9a-fA-F]{2}.*\)\s*(https?:|[A-Za-z])")
                .expect("OB-003: invalid regex"),
            // xxd reverse (hex to binary)
            Regex::new(r"xxd\s+-r.*\|\s*(bash|sh|zsh|eval)").expect("OB-003: invalid regex"),
            // Python chr() obfuscation
            Regex::new(r"''.join\s*\(\s*\[\s*chr\s*\(").expect("OB-003: invalid regex"),
            Regex::new(r"exec\s*\(\s*''.join").expect("OB-003: invalid regex"),
        ],
        exclusions: vec![
            // Comments
            Regex::new(r"^\s*#").expect("OB-003: invalid regex"),
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
            Regex::new(r"\$\(.*\|\s*rev\s*\)").expect("OB-004: invalid regex"),
            Regex::new(r"`.*\|\s*rev`").expect("OB-004: invalid regex"),
            // String slicing in bash: ${var:start:length}
            Regex::new(r"\$\{[^}]+:[0-9]+:[0-9]+\}.*https?://").expect("OB-004: invalid regex"),
            // Array joining to build commands
            Regex::new(r#""\$\{[^}]+\[\*\]\}"\s+https?://"#).expect("OB-004: invalid regex"),
            // IFS manipulation
            Regex::new(r"IFS\s*=.*read.*<<<").expect("OB-004: invalid regex"),
            // Indirect variable reference
            Regex::new(r"\$\{![^}]+\}.*https?://").expect("OB-004: invalid regex"),
            // tr for character substitution building commands
            Regex::new(r"tr\s+.*\|\s*(bash|sh|eval)").expect("OB-004: invalid regex"),
            // sed/awk for command transformation
            Regex::new(r"(sed|awk).*\|\s*(bash|sh|eval)").expect("OB-004: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"^\s*#").expect("OB-004: invalid regex"),
            // Common legitimate uses
            Regex::new(r"rev\s+<\s*[^|]+$").expect("OB-004: invalid regex"),
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
            Regex::new(r#"compile\s*\([^)]*['\"][^'\"]*os\.(system|popen|exec)"#)
                .expect("OB-005: invalid regex"),
            Regex::new(r#"compile\s*\([^)]*['\"][^'\"]*subprocess"#)
                .expect("OB-005: invalid regex"),
            // Python __import__ for dynamic imports
            Regex::new(r#"__import__\s*\(\s*['\"]os['\"]"#).expect("OB-005: invalid regex"),
            Regex::new(r#"__import__\s*\(\s*['\"]subprocess['\"]"#).expect("OB-005: invalid regex"),
            Regex::new(r#"__import__\s*\(\s*['\"]socket['\"]"#).expect("OB-005: invalid regex"),
            // Python getattr for method access obfuscation
            Regex::new(r#"getattr\s*\([^)]*,\s*['\"]system['\"]"#).expect("OB-005: invalid regex"),
            Regex::new(r#"getattr\s*\([^)]*,\s*['\"]popen['\"]"#).expect("OB-005: invalid regex"),
            // Node.js vm module
            Regex::new(r"vm\.run(In(This)?Context|InNewContext)\s*\(")
                .expect("OB-005: invalid regex"),
            // Node.js new Function
            Regex::new(r"new\s+Function\s*\([^)]*require").expect("OB-005: invalid regex"),
            // Node.js dynamic require
            Regex::new(r#"require\s*\(\s*[^'"][^)]+\)"#).expect("OB-005: invalid regex"),
            // Python globals/locals manipulation
            Regex::new(r#"globals\s*\(\s*\)\s*\[.*exec"#).expect("OB-005: invalid regex"),
            Regex::new(r#"locals\s*\(\s*\)\s*\["#).expect("OB-005: invalid regex"),
            // Python pickle (code execution via deserialization)
            Regex::new(r"pickle\.loads?\s*\(").expect("OB-005: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"^\s*#").expect("OB-005: invalid regex"),
            Regex::new(r"^\s*//").expect("OB-005: invalid regex"),
            // Safe require patterns
            Regex::new(r#"require\s*\(\s*['\"]"#).expect("OB-005: invalid regex"),
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
            Regex::new(r"base32\s+(-d|--decode).*\|\s*(bash|sh|zsh|eval)")
                .expect("OB-006: invalid regex"),
            Regex::new(r"\|\s*base32\s+(-d|--decode)\s*\|\s*(bash|sh)")
                .expect("OB-006: invalid regex"),
            // ROT13 (tr command)
            Regex::new(r#"tr\s+['"]A-Za-z['"]\s+['"]N-ZA-Mn-za-m['"]\s*\|\s*(bash|sh)"#)
                .expect("OB-006: invalid regex"),
            // gzip/gunzip pipe to execution
            Regex::new(r"(gunzip|gzip\s+-d|zcat).*\|\s*(bash|sh|zsh|eval)")
                .expect("OB-006: invalid regex"),
            // bzip2 pipe to execution
            Regex::new(r"(bunzip2|bzip2\s+-d|bzcat).*\|\s*(bash|sh|zsh|eval)")
                .expect("OB-006: invalid regex"),
            // xz/unxz pipe to execution
            Regex::new(r"(unxz|xz\s+-d|xzcat).*\|\s*(bash|sh|zsh|eval)")
                .expect("OB-006: invalid regex"),
            // openssl encoding
            Regex::new(r"openssl\s+(enc|base64)\s+-d.*\|\s*(bash|sh|eval)")
                .expect("OB-006: invalid regex"),
            // uudecode
            Regex::new(r"uudecode.*\|\s*(bash|sh|eval)").expect("OB-006: invalid regex"),
        ],
        exclusions: vec![Regex::new(r"^\s*#").expect("OB-006: invalid regex")],
        message: "Alternative encoding execution detected. Content is decoded and executed, potentially hiding malicious commands.",
        recommendation: "Decode the content first and review before execution. Avoid executing encoded content.",
        fix_hint: Some("Decode and review: base32 -d file.txt, then inspect before executing"),
        cwe_ids: &["CWE-95", "CWE-116"],
    }
}

fn ob_007() -> Rule {
    Rule {
        id: "OB-007",
        name: "String concatenation obfuscation",
        description: "Detects command obfuscation via string concatenation to hide malicious intent",
        severity: Severity::Medium,
        category: Category::Obfuscation,
        confidence: Confidence::Tentative,
        patterns: vec![
            // JavaScript string concatenation building commands
            Regex::new(r#"['"]cu['"].*\+.*['"]rl['"]"#).expect("OB-007: invalid regex"),
            Regex::new(r#"['"]wg['"].*\+.*['"]et['"]"#).expect("OB-007: invalid regex"),
            Regex::new(r#"['"]ev['"].*\+.*['"]al['"]"#).expect("OB-007: invalid regex"),
            // Python string concatenation
            Regex::new(r#"['"]cu['"].*['"]rl['"]"#).expect("OB-007: invalid regex"),
            // Bash variable concatenation building commands
            Regex::new(r#"[a-z]=["']?[a-z]{1,3}["']?;.*\$[a-z].*\$[a-z]"#).expect("OB-007: invalid regex"),
            // Split array join to build command
            Regex::new(r#"\[\s*['"][a-z]{1,3}['"]\s*,\s*['"][a-z]{1,3}['"].*\]\.join\s*\(\s*['"]['"]\s*\)"#)
                .expect("OB-007: invalid regex"),
            // Template literal concatenation
            Regex::new(r#"`\$\{['"][a-z]{1,3}['"]\}`"#).expect("OB-007: invalid regex"),
            // Character code building (String.fromCharCode patterns)
            Regex::new(r"String\.fromCharCode\s*\(\s*\d+\s*(,\s*\d+\s*){3,}")
                .expect("OB-007: invalid regex"),
            // Python chr() building
            Regex::new(r"chr\s*\(\s*\d+\s*\)\s*\+\s*chr\s*\(\s*\d+\s*\)")
                .expect("OB-007: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"^\s*#").expect("OB-007: invalid regex"),
            Regex::new(r"^\s*//").expect("OB-007: invalid regex"),
            // Test/example files
            Regex::new(r"test|spec|example").expect("OB-007: invalid regex"),
        ],
        message: "String concatenation obfuscation detected. Command names may be built from fragments to evade detection.",
        recommendation: "Use direct command names instead of building them from string fragments.",
        fix_hint: Some("Replace string concatenation with direct command: 'curl' instead of 'cu' + 'rl'"),
        cwe_ids: &["CWE-95"],
    }
}

fn ob_008() -> Rule {
    Rule {
        id: "OB-008",
        name: "Variable expansion obfuscation",
        description: "Detects command obfuscation via variable expansion and indirect references",
        severity: Severity::Medium,
        category: Category::Obfuscation,
        confidence: Confidence::Tentative,
        patterns: vec![
            // Bash indirect variable expansion
            Regex::new(r"\$\{![a-zA-Z_][a-zA-Z0-9_]*\}").expect("OB-008: invalid regex"),
            // Building command in variable then executing
            Regex::new(r#"[A-Z_]+=['"]?(curl|wget|nc|bash|sh|eval)['"]?.*;\s*\$[A-Z_]+"#)
                .expect("OB-008: invalid regex"),
            // Brace expansion building commands
            Regex::new(r"\{[a-z],[a-z],[a-z]\}").expect("OB-008: invalid regex"),
            // Parameter expansion tricks
            Regex::new(r"\$\{[a-zA-Z_]+::\d+\}").expect("OB-008: invalid regex"),
            Regex::new(r"\$\{[a-zA-Z_]+:\d+:\d+\}").expect("OB-008: invalid regex"),
            // Environment variable command execution
            Regex::new(r"\$\([^)]*\$[A-Z_]+[^)]*\)").expect("OB-008: invalid regex"),
            // Command substitution with variable command
            Regex::new(r"`\$[A-Z_]+.*`").expect("OB-008: invalid regex"),
            // Python globals/eval tricks
            Regex::new(r#"globals\s*\(\s*\)\s*\[['"]"#).expect("OB-008: invalid regex"),
            Regex::new(r"eval\s*\(\s*[a-zA-Z_]+\s*\)").expect("OB-008: invalid regex"),
            // Node.js global/process tricks
            Regex::new(r#"global\s*\[\s*['"][a-zA-Z]+['"]\s*\]"#).expect("OB-008: invalid regex"),
            Regex::new(r#"process\s*\[\s*['"]"#).expect("OB-008: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"^\s*#").expect("OB-008: invalid regex"),
            Regex::new(r"^\s*//").expect("OB-008: invalid regex"),
            // Common legitimate uses
            Regex::new(r"\$\{[A-Z_]+:-").expect("OB-008: invalid regex"), // Default value expansion
            Regex::new(r"\$\{#[A-Z_]+\}").expect("OB-008: invalid regex"), // String length
        ],
        message: "Variable expansion obfuscation detected. Commands may be hidden in variable references.",
        recommendation: "Use direct command names instead of variable indirection.",
        fix_hint: Some("Replace variable expansion with direct commands for clarity"),
        cwe_ids: &["CWE-95"],
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
