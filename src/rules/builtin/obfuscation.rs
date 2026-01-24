use crate::rules::types::{Category, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![ob_001(), ob_002()]
}

fn ob_001() -> Rule {
    Rule {
        id: "OB-001",
        name: "Eval with variable expansion",
        description: "Detects eval commands with variable expansion that could execute arbitrary code",
        severity: Severity::High,
        category: Category::Obfuscation,
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
    }
}

fn ob_002() -> Rule {
    Rule {
        id: "OB-002",
        name: "Base64 decode execution",
        description: "Detects base64 decoding piped to execution, commonly used to hide malicious commands",
        severity: Severity::High,
        category: Category::Obfuscation,
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
}
