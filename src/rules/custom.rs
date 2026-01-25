use crate::rules::types::{Category, Confidence, Finding, Location, Severity};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A dynamic rule loaded from YAML configuration.
#[derive(Debug, Clone)]
pub struct DynamicRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub category: Category,
    pub confidence: Confidence,
    pub patterns: Vec<Regex>,
    pub exclusions: Vec<Regex>,
    pub message: String,
    pub recommendation: String,
    pub fix_hint: Option<String>,
    pub cwe_ids: Vec<String>,
}

impl DynamicRule {
    /// Check if a line matches this rule.
    pub fn matches(&self, line: &str) -> bool {
        let pattern_match = self.patterns.iter().any(|p| p.is_match(line));
        let excluded = self.exclusions.iter().any(|e| e.is_match(line));
        pattern_match && !excluded
    }

    /// Create a Finding from this rule.
    pub fn create_finding(&self, location: Location, code: String) -> Finding {
        Finding {
            id: self.id.clone(),
            severity: self.severity,
            category: self.category,
            confidence: self.confidence,
            name: self.name.clone(),
            location,
            code,
            message: self.message.clone(),
            recommendation: self.recommendation.clone(),
            fix_hint: self.fix_hint.clone(),
            cwe_ids: self.cwe_ids.clone(),
        }
    }
}

/// YAML schema for custom rules file.
#[derive(Debug, Serialize, Deserialize)]
pub struct CustomRulesConfig {
    pub version: String,
    pub rules: Vec<YamlRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YamlRule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub severity: String,
    pub category: String,
    #[serde(default = "default_confidence")]
    pub confidence: String,
    pub patterns: Vec<String>,
    #[serde(default)]
    pub exclusions: Vec<String>,
    pub message: String,
    #[serde(default)]
    pub recommendation: String,
    #[serde(default)]
    pub fix_hint: Option<String>,
    #[serde(default)]
    pub cwe: Vec<String>,
}

fn default_confidence() -> String {
    "firm".to_string()
}

/// Error type for custom rule loading.
#[derive(Debug)]
pub enum CustomRuleError {
    IoError(std::io::Error),
    ParseError(serde_yaml::Error),
    InvalidPattern {
        rule_id: String,
        pattern: String,
        error: regex::Error,
    },
    InvalidSeverity {
        rule_id: String,
        value: String,
    },
    InvalidCategory {
        rule_id: String,
        value: String,
    },
    InvalidConfidence {
        rule_id: String,
        value: String,
    },
}

impl std::fmt::Display for CustomRuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "Failed to read custom rules file: {}", e),
            Self::ParseError(e) => write!(f, "Failed to parse custom rules YAML: {}", e),
            Self::InvalidPattern {
                rule_id,
                pattern,
                error,
            } => {
                write!(
                    f,
                    "Invalid regex pattern '{}' in rule {}: {}",
                    pattern, rule_id, error
                )
            }
            Self::InvalidSeverity { rule_id, value } => {
                write!(
                    f,
                    "Invalid severity '{}' in rule {}. Expected: critical, high, medium, low",
                    value, rule_id
                )
            }
            Self::InvalidCategory { rule_id, value } => {
                write!(
                    f,
                    "Invalid category '{}' in rule {}. Expected: exfiltration, privilege-escalation, persistence, prompt-injection, overpermission, obfuscation, supply-chain, secret-leak",
                    value, rule_id
                )
            }
            Self::InvalidConfidence { rule_id, value } => {
                write!(
                    f,
                    "Invalid confidence '{}' in rule {}. Expected: certain, firm, tentative",
                    value, rule_id
                )
            }
        }
    }
}

impl std::error::Error for CustomRuleError {}

/// Loads custom rules from a YAML file.
pub struct CustomRuleLoader;

impl CustomRuleLoader {
    /// Load rules from a YAML file path.
    pub fn load_from_file(path: &Path) -> Result<Vec<DynamicRule>, CustomRuleError> {
        let content = std::fs::read_to_string(path).map_err(CustomRuleError::IoError)?;
        Self::load_from_string(&content)
    }

    /// Load rules from a YAML string.
    pub fn load_from_string(content: &str) -> Result<Vec<DynamicRule>, CustomRuleError> {
        let config: CustomRulesConfig =
            serde_yaml::from_str(content).map_err(CustomRuleError::ParseError)?;

        let mut rules = Vec::new();
        for yaml_rule in config.rules {
            let rule = Self::convert_yaml_rule(yaml_rule)?;
            rules.push(rule);
        }
        Ok(rules)
    }

    /// Convert a vector of YamlRules to DynamicRules.
    pub fn convert_yaml_rules(rules: Vec<YamlRule>) -> Result<Vec<DynamicRule>, CustomRuleError> {
        rules.into_iter().map(Self::convert_yaml_rule).collect()
    }

    /// Convert a single YamlRule to a DynamicRule.
    pub fn convert_yaml_rule(yaml: YamlRule) -> Result<DynamicRule, CustomRuleError> {
        let severity = Self::parse_severity(&yaml.id, &yaml.severity)?;
        let category = Self::parse_category(&yaml.id, &yaml.category)?;
        let confidence = Self::parse_confidence(&yaml.id, &yaml.confidence)?;

        let patterns = yaml
            .patterns
            .iter()
            .map(|p| {
                Regex::new(p).map_err(|e| CustomRuleError::InvalidPattern {
                    rule_id: yaml.id.clone(),
                    pattern: p.clone(),
                    error: e,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let exclusions = yaml
            .exclusions
            .iter()
            .map(|p| {
                Regex::new(p).map_err(|e| CustomRuleError::InvalidPattern {
                    rule_id: yaml.id.clone(),
                    pattern: p.clone(),
                    error: e,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(DynamicRule {
            id: yaml.id,
            name: yaml.name,
            description: yaml.description,
            severity,
            category,
            confidence,
            patterns,
            exclusions,
            message: yaml.message,
            recommendation: yaml.recommendation,
            fix_hint: yaml.fix_hint,
            cwe_ids: yaml.cwe,
        })
    }

    fn parse_severity(rule_id: &str, value: &str) -> Result<Severity, CustomRuleError> {
        match value.to_lowercase().as_str() {
            "critical" => Ok(Severity::Critical),
            "high" => Ok(Severity::High),
            "medium" => Ok(Severity::Medium),
            "low" => Ok(Severity::Low),
            _ => Err(CustomRuleError::InvalidSeverity {
                rule_id: rule_id.to_string(),
                value: value.to_string(),
            }),
        }
    }

    fn parse_category(rule_id: &str, value: &str) -> Result<Category, CustomRuleError> {
        match value.to_lowercase().replace('_', "-").as_str() {
            "exfiltration" | "data-exfiltration" => Ok(Category::Exfiltration),
            "privilege-escalation" | "privilege" => Ok(Category::PrivilegeEscalation),
            "persistence" => Ok(Category::Persistence),
            "prompt-injection" | "injection" => Ok(Category::PromptInjection),
            "overpermission" | "permission" => Ok(Category::Overpermission),
            "obfuscation" => Ok(Category::Obfuscation),
            "supply-chain" | "supplychain" => Ok(Category::SupplyChain),
            "secret-leak" | "secrets" | "secretleak" => Ok(Category::SecretLeak),
            _ => Err(CustomRuleError::InvalidCategory {
                rule_id: rule_id.to_string(),
                value: value.to_string(),
            }),
        }
    }

    fn parse_confidence(rule_id: &str, value: &str) -> Result<Confidence, CustomRuleError> {
        match value.to_lowercase().as_str() {
            "certain" => Ok(Confidence::Certain),
            "firm" => Ok(Confidence::Firm),
            "tentative" => Ok(Confidence::Tentative),
            _ => Err(CustomRuleError::InvalidConfidence {
                rule_id: rule_id.to_string(),
                value: value.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_valid_yaml() {
        let yaml = r#"
version: "1"
rules:
  - id: "CUSTOM-001"
    name: "Internal API access"
    description: "Detects access to internal APIs"
    severity: "high"
    category: "exfiltration"
    confidence: "firm"
    patterns:
      - 'https?://internal\.'
    exclusions:
      - 'localhost'
    message: "Internal API access detected"
    recommendation: "Review if this is intended"
    cwe:
      - "CWE-200"
"#;
        let rules = CustomRuleLoader::load_from_string(yaml).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "CUSTOM-001");
        assert_eq!(rules[0].name, "Internal API access");
        assert_eq!(rules[0].severity, Severity::High);
        assert_eq!(rules[0].category, Category::Exfiltration);
        assert_eq!(rules[0].confidence, Confidence::Firm);
        assert_eq!(rules[0].cwe_ids, vec!["CWE-200"]);
    }

    #[test]
    fn test_load_multiple_rules() {
        let yaml = r#"
version: "1"
rules:
  - id: "CUSTOM-001"
    name: "Rule One"
    severity: "critical"
    category: "exfiltration"
    patterns:
      - 'pattern1'
    message: "Message 1"
  - id: "CUSTOM-002"
    name: "Rule Two"
    severity: "low"
    category: "obfuscation"
    patterns:
      - 'pattern2'
    message: "Message 2"
"#;
        let rules = CustomRuleLoader::load_from_string(yaml).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "CUSTOM-001");
        assert_eq!(rules[1].id, "CUSTOM-002");
    }

    #[test]
    fn test_invalid_severity() {
        let yaml = r#"
version: "1"
rules:
  - id: "CUSTOM-001"
    name: "Test"
    severity: "invalid"
    category: "exfiltration"
    patterns:
      - 'test'
    message: "Test"
"#;
        let result = CustomRuleLoader::load_from_string(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CustomRuleError::InvalidSeverity { .. }));
    }

    #[test]
    fn test_invalid_category() {
        let yaml = r#"
version: "1"
rules:
  - id: "CUSTOM-001"
    name: "Test"
    severity: "high"
    category: "invalid"
    patterns:
      - 'test'
    message: "Test"
"#;
        let result = CustomRuleLoader::load_from_string(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CustomRuleError::InvalidCategory { .. }));
    }

    #[test]
    fn test_invalid_regex() {
        let yaml = r#"
version: "1"
rules:
  - id: "CUSTOM-001"
    name: "Test"
    severity: "high"
    category: "exfiltration"
    patterns:
      - '[invalid('
    message: "Test"
"#;
        let result = CustomRuleLoader::load_from_string(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CustomRuleError::InvalidPattern { .. }));
    }

    #[test]
    fn test_default_confidence() {
        let yaml = r#"
version: "1"
rules:
  - id: "CUSTOM-001"
    name: "Test"
    severity: "high"
    category: "exfiltration"
    patterns:
      - 'test'
    message: "Test"
"#;
        let rules = CustomRuleLoader::load_from_string(yaml).unwrap();
        assert_eq!(rules[0].confidence, Confidence::Firm);
    }

    #[test]
    fn test_rule_matches() {
        let yaml = r#"
version: "1"
rules:
  - id: "CUSTOM-001"
    name: "API Key Pattern"
    severity: "high"
    category: "secret-leak"
    patterns:
      - 'API_KEY\s*=\s*"[^"]+"'
    exclusions:
      - 'test'
      - 'example'
    message: "API key detected"
"#;
        let rules = CustomRuleLoader::load_from_string(yaml).unwrap();
        let rule = &rules[0];

        // Should match
        assert!(rule.matches(r#"API_KEY = "secret123""#));

        // Should not match (exclusion)
        assert!(!rule.matches(r#"test API_KEY = "secret123""#));

        // Should not match (no pattern match)
        assert!(!rule.matches("random text"));
    }

    #[test]
    fn test_create_finding() {
        let yaml = r#"
version: "1"
rules:
  - id: "CUSTOM-001"
    name: "Test Rule"
    severity: "critical"
    category: "exfiltration"
    confidence: "certain"
    patterns:
      - 'test'
    message: "Test message"
    recommendation: "Fix it"
    fix_hint: "Do this"
    cwe:
      - "CWE-200"
      - "CWE-319"
"#;
        let rules = CustomRuleLoader::load_from_string(yaml).unwrap();
        let rule = &rules[0];

        let location = Location {
            file: "test.txt".to_string(),
            line: 10,
            column: None,
        };
        let finding = rule.create_finding(location, "test code".to_string());

        assert_eq!(finding.id, "CUSTOM-001");
        assert_eq!(finding.name, "Test Rule");
        assert_eq!(finding.severity, Severity::Critical);
        assert_eq!(finding.category, Category::Exfiltration);
        assert_eq!(finding.confidence, Confidence::Certain);
        assert_eq!(finding.message, "Test message");
        assert_eq!(finding.recommendation, "Fix it");
        assert_eq!(finding.fix_hint, Some("Do this".to_string()));
        assert_eq!(finding.cwe_ids, vec!["CWE-200", "CWE-319"]);
    }

    #[test]
    fn test_category_variations() {
        let test_cases = vec![
            ("exfiltration", Category::Exfiltration),
            ("data-exfiltration", Category::Exfiltration),
            ("privilege-escalation", Category::PrivilegeEscalation),
            ("privilege", Category::PrivilegeEscalation),
            ("persistence", Category::Persistence),
            ("prompt-injection", Category::PromptInjection),
            ("injection", Category::PromptInjection),
            ("overpermission", Category::Overpermission),
            ("permission", Category::Overpermission),
            ("obfuscation", Category::Obfuscation),
            ("supply-chain", Category::SupplyChain),
            ("supplychain", Category::SupplyChain),
            ("secret-leak", Category::SecretLeak),
            ("secrets", Category::SecretLeak),
            ("secretleak", Category::SecretLeak),
        ];

        for (input, expected) in test_cases {
            let result = CustomRuleLoader::parse_category("test", input);
            assert_eq!(result.unwrap(), expected, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_error_display() {
        let io_err = CustomRuleError::IoError(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        ));
        assert!(io_err.to_string().contains("Failed to read"));

        let severity_err = CustomRuleError::InvalidSeverity {
            rule_id: "TEST".to_string(),
            value: "bad".to_string(),
        };
        assert!(severity_err.to_string().contains("Invalid severity"));

        let category_err = CustomRuleError::InvalidCategory {
            rule_id: "TEST".to_string(),
            value: "bad".to_string(),
        };
        assert!(category_err.to_string().contains("Invalid category"));

        let confidence_err = CustomRuleError::InvalidConfidence {
            rule_id: "TEST".to_string(),
            value: "bad".to_string(),
        };
        assert!(confidence_err.to_string().contains("Invalid confidence"));
    }

    #[test]
    fn test_load_from_file() {
        use tempfile::TempDir;
        use std::fs;

        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("rules.yaml");
        fs::write(
            &file_path,
            r#"
version: "1"
rules:
  - id: "FILE-001"
    name: "File Test"
    severity: "high"
    category: "exfiltration"
    patterns:
      - 'test_from_file'
    message: "Test"
"#,
        )
        .unwrap();

        let rules = CustomRuleLoader::load_from_file(&file_path).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "FILE-001");
    }

    #[test]
    fn test_load_from_file_not_found() {
        let result = CustomRuleLoader::load_from_file(std::path::Path::new("/nonexistent/file.yaml"));
        assert!(result.is_err());
        assert!(matches!(result, Err(CustomRuleError::IoError(_))));
    }

    #[test]
    fn test_convert_yaml_rules() {
        let yaml_rules = vec![
            YamlRule {
                id: "CONV-001".to_string(),
                name: "Convert Test".to_string(),
                description: "Test".to_string(),
                severity: "high".to_string(),
                category: "exfiltration".to_string(),
                confidence: "firm".to_string(),
                patterns: vec!["test".to_string()],
                exclusions: vec![],
                message: "Test".to_string(),
                recommendation: "".to_string(),
                fix_hint: None,
                cwe: vec![],
            },
        ];

        let rules = CustomRuleLoader::convert_yaml_rules(yaml_rules).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "CONV-001");
    }

    #[test]
    fn test_invalid_confidence() {
        let yaml = r#"
version: "1"
rules:
  - id: "CUSTOM-001"
    name: "Test"
    severity: "high"
    category: "exfiltration"
    confidence: "invalid"
    patterns:
      - 'test'
    message: "Test"
"#;
        let result = CustomRuleLoader::load_from_string(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CustomRuleError::InvalidConfidence { .. }));
    }

    #[test]
    fn test_parse_error_display() {
        let invalid_yaml = "invalid: yaml: [";
        let result: Result<CustomRulesConfig, _> = serde_yaml::from_str(invalid_yaml);
        let yaml_err = result.unwrap_err();
        let err = CustomRuleError::ParseError(yaml_err);
        assert!(err.to_string().contains("Failed to parse"));
    }

    #[test]
    fn test_invalid_pattern_error_display() {
        let regex_err = Regex::new("[invalid(").unwrap_err();
        let err = CustomRuleError::InvalidPattern {
            rule_id: "TEST-001".to_string(),
            pattern: "[invalid(".to_string(),
            error: regex_err,
        };
        let display = err.to_string();
        assert!(display.contains("Invalid regex pattern"));
        assert!(display.contains("[invalid("));
        assert!(display.contains("TEST-001"));
    }

    #[test]
    fn test_invalid_exclusion_regex() {
        let yaml = r#"
version: "1"
rules:
  - id: "CUSTOM-001"
    name: "Test"
    severity: "high"
    category: "exfiltration"
    patterns:
      - 'valid_pattern'
    exclusions:
      - '[invalid('
    message: "Test"
"#;
        let result = CustomRuleLoader::load_from_string(yaml);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CustomRuleError::InvalidPattern { .. }));
    }
}
