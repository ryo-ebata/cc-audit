use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str().to_uppercase())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Exfiltration,
    PrivilegeEscalation,
    Persistence,
    PromptInjection,
    Overpermission,
    Obfuscation,
    SupplyChain,
}

impl Category {
    pub fn as_str(&self) -> &'static str {
        match self {
            Category::Exfiltration => "exfiltration",
            Category::PrivilegeEscalation => "privilege_escalation",
            Category::Persistence => "persistence",
            Category::PromptInjection => "prompt_injection",
            Category::Overpermission => "overpermission",
            Category::Obfuscation => "obfuscation",
            Category::SupplyChain => "supply_chain",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub category: Category,
    pub patterns: Vec<regex::Regex>,
    pub exclusions: Vec<regex::Regex>,
    pub message: &'static str,
    pub recommendation: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub category: Category,
    pub name: String,
    pub location: Location,
    pub code: String,
    pub message: String,
    pub recommendation: String,
}

impl Finding {
    pub fn new(rule: &Rule, location: Location, code: String) -> Self {
        Self {
            id: rule.id.to_string(),
            severity: rule.severity,
            category: rule.category,
            name: rule.name.to_string(),
            location,
            code,
            message: rule.message.to_string(),
            recommendation: rule.recommendation.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub passed: bool,
}

impl Summary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let (critical, high, medium, low) =
            findings
                .iter()
                .fold((0, 0, 0, 0), |(c, h, m, l), f| match f.severity {
                    Severity::Critical => (c + 1, h, m, l),
                    Severity::High => (c, h + 1, m, l),
                    Severity::Medium => (c, h, m + 1, l),
                    Severity::Low => (c, h, m, l + 1),
                });

        Self {
            critical,
            high,
            medium,
            low,
            passed: critical == 0 && high == 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub version: String,
    pub scanned_at: String,
    pub target: String,
    pub summary: Summary,
    pub findings: Vec<Finding>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_as_str() {
        assert_eq!(Severity::Low.as_str(), "low");
        assert_eq!(Severity::Medium.as_str(), "medium");
        assert_eq!(Severity::High.as_str(), "high");
        assert_eq!(Severity::Critical.as_str(), "critical");
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", Severity::Low), "LOW");
        assert_eq!(format!("{}", Severity::Medium), "MEDIUM");
        assert_eq!(format!("{}", Severity::High), "HIGH");
        assert_eq!(format!("{}", Severity::Critical), "CRITICAL");
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_category_as_str() {
        assert_eq!(Category::Exfiltration.as_str(), "exfiltration");
        assert_eq!(
            Category::PrivilegeEscalation.as_str(),
            "privilege_escalation"
        );
        assert_eq!(Category::Persistence.as_str(), "persistence");
        assert_eq!(Category::PromptInjection.as_str(), "prompt_injection");
        assert_eq!(Category::Overpermission.as_str(), "overpermission");
        assert_eq!(Category::Obfuscation.as_str(), "obfuscation");
        assert_eq!(Category::SupplyChain.as_str(), "supply_chain");
    }

    #[test]
    fn test_summary_from_empty_findings() {
        let findings: Vec<Finding> = vec![];
        let summary = Summary::from_findings(&findings);
        assert_eq!(summary.critical, 0);
        assert_eq!(summary.high, 0);
        assert_eq!(summary.medium, 0);
        assert_eq!(summary.low, 0);
        assert!(summary.passed);
    }

    #[test]
    fn test_summary_from_findings_with_critical() {
        let findings = vec![Finding {
            id: "EX-001".to_string(),
            severity: Severity::Critical,
            category: Category::Exfiltration,
            name: "Test".to_string(),
            location: Location {
                file: "test.sh".to_string(),
                line: 1,
                column: None,
            },
            code: "test".to_string(),
            message: "test".to_string(),
            recommendation: "test".to_string(),
        }];
        let summary = Summary::from_findings(&findings);
        assert_eq!(summary.critical, 1);
        assert!(!summary.passed);
    }

    #[test]
    fn test_summary_from_findings_all_severities() {
        let findings = vec![
            Finding {
                id: "C-001".to_string(),
                severity: Severity::Critical,
                category: Category::Exfiltration,
                name: "Critical".to_string(),
                location: Location {
                    file: "test.sh".to_string(),
                    line: 1,
                    column: None,
                },
                code: "test".to_string(),
                message: "test".to_string(),
                recommendation: "test".to_string(),
            },
            Finding {
                id: "H-001".to_string(),
                severity: Severity::High,
                category: Category::PrivilegeEscalation,
                name: "High".to_string(),
                location: Location {
                    file: "test.sh".to_string(),
                    line: 2,
                    column: None,
                },
                code: "test".to_string(),
                message: "test".to_string(),
                recommendation: "test".to_string(),
            },
            Finding {
                id: "M-001".to_string(),
                severity: Severity::Medium,
                category: Category::Persistence,
                name: "Medium".to_string(),
                location: Location {
                    file: "test.sh".to_string(),
                    line: 3,
                    column: Some(5),
                },
                code: "test".to_string(),
                message: "test".to_string(),
                recommendation: "test".to_string(),
            },
            Finding {
                id: "L-001".to_string(),
                severity: Severity::Low,
                category: Category::Overpermission,
                name: "Low".to_string(),
                location: Location {
                    file: "test.sh".to_string(),
                    line: 4,
                    column: None,
                },
                code: "test".to_string(),
                message: "test".to_string(),
                recommendation: "test".to_string(),
            },
        ];
        let summary = Summary::from_findings(&findings);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 1);
        assert_eq!(summary.low, 1);
        assert!(!summary.passed);
    }

    #[test]
    fn test_summary_passes_with_only_medium_low() {
        let findings = vec![
            Finding {
                id: "M-001".to_string(),
                severity: Severity::Medium,
                category: Category::Persistence,
                name: "Medium".to_string(),
                location: Location {
                    file: "test.sh".to_string(),
                    line: 1,
                    column: None,
                },
                code: "test".to_string(),
                message: "test".to_string(),
                recommendation: "test".to_string(),
            },
            Finding {
                id: "L-001".to_string(),
                severity: Severity::Low,
                category: Category::Overpermission,
                name: "Low".to_string(),
                location: Location {
                    file: "test.sh".to_string(),
                    line: 2,
                    column: None,
                },
                code: "test".to_string(),
                message: "test".to_string(),
                recommendation: "test".to_string(),
            },
        ];
        let summary = Summary::from_findings(&findings);
        assert!(summary.passed);
    }

    #[test]
    fn test_finding_new() {
        let rule = Rule {
            id: "TEST-001",
            name: "Test Rule",
            description: "A test rule",
            severity: Severity::High,
            category: Category::Exfiltration,
            patterns: vec![],
            exclusions: vec![],
            message: "Test message",
            recommendation: "Test recommendation",
        };
        let location = Location {
            file: "test.sh".to_string(),
            line: 42,
            column: Some(10),
        };
        let finding = Finding::new(&rule, location, "test code".to_string());

        assert_eq!(finding.id, "TEST-001");
        assert_eq!(finding.name, "Test Rule");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.category, Category::Exfiltration);
        assert_eq!(finding.location.file, "test.sh");
        assert_eq!(finding.location.line, 42);
        assert_eq!(finding.location.column, Some(10));
        assert_eq!(finding.code, "test code");
        assert_eq!(finding.message, "Test message");
        assert_eq!(finding.recommendation, "Test recommendation");
    }

    #[test]
    fn test_severity_serialization() {
        let severity = Severity::Critical;
        let json = serde_json::to_string(&severity).unwrap();
        assert_eq!(json, "\"critical\"");

        let deserialized: Severity = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, Severity::Critical);
    }

    #[test]
    fn test_category_serialization() {
        let category = Category::PromptInjection;
        let json = serde_json::to_string(&category).unwrap();
        assert_eq!(json, "\"promptinjection\"");

        let deserialized: Category = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, Category::PromptInjection);
    }

    #[test]
    fn test_location_without_column_serialization() {
        let location = Location {
            file: "test.sh".to_string(),
            line: 10,
            column: None,
        };
        let json = serde_json::to_string(&location).unwrap();
        assert!(!json.contains("column"));
    }

    #[test]
    fn test_location_with_column_serialization() {
        let location = Location {
            file: "test.sh".to_string(),
            line: 10,
            column: Some(5),
        };
        let json = serde_json::to_string(&location).unwrap();
        assert!(json.contains("\"column\":5"));
    }
}
