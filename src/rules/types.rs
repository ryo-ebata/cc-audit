use crate::scoring::RiskScore;
use serde::{Deserialize, Serialize};

/// Error type for parsing enum values from strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseEnumError {
    type_name: &'static str,
    value: String,
}

impl ParseEnumError {
    pub fn invalid(type_name: &'static str, value: &str) -> Self {
        Self {
            type_name,
            value: value.to_string(),
        }
    }
}

impl std::fmt::Display for ParseEnumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid {} value: '{}'", self.type_name, self.value)
    }
}

impl std::error::Error for ParseEnumError {}

/// Rule severity level - determines how findings affect CI exit code.
/// This is separate from detection Severity (Critical/High/Medium/Low).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Default,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum RuleSeverity {
    /// Warning: Report only, does not cause CI failure (exit 0)
    Warn,
    /// Error: Causes CI failure (exit 1)
    #[default]
    Error,
}

impl RuleSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleSeverity::Warn => "warn",
            RuleSeverity::Error => "error",
        }
    }
}

impl std::fmt::Display for RuleSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str().to_uppercase())
    }
}

impl std::str::FromStr for RuleSeverity {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "warn" | "warning" => Ok(RuleSeverity::Warn),
            "error" | "err" => Ok(RuleSeverity::Error),
            _ => Err(ParseEnumError::invalid("RuleSeverity", s)),
        }
    }
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Confidence level for findings. Higher confidence means less likely to be a false positive.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    Default,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Tentative: May be a false positive, requires review
    Tentative,
    /// Firm: Likely a real issue, but context-dependent
    #[default]
    Firm,
    /// Certain: Very high confidence, unlikely to be a false positive
    Certain,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Confidence::Tentative => "tentative",
            Confidence::Firm => "firm",
            Confidence::Certain => "certain",
        }
    }

    /// Downgrade the confidence level by one step.
    ///
    /// Used to reduce confidence when heuristics suggest a potential false positive
    /// (e.g., detecting secrets in test files or dummy variable names).
    ///
    /// - Certain -> Firm
    /// - Firm -> Tentative
    /// - Tentative -> Tentative (minimum level)
    pub fn downgrade(&self) -> Self {
        match self {
            Confidence::Certain => Confidence::Firm,
            Confidence::Firm => Confidence::Tentative,
            Confidence::Tentative => Confidence::Tentative,
        }
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Confidence {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tentative" => Ok(Confidence::Tentative),
            "firm" => Ok(Confidence::Firm),
            "certain" => Ok(Confidence::Certain),
            _ => Err(ParseEnumError::invalid("Confidence", s)),
        }
    }
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

impl std::str::FromStr for Severity {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Severity::Low),
            "medium" | "med" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" | "crit" => Ok(Severity::Critical),
            _ => Err(ParseEnumError::invalid("Severity", s)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Exfiltration,
    PrivilegeEscalation,
    Persistence,
    PromptInjection,
    Overpermission,
    Obfuscation,
    SupplyChain,
    SecretLeak,
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
            Category::SecretLeak => "secret_leak",
        }
    }
}

impl std::str::FromStr for Category {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace(['_', '-'], "").as_str() {
            "exfiltration" | "exfil" => Ok(Category::Exfiltration),
            "privilegeescalation" | "privesc" => Ok(Category::PrivilegeEscalation),
            "persistence" => Ok(Category::Persistence),
            "promptinjection" => Ok(Category::PromptInjection),
            "overpermission" => Ok(Category::Overpermission),
            "obfuscation" => Ok(Category::Obfuscation),
            "supplychain" => Ok(Category::SupplyChain),
            "secretleak" => Ok(Category::SecretLeak),
            _ => Err(ParseEnumError::invalid("Category", s)),
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
    pub confidence: Confidence,
    pub patterns: Vec<regex::Regex>,
    pub exclusions: Vec<regex::Regex>,
    pub message: &'static str,
    pub recommendation: &'static str,
    /// Optional concrete fix hint (e.g., command to run, code pattern to use)
    pub fix_hint: Option<&'static str>,
    /// CWE IDs associated with this rule (e.g., ["CWE-200", "CWE-78"])
    pub cwe_ids: &'static [&'static str],
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
    pub confidence: Confidence,
    pub name: String,
    pub location: Location,
    pub code: String,
    pub message: String,
    pub recommendation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix_hint: Option<String>,
    /// CWE IDs associated with this finding
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cwe_ids: Vec<String>,
    /// Rule severity level (error/warn) - determines CI exit code behavior.
    /// This is assigned based on configuration, not the rule definition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_severity: Option<RuleSeverity>,
    /// AI client that owns this configuration (Claude, Cursor, Windsurf, VS Code).
    /// Set when scanning with --all-clients or --client options.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// Content context (documentation, code block, etc.) for false positive reduction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<crate::context::ContentContext>,
}

impl Finding {
    pub fn new(rule: &Rule, location: Location, code: String) -> Self {
        Self {
            id: rule.id.to_string(),
            severity: rule.severity,
            category: rule.category,
            confidence: rule.confidence,
            name: rule.name.to_string(),
            location,
            code,
            message: rule.message.to_string(),
            recommendation: rule.recommendation.to_string(),
            fix_hint: rule.fix_hint.map(|s| s.to_string()),
            cwe_ids: rule.cwe_ids.iter().map(|s| s.to_string()).collect(),
            rule_severity: None, // Assigned later based on config
            client: None,        // Assigned later for client scans
            context: None,       // Assigned by context-aware scanner
        }
    }

    /// Set the content context for this finding
    pub fn with_context(mut self, context: crate::context::ContentContext) -> Self {
        self.context = Some(context);
        self
    }

    /// Set the client for this finding
    pub fn with_client(mut self, client: Option<String>) -> Self {
        self.client = client;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub passed: bool,
    /// Number of findings with RuleSeverity::Error
    #[serde(default)]
    pub errors: usize,
    /// Number of findings with RuleSeverity::Warn
    #[serde(default)]
    pub warnings: usize,
}

impl Summary {
    /// Creates a Summary from findings.
    /// Note: This method does not set errors/warnings counts.
    /// Use `from_findings_with_rule_severity` when rule_severity is assigned.
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
            errors: 0,
            warnings: 0,
        }
    }

    /// Creates a Summary from findings with rule_severity counts.
    /// The `passed` field is determined by whether there are any errors.
    pub fn from_findings_with_rule_severity(findings: &[Finding]) -> Self {
        let (critical, high, medium, low, errors, warnings) =
            findings
                .iter()
                .fold((0, 0, 0, 0, 0, 0), |(c, h, m, l, e, w), f| {
                    let (new_c, new_h, new_m, new_l) = match f.severity {
                        Severity::Critical => (c + 1, h, m, l),
                        Severity::High => (c, h + 1, m, l),
                        Severity::Medium => (c, h, m + 1, l),
                        Severity::Low => (c, h, m, l + 1),
                    };
                    let (new_e, new_w) = match f.rule_severity {
                        Some(RuleSeverity::Error) | None => (e + 1, w), // Default to error
                        Some(RuleSeverity::Warn) => (e, w + 1),
                    };
                    (new_c, new_h, new_m, new_l, new_e, new_w)
                });

        Self {
            critical,
            high,
            medium,
            low,
            passed: errors == 0, // Pass only if no errors
            errors,
            warnings,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_score: Option<RiskScore>,
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
        assert_eq!(Category::SecretLeak.as_str(), "secret_leak");
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
            confidence: Confidence::Certain,
            name: "Test".to_string(),
            location: Location {
                file: "test.sh".to_string(),
                line: 1,
                column: None,
            },
            code: "test".to_string(),
            message: "test".to_string(),
            recommendation: "test".to_string(),
            fix_hint: None,
            cwe_ids: vec![],
            rule_severity: None,
            client: None,
            context: None,
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
                confidence: Confidence::Certain,
                name: "Critical".to_string(),
                location: Location {
                    file: "test.sh".to_string(),
                    line: 1,
                    column: None,
                },
                code: "test".to_string(),
                message: "test".to_string(),
                recommendation: "test".to_string(),
                fix_hint: None,
                cwe_ids: vec![],
                rule_severity: None,
                client: None,
                context: None,
            },
            Finding {
                id: "H-001".to_string(),
                severity: Severity::High,
                category: Category::PrivilegeEscalation,
                confidence: Confidence::Firm,
                name: "High".to_string(),
                location: Location {
                    file: "test.sh".to_string(),
                    line: 2,
                    column: None,
                },
                code: "test".to_string(),
                message: "test".to_string(),
                recommendation: "test".to_string(),
                fix_hint: None,
                cwe_ids: vec![],
                rule_severity: None,
                client: None,
                context: None,
            },
            Finding {
                id: "M-001".to_string(),
                severity: Severity::Medium,
                category: Category::Persistence,
                confidence: Confidence::Tentative,
                name: "Medium".to_string(),
                location: Location {
                    file: "test.sh".to_string(),
                    line: 3,
                    column: Some(5),
                },
                code: "test".to_string(),
                message: "test".to_string(),
                recommendation: "test".to_string(),
                fix_hint: None,
                cwe_ids: vec![],
                rule_severity: None,
                client: None,
                context: None,
            },
            Finding {
                id: "L-001".to_string(),
                severity: Severity::Low,
                category: Category::Overpermission,
                confidence: Confidence::Firm,
                name: "Low".to_string(),
                location: Location {
                    file: "test.sh".to_string(),
                    line: 4,
                    column: None,
                },
                code: "test".to_string(),
                message: "test".to_string(),
                recommendation: "test".to_string(),
                fix_hint: None,
                cwe_ids: vec![],
                rule_severity: None,
                client: None,
                context: None,
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
                confidence: Confidence::Firm,
                name: "Medium".to_string(),
                location: Location {
                    file: "test.sh".to_string(),
                    line: 1,
                    column: None,
                },
                code: "test".to_string(),
                message: "test".to_string(),
                recommendation: "test".to_string(),
                fix_hint: None,
                cwe_ids: vec![],
                rule_severity: None,
                client: None,
                context: None,
            },
            Finding {
                id: "L-001".to_string(),
                severity: Severity::Low,
                category: Category::Overpermission,
                confidence: Confidence::Firm,
                name: "Low".to_string(),
                location: Location {
                    file: "test.sh".to_string(),
                    line: 2,
                    column: None,
                },
                code: "test".to_string(),
                message: "test".to_string(),
                recommendation: "test".to_string(),
                fix_hint: None,
                cwe_ids: vec![],
                rule_severity: None,
                client: None,
                context: None,
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
            confidence: Confidence::Certain,
            patterns: vec![],
            exclusions: vec![],
            message: "Test message",
            recommendation: "Test recommendation",
            fix_hint: Some("Test fix hint"),
            cwe_ids: &["CWE-200", "CWE-78"],
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
        assert_eq!(finding.confidence, Confidence::Certain);
        assert_eq!(finding.location.file, "test.sh");
        assert_eq!(finding.location.line, 42);
        assert_eq!(finding.location.column, Some(10));
        assert_eq!(finding.code, "test code");
        assert_eq!(finding.message, "Test message");
        assert_eq!(finding.recommendation, "Test recommendation");
        assert_eq!(finding.cwe_ids, vec!["CWE-200", "CWE-78"]);
    }

    #[test]
    fn test_confidence_as_str() {
        assert_eq!(Confidence::Tentative.as_str(), "tentative");
        assert_eq!(Confidence::Firm.as_str(), "firm");
        assert_eq!(Confidence::Certain.as_str(), "certain");
    }

    #[test]
    fn test_confidence_display() {
        assert_eq!(format!("{}", Confidence::Tentative), "tentative");
        assert_eq!(format!("{}", Confidence::Firm), "firm");
        assert_eq!(format!("{}", Confidence::Certain), "certain");
    }

    #[test]
    fn test_confidence_downgrade() {
        // Certain -> Firm
        assert_eq!(Confidence::Certain.downgrade(), Confidence::Firm);
        // Firm -> Tentative
        assert_eq!(Confidence::Firm.downgrade(), Confidence::Tentative);
        // Tentative -> Tentative (minimum level)
        assert_eq!(Confidence::Tentative.downgrade(), Confidence::Tentative);
    }

    #[test]
    fn test_confidence_downgrade_twice() {
        // Double downgrade: Certain -> Firm -> Tentative
        let confidence = Confidence::Certain;
        let downgraded_once = confidence.downgrade();
        let downgraded_twice = downgraded_once.downgrade();
        assert_eq!(downgraded_twice, Confidence::Tentative);
    }

    #[test]
    fn test_confidence_ordering() {
        assert!(Confidence::Tentative < Confidence::Firm);
        assert!(Confidence::Firm < Confidence::Certain);
    }

    #[test]
    fn test_confidence_default() {
        assert_eq!(Confidence::default(), Confidence::Firm);
    }

    #[test]
    fn test_confidence_serialization() {
        let confidence = Confidence::Certain;
        let json = serde_json::to_string(&confidence).unwrap();
        assert_eq!(json, "\"certain\"");

        let deserialized: Confidence = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, Confidence::Certain);
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

    // ========== RuleSeverity Tests ==========

    #[test]
    fn test_rule_severity_default_is_error() {
        assert_eq!(RuleSeverity::default(), RuleSeverity::Error);
    }

    #[test]
    fn test_rule_severity_as_str() {
        assert_eq!(RuleSeverity::Error.as_str(), "error");
        assert_eq!(RuleSeverity::Warn.as_str(), "warn");
    }

    #[test]
    fn test_rule_severity_display() {
        assert_eq!(format!("{}", RuleSeverity::Error), "ERROR");
        assert_eq!(format!("{}", RuleSeverity::Warn), "WARN");
    }

    #[test]
    fn test_rule_severity_ordering() {
        // Warn < Error (warn is less severe)
        assert!(RuleSeverity::Warn < RuleSeverity::Error);
    }

    #[test]
    fn test_rule_severity_serialization() {
        let error = RuleSeverity::Error;
        let json = serde_json::to_string(&error).unwrap();
        assert_eq!(json, "\"error\"");

        let warn = RuleSeverity::Warn;
        let json = serde_json::to_string(&warn).unwrap();
        assert_eq!(json, "\"warn\"");

        let deserialized: RuleSeverity = serde_json::from_str("\"error\"").unwrap();
        assert_eq!(deserialized, RuleSeverity::Error);

        let deserialized: RuleSeverity = serde_json::from_str("\"warn\"").unwrap();
        assert_eq!(deserialized, RuleSeverity::Warn);
    }

    // ========== Summary with RuleSeverity Tests ==========

    fn create_test_finding(
        id: &str,
        severity: Severity,
        rule_severity: Option<RuleSeverity>,
    ) -> Finding {
        Finding {
            id: id.to_string(),
            severity,
            category: Category::Exfiltration,
            confidence: Confidence::Firm,
            name: "Test".to_string(),
            location: Location {
                file: "test.sh".to_string(),
                line: 1,
                column: None,
            },
            code: "test".to_string(),
            message: "test".to_string(),
            recommendation: "test".to_string(),
            fix_hint: None,
            cwe_ids: vec![],
            rule_severity,
            client: None,
            context: None,
        }
    }

    #[test]
    fn test_summary_with_rule_severity_empty() {
        let findings: Vec<Finding> = vec![];
        let summary = Summary::from_findings_with_rule_severity(&findings);
        assert_eq!(summary.errors, 0);
        assert_eq!(summary.warnings, 0);
        assert!(summary.passed);
    }

    #[test]
    fn test_summary_with_rule_severity_all_errors() {
        let findings = vec![
            create_test_finding("E-001", Severity::Critical, Some(RuleSeverity::Error)),
            create_test_finding("E-002", Severity::High, Some(RuleSeverity::Error)),
        ];
        let summary = Summary::from_findings_with_rule_severity(&findings);
        assert_eq!(summary.errors, 2);
        assert_eq!(summary.warnings, 0);
        assert!(!summary.passed);
    }

    #[test]
    fn test_summary_with_rule_severity_all_warnings() {
        let findings = vec![
            create_test_finding("W-001", Severity::Critical, Some(RuleSeverity::Warn)),
            create_test_finding("W-002", Severity::High, Some(RuleSeverity::Warn)),
        ];
        let summary = Summary::from_findings_with_rule_severity(&findings);
        assert_eq!(summary.errors, 0);
        assert_eq!(summary.warnings, 2);
        assert!(summary.passed); // No errors, so passed
    }

    #[test]
    fn test_summary_with_rule_severity_mixed() {
        let findings = vec![
            create_test_finding("E-001", Severity::Critical, Some(RuleSeverity::Error)),
            create_test_finding("W-001", Severity::High, Some(RuleSeverity::Warn)),
            create_test_finding("W-002", Severity::Medium, Some(RuleSeverity::Warn)),
        ];
        let summary = Summary::from_findings_with_rule_severity(&findings);
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.warnings, 2);
        assert!(!summary.passed); // Has errors, so failed
        // Also check severity counts
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.medium, 1);
    }

    #[test]
    fn test_summary_with_rule_severity_none_defaults_to_error() {
        let findings = vec![
            create_test_finding("N-001", Severity::Low, None), // None defaults to Error
        ];
        let summary = Summary::from_findings_with_rule_severity(&findings);
        assert_eq!(summary.errors, 1);
        assert_eq!(summary.warnings, 0);
        assert!(!summary.passed);
    }

    #[test]
    fn test_finding_rule_severity_not_serialized_when_none() {
        let finding = create_test_finding("TEST-001", Severity::High, None);
        let json = serde_json::to_string(&finding).unwrap();
        assert!(!json.contains("rule_severity"));
    }

    #[test]
    fn test_finding_rule_severity_serialized_when_some() {
        let finding = create_test_finding("TEST-001", Severity::High, Some(RuleSeverity::Warn));
        let json = serde_json::to_string(&finding).unwrap();
        assert!(json.contains("\"rule_severity\":\"warn\""));
    }

    // ========== ParseEnumError Tests ==========

    #[test]
    fn test_parse_enum_error_invalid() {
        let error = ParseEnumError::invalid("TestType", "bad_value");
        assert_eq!(error.type_name, "TestType");
        assert_eq!(error.value, "bad_value");
    }

    #[test]
    fn test_parse_enum_error_display() {
        let error = ParseEnumError::invalid("RuleSeverity", "unknown");
        let display = format!("{}", error);
        assert_eq!(display, "invalid RuleSeverity value: 'unknown'");
    }

    #[test]
    fn test_parse_enum_error_debug() {
        let error = ParseEnumError::invalid("TestType", "value");
        let debug = format!("{:?}", error);
        assert!(debug.contains("ParseEnumError"));
        assert!(debug.contains("TestType"));
        assert!(debug.contains("value"));
    }

    #[test]
    fn test_parse_enum_error_is_error() {
        let error = ParseEnumError::invalid("Test", "val");
        // Verify it implements std::error::Error
        let _: &dyn std::error::Error = &error;
    }

    // ========== RuleSeverity FromStr Tests ==========

    #[test]
    fn test_rule_severity_from_str_valid() {
        use std::str::FromStr;

        // Standard names
        assert_eq!(RuleSeverity::from_str("warn").unwrap(), RuleSeverity::Warn);
        assert_eq!(
            RuleSeverity::from_str("error").unwrap(),
            RuleSeverity::Error
        );

        // Alternate names
        assert_eq!(
            RuleSeverity::from_str("warning").unwrap(),
            RuleSeverity::Warn
        );
        assert_eq!(RuleSeverity::from_str("err").unwrap(), RuleSeverity::Error);

        // Case insensitive
        assert_eq!(RuleSeverity::from_str("WARN").unwrap(), RuleSeverity::Warn);
        assert_eq!(
            RuleSeverity::from_str("ERROR").unwrap(),
            RuleSeverity::Error
        );
        assert_eq!(
            RuleSeverity::from_str("Warning").unwrap(),
            RuleSeverity::Warn
        );
    }

    #[test]
    fn test_rule_severity_from_str_invalid() {
        use std::str::FromStr;

        let result = RuleSeverity::from_str("invalid");
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.type_name, "RuleSeverity");
        assert_eq!(error.value, "invalid");

        // Empty string
        let result = RuleSeverity::from_str("");
        assert!(result.is_err());

        // Random value
        let result = RuleSeverity::from_str("critical");
        assert!(result.is_err());
    }
}
