//! Detection engine traits for the detection layer (L5).

use crate::parser::ParsedContent;
use crate::rules::{Finding, Severity};
use serde::{Deserialize, Serialize};

/// Configuration for the detection engine.
#[derive(Debug, Clone, Default)]
pub struct EngineConfig {
    /// Enable deobfuscation.
    pub deobfuscate: bool,
    /// Enable malware database scanning.
    pub malware_scan: bool,
    /// Enable CVE database scanning.
    pub cve_scan: bool,
    /// Minimum severity to report.
    pub min_severity: Option<Severity>,
    /// Rules to skip.
    pub skip_rules: Vec<String>,
    /// Context to provide to rules.
    pub context: Option<String>,
}

impl EngineConfig {
    /// Create a new engine config with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable deobfuscation.
    pub fn with_deobfuscation(mut self, enabled: bool) -> Self {
        self.deobfuscate = enabled;
        self
    }

    /// Enable malware scanning.
    pub fn with_malware_scan(mut self, enabled: bool) -> Self {
        self.malware_scan = enabled;
        self
    }

    /// Enable CVE scanning.
    pub fn with_cve_scan(mut self, enabled: bool) -> Self {
        self.cve_scan = enabled;
        self
    }

    /// Set minimum severity.
    pub fn with_min_severity(mut self, severity: Severity) -> Self {
        self.min_severity = Some(severity);
        self
    }

    /// Add rules to skip.
    pub fn skip_rule(mut self, rule_id: &str) -> Self {
        self.skip_rules.push(rule_id.to_string());
        self
    }
}

/// Result of analyzing content with a detection engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Findings from the analysis.
    pub findings: Vec<Finding>,
    /// Whether the content was deobfuscated.
    pub deobfuscated: bool,
    /// Number of rules applied.
    pub rules_applied: usize,
    /// Analysis metadata.
    pub metadata: AnalysisMetadata,
}

/// Metadata about the analysis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisMetadata {
    /// Time taken for analysis in milliseconds.
    pub duration_ms: u64,
    /// Number of patterns matched.
    pub patterns_matched: usize,
    /// Context detected (if any).
    pub detected_context: Option<String>,
}

impl AnalysisResult {
    /// Create a new empty analysis result.
    pub fn empty() -> Self {
        Self {
            findings: Vec::new(),
            deobfuscated: false,
            rules_applied: 0,
            metadata: AnalysisMetadata::default(),
        }
    }

    /// Create a result with findings.
    pub fn with_findings(findings: Vec<Finding>) -> Self {
        Self {
            findings,
            deobfuscated: false,
            rules_applied: 0,
            metadata: AnalysisMetadata::default(),
        }
    }

    /// Check if any findings were detected.
    pub fn has_findings(&self) -> bool {
        !self.findings.is_empty()
    }

    /// Get the highest severity finding.
    pub fn highest_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}

/// Trait for detection engines (L5).
///
/// Each engine analyzes parsed content and produces findings.
/// Engines can be composed together for comprehensive analysis.
pub trait DetectionEngine: Send + Sync {
    /// Analyze parsed content and return findings.
    fn analyze(&self, content: &ParsedContent, config: &EngineConfig) -> AnalysisResult;

    /// Get the name of this engine.
    fn name(&self) -> &str;

    /// Check if this engine can analyze the given content type.
    fn can_analyze(&self, content: &ParsedContent) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_config_builder() {
        let config = EngineConfig::new()
            .with_deobfuscation(true)
            .with_malware_scan(true)
            .skip_rule("PI-001");

        assert!(config.deobfuscate);
        assert!(config.malware_scan);
        assert!(config.skip_rules.contains(&"PI-001".to_string()));
    }

    #[test]
    fn test_analysis_result_empty() {
        let result = AnalysisResult::empty();
        assert!(!result.has_findings());
        assert!(result.highest_severity().is_none());
    }

    #[test]
    fn test_analysis_result_with_findings() {
        use crate::rules::{Category, Confidence, Location};

        let finding = Finding {
            id: "TEST-001".to_string(),
            severity: Severity::Medium,
            category: Category::PromptInjection,
            confidence: Confidence::Firm,
            name: "Test Finding".to_string(),
            location: Location {
                file: "test.md".to_string(),
                line: 1,
                column: None,
            },
            code: "test code".to_string(),
            message: "Test finding message".to_string(),
            recommendation: "Fix it".to_string(),
            fix_hint: None,
            cwe_ids: Vec::new(),
            rule_severity: None,
            client: None,
            context: None,
        };

        let result = AnalysisResult::with_findings(vec![finding]);
        assert!(result.has_findings());
        assert_eq!(result.highest_severity(), Some(Severity::Medium));
    }
}
