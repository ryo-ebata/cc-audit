use crate::rules::{Category, Finding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Risk score configuration
const CRITICAL_WEIGHT: u32 = 40;
const HIGH_WEIGHT: u32 = 20;
const MEDIUM_WEIGHT: u32 = 10;
const LOW_WEIGHT: u32 = 5;
const MAX_SCORE: u32 = 100;

/// Risk level based on score
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Safe,
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn from_score(score: u32) -> Self {
        match score {
            0 => RiskLevel::Safe,
            1..=25 => RiskLevel::Low,
            26..=50 => RiskLevel::Medium,
            51..=75 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Safe => "SAFE",
            RiskLevel::Low => "LOW",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::High => "HIGH",
            RiskLevel::Critical => "CRITICAL",
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Score breakdown by category
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryScore {
    pub category: String,
    pub score: u32,
    pub findings_count: usize,
}

/// Complete risk score result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScore {
    /// Total risk score (0-100)
    pub total: u32,
    /// Risk level classification
    pub level: RiskLevel,
    /// Score breakdown by category
    pub by_category: Vec<CategoryScore>,
    /// Score breakdown by severity
    pub by_severity: SeverityBreakdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeverityBreakdown {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

impl RiskScore {
    /// Calculate risk score from findings
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut category_scores: HashMap<Category, (u32, usize)> = HashMap::new();
        let mut severity_scores = SeverityBreakdown {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };

        for finding in findings {
            let weight = match finding.severity {
                Severity::Critical => {
                    severity_scores.critical += CRITICAL_WEIGHT;
                    CRITICAL_WEIGHT
                }
                Severity::High => {
                    severity_scores.high += HIGH_WEIGHT;
                    HIGH_WEIGHT
                }
                Severity::Medium => {
                    severity_scores.medium += MEDIUM_WEIGHT;
                    MEDIUM_WEIGHT
                }
                Severity::Low => {
                    severity_scores.low += LOW_WEIGHT;
                    LOW_WEIGHT
                }
            };

            let entry = category_scores.entry(finding.category).or_insert((0, 0));
            entry.0 += weight;
            entry.1 += 1;
        }

        // Calculate total raw score
        let raw_total: u32 = category_scores.values().map(|(s, _)| *s).sum();

        // Cap at MAX_SCORE
        let total = raw_total.min(MAX_SCORE);

        // Build category breakdown
        let mut by_category: Vec<CategoryScore> = category_scores
            .into_iter()
            .map(|(cat, (score, count))| CategoryScore {
                category: cat.as_str().to_string(),
                score: score.min(MAX_SCORE),
                findings_count: count,
            })
            .collect();

        // Sort by score descending
        by_category.sort_by(|a, b| b.score.cmp(&a.score));

        RiskScore {
            total,
            level: RiskLevel::from_score(total),
            by_category,
            by_severity: severity_scores,
        }
    }

    /// Generate a visual bar for score (10 chars wide)
    pub fn score_bar(&self, score: u32, max: u32) -> String {
        let filled = ((score as f32 / max as f32) * 10.0).round() as usize;
        let filled = filled.min(10);
        let empty = 10 - filled;
        format!("{}{}", "█".repeat(filled), "░".repeat(empty))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Confidence, Location};

    fn create_test_finding(severity: Severity, category: Category) -> Finding {
        Finding {
            id: "TEST-001".to_string(),
            severity,
            category,
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
            rule_severity: None,
            client: None,
        }
    }

    #[test]
    fn test_empty_findings_safe() {
        let score = RiskScore::from_findings(&[]);
        assert_eq!(score.total, 0);
        assert_eq!(score.level, RiskLevel::Safe);
    }

    #[test]
    fn test_single_critical_finding() {
        let findings = vec![create_test_finding(
            Severity::Critical,
            Category::Exfiltration,
        )];
        let score = RiskScore::from_findings(&findings);
        assert_eq!(score.total, 40);
        assert_eq!(score.level, RiskLevel::Medium);
    }

    #[test]
    fn test_multiple_findings_caps_at_100() {
        let findings = vec![
            create_test_finding(Severity::Critical, Category::Exfiltration),
            create_test_finding(Severity::Critical, Category::PrivilegeEscalation),
            create_test_finding(Severity::Critical, Category::Persistence),
        ];
        let score = RiskScore::from_findings(&findings);
        assert_eq!(score.total, 100);
        assert_eq!(score.level, RiskLevel::Critical);
    }

    #[test]
    fn test_risk_level_boundaries() {
        assert_eq!(RiskLevel::from_score(0), RiskLevel::Safe);
        assert_eq!(RiskLevel::from_score(1), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(25), RiskLevel::Low);
        assert_eq!(RiskLevel::from_score(26), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(50), RiskLevel::Medium);
        assert_eq!(RiskLevel::from_score(51), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(75), RiskLevel::High);
        assert_eq!(RiskLevel::from_score(76), RiskLevel::Critical);
        assert_eq!(RiskLevel::from_score(100), RiskLevel::Critical);
    }

    #[test]
    fn test_category_breakdown() {
        let findings = vec![
            create_test_finding(Severity::Critical, Category::Exfiltration),
            create_test_finding(Severity::High, Category::Exfiltration),
            create_test_finding(Severity::Medium, Category::Persistence),
        ];
        let score = RiskScore::from_findings(&findings);

        assert_eq!(score.by_category.len(), 2);
        // Exfiltration should be first (higher score)
        assert_eq!(score.by_category[0].category, "exfiltration");
        assert_eq!(score.by_category[0].score, 60); // 40 + 20
        assert_eq!(score.by_category[0].findings_count, 2);
    }

    #[test]
    fn test_severity_breakdown() {
        let findings = vec![
            create_test_finding(Severity::Critical, Category::Exfiltration),
            create_test_finding(Severity::High, Category::PrivilegeEscalation),
            create_test_finding(Severity::Medium, Category::Persistence),
            create_test_finding(Severity::Low, Category::Overpermission),
        ];
        let score = RiskScore::from_findings(&findings);

        assert_eq!(score.by_severity.critical, 40);
        assert_eq!(score.by_severity.high, 20);
        assert_eq!(score.by_severity.medium, 10);
        assert_eq!(score.by_severity.low, 5);
    }

    #[test]
    fn test_score_bar() {
        let score = RiskScore::from_findings(&[]);
        assert_eq!(score.score_bar(0, 100), "░░░░░░░░░░");
        assert_eq!(score.score_bar(50, 100), "█████░░░░░");
        assert_eq!(score.score_bar(100, 100), "██████████");
        assert_eq!(score.score_bar(75, 100), "████████░░");
    }

    #[test]
    fn test_risk_level_display() {
        assert_eq!(format!("{}", RiskLevel::Safe), "SAFE");
        assert_eq!(format!("{}", RiskLevel::Critical), "CRITICAL");
    }
}
