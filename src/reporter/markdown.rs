//! Markdown reporter for scan results
//!
//! Generates a human-readable Markdown report suitable for
//! GitHub issues, pull requests, and documentation.

use crate::reporter::Reporter;
use crate::rules::{Confidence, RuleSeverity, ScanResult, Severity};
use crate::scoring::RiskLevel;

pub struct MarkdownReporter {
    include_badge: bool,
}

impl MarkdownReporter {
    pub fn new() -> Self {
        Self {
            include_badge: false,
        }
    }

    pub fn with_badge(mut self) -> Self {
        self.include_badge = true;
        self
    }

    fn severity_emoji(&self, severity: &Severity) -> &'static str {
        match severity {
            Severity::Critical => "\u{1F6A8}",    // 🚨
            Severity::High => "\u{26A0}\u{FE0F}", // ⚠️
            Severity::Medium => "\u{1F7E1}",      // 🟡
            Severity::Low => "\u{1F535}",         // 🔵
        }
    }

    fn confidence_label(&self, confidence: &Confidence) -> &'static str {
        match confidence {
            Confidence::Certain => "Certain",
            Confidence::Firm => "Firm",
            Confidence::Tentative => "Tentative",
        }
    }

    fn rule_severity_label(&self, rule_severity: &Option<RuleSeverity>) -> &'static str {
        match rule_severity {
            Some(RuleSeverity::Error) | None => "ERROR",
            Some(RuleSeverity::Warn) => "WARN",
        }
    }

    fn risk_level_emoji(&self, level: &RiskLevel) -> &'static str {
        match level {
            RiskLevel::Safe => "\u{2705}",      // ✅
            RiskLevel::Low => "\u{1F7E2}",      // 🟢
            RiskLevel::Medium => "\u{1F7E1}",   // 🟡
            RiskLevel::High => "\u{1F7E0}",     // 🟠
            RiskLevel::Critical => "\u{1F534}", // 🔴
        }
    }

    fn format_badge(&self, result: &ScanResult) -> String {
        if !self.include_badge {
            return String::new();
        }

        let (status, color) = if result.summary.critical == 0 && result.summary.high == 0 {
            if result.summary.medium == 0 && result.summary.low == 0 {
                ("verified", "brightgreen")
            } else {
                ("warning", "yellow")
            }
        } else {
            ("failed", "red")
        };

        let badge_url = format!(
            "https://img.shields.io/badge/cc--audit-{}-{}",
            status, color
        );

        let mut output = format!(
            "[![cc-audit]({})](https://github.com/ryo-ebata/cc-audit)\n\n",
            badge_url
        );

        // Add HTML comment with scan metadata
        let total_findings = result.summary.critical
            + result.summary.high
            + result.summary.medium
            + result.summary.low;

        output.push_str("<!-- cc-audit scan results\n");
        output.push_str(&format!("Version: {}\n", env!("CARGO_PKG_VERSION")));
        output.push_str(&format!(
            "Result: {} ({} critical, {} high, {} medium, {} low)\n",
            if result.summary.critical == 0 && result.summary.high == 0 {
                "PASS"
            } else {
                "FAIL"
            },
            result.summary.critical,
            result.summary.high,
            result.summary.medium,
            result.summary.low
        ));
        if let Some(ref score) = result.risk_score {
            output.push_str(&format!("Risk Score: {}/100\n", score.total));
        }
        output.push_str(&format!("Total Findings: {}\n", total_findings));
        output.push_str("-->\n\n");

        output
    }

    fn format_summary(&self, result: &ScanResult) -> String {
        let mut output = String::new();
        let total_findings = result.summary.critical
            + result.summary.high
            + result.summary.medium
            + result.summary.low;

        output.push_str("## Summary\n\n");
        output.push_str("| Metric | Count |\n");
        output.push_str("|--------|-------|\n");
        output.push_str(&format!("| Total findings | {} |\n", total_findings));
        output.push_str(&format!(
            "| \u{1F6A8} Critical | {} |\n",
            result.summary.critical
        ));
        output.push_str(&format!(
            "| \u{26A0}\u{FE0F} High | {} |\n",
            result.summary.high
        ));
        output.push_str(&format!(
            "| \u{1F7E1} Medium | {} |\n",
            result.summary.medium
        ));
        output.push_str(&format!("| \u{1F535} Low | {} |\n", result.summary.low));

        if result.summary.errors > 0 || result.summary.warnings > 0 {
            output.push_str(&format!("| Errors | {} |\n", result.summary.errors));
            output.push_str(&format!("| Warnings | {} |\n", result.summary.warnings));
        }

        output.push('\n');
        output
    }

    fn format_risk_score(&self, result: &ScanResult) -> String {
        let mut output = String::new();

        if let Some(ref score) = result.risk_score {
            output.push_str("## Risk Score\n\n");
            output.push_str(&format!(
                "{} **{}/100** - {}\n\n",
                self.risk_level_emoji(&score.level),
                score.total,
                score.level.as_str()
            ));

            if !score.by_category.is_empty() {
                output.push_str("### Category Breakdown\n\n");
                output.push_str("| Category | Score | Findings |\n");
                output.push_str("|----------|-------|----------|\n");
                for cat_score in &score.by_category {
                    let bar = self.format_score_bar(cat_score.score, 100);
                    output.push_str(&format!(
                        "| {} | {} {} | {} |\n",
                        cat_score.category, cat_score.score, bar, cat_score.findings_count
                    ));
                }
                output.push('\n');
            }
        }

        output
    }

    fn format_score_bar(&self, score: u32, max: u32) -> String {
        let filled = ((score as f64 / max as f64) * 10.0).round() as usize;
        let empty = 10 - filled;
        format!(
            "`{}{}`",
            "\u{2588}".repeat(filled),
            "\u{2591}".repeat(empty)
        )
    }

    fn format_findings(&self, result: &ScanResult) -> String {
        if result.findings.is_empty() {
            return String::from("## Findings\n\n\u{2705} No security issues found.\n\n");
        }

        let mut output = String::new();
        output.push_str("## Findings\n\n");

        output.push_str("| Severity | ID | Rule | File | Line | Confidence |\n");
        output.push_str("|----------|-----|------|------|------|------------|\n");

        for finding in &result.findings {
            output.push_str(&format!(
                "| {} {} | `{}` | {} | `{}` | {} | {} |\n",
                self.severity_emoji(&finding.severity),
                self.rule_severity_label(&finding.rule_severity),
                finding.id,
                finding.name,
                finding.location.file,
                finding.location.line,
                self.confidence_label(&finding.confidence)
            ));
        }

        output.push('\n');

        // Detailed findings
        output.push_str("### Details\n\n");
        for (i, finding) in result.findings.iter().enumerate() {
            output.push_str(&format!(
                "<details>\n<summary>{} <strong>{}</strong>: {} ({}:{})</summary>\n\n",
                self.severity_emoji(&finding.severity),
                finding.id,
                finding.name,
                finding.location.file,
                finding.location.line
            ));

            output.push_str(&format!("**Description:** {}\n\n", finding.message));
            output.push_str(&format!("**Severity:** {:?}\n\n", finding.severity));
            output.push_str(&format!(
                "**Confidence:** {}\n\n",
                self.confidence_label(&finding.confidence)
            ));

            if !finding.code.is_empty() {
                output.push_str("**Matched code:**\n```\n");
                output.push_str(&finding.code);
                output.push_str("\n```\n\n");
            }

            if !finding.recommendation.is_empty() {
                output.push_str(&format!(
                    "**Recommendation:** {}\n\n",
                    finding.recommendation
                ));
            }

            output.push_str("</details>\n\n");

            // Add separator between findings except for the last one
            if i < result.findings.len() - 1 {
                output.push_str("---\n\n");
            }
        }

        output
    }

    fn format_recommendations(&self, result: &ScanResult) -> String {
        let mut recommendations: Vec<&str> = result
            .findings
            .iter()
            .filter(|f| !f.recommendation.is_empty())
            .map(|f| f.recommendation.as_str())
            .collect();

        recommendations.sort();
        recommendations.dedup();

        if recommendations.is_empty() {
            return String::new();
        }

        let mut output = String::new();
        output.push_str("## Recommendations\n\n");
        for rec in recommendations {
            output.push_str(&format!("- {}\n", rec));
        }
        output.push('\n');

        output
    }

    fn format_footer(&self) -> String {
        format!(
            "---\n\n*Generated by [cc-audit](https://github.com/ryo-ebata/cc-audit) v{}*\n",
            env!("CARGO_PKG_VERSION")
        )
    }
}

impl Default for MarkdownReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for MarkdownReporter {
    fn report(&self, result: &ScanResult) -> String {
        let mut output = String::new();

        // Badge (if enabled)
        output.push_str(&self.format_badge(result));

        // Title
        output.push_str("# Security Audit Report\n\n");

        // Summary
        output.push_str(&self.format_summary(result));

        // Risk Score
        output.push_str(&self.format_risk_score(result));

        // Findings
        output.push_str(&self.format_findings(result));

        // Recommendations
        output.push_str(&self.format_recommendations(result));

        // Footer
        output.push_str(&self.format_footer());

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::ContentContext;
    use crate::rules::{Category, Finding, Location, Summary};

    fn create_test_result() -> ScanResult {
        ScanResult {
            version: env!("CARGO_PKG_VERSION").to_string(),
            scanned_at: "2024-01-01T00:00:00Z".to_string(),
            target: "test".to_string(),
            findings: vec![Finding {
                id: "TEST-001".to_string(),
                name: "Test Rule".to_string(),
                severity: Severity::High,
                category: Category::Overpermission,
                confidence: Confidence::Firm,
                location: Location {
                    file: "test.yaml".to_string(),
                    line: 10,
                    column: Some(5),
                },
                code: "test pattern".to_string(),
                message: "Test finding description".to_string(),
                recommendation: "Fix this issue".to_string(),
                fix_hint: None,
                cwe_ids: vec![],
                rule_severity: Some(RuleSeverity::Error),
                client: None,
                context: None,
            }],
            summary: Summary {
                critical: 0,
                high: 1,
                medium: 0,
                low: 0,
                passed: false,
                errors: 1,
                warnings: 0,
            },
            risk_score: None,
            elapsed_ms: 0,
        }
    }

    #[test]
    fn test_basic_report() {
        let reporter = MarkdownReporter::new();
        let result = create_test_result();
        let output = reporter.report(&result);

        assert!(output.contains("# Security Audit Report"));
        assert!(output.contains("## Summary"));
        assert!(output.contains("## Findings"));
        assert!(output.contains("TEST-001"));
    }

    #[test]
    fn test_with_badge() {
        let reporter = MarkdownReporter::new().with_badge();
        let result = create_test_result();
        let output = reporter.report(&result);

        assert!(output.contains("[![cc-audit]"));
        assert!(output.contains("<!-- cc-audit scan results"));
    }

    #[test]
    fn test_empty_findings() {
        let reporter = MarkdownReporter::new();
        let result = ScanResult {
            version: env!("CARGO_PKG_VERSION").to_string(),
            scanned_at: "2024-01-01T00:00:00Z".to_string(),
            target: "test".to_string(),
            findings: vec![],
            summary: Summary {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                passed: true,
                errors: 0,
                warnings: 0,
            },
            risk_score: None,
            elapsed_ms: 0,
        };
        let output = reporter.report(&result);

        assert!(output.contains("No security issues found"));
    }

    #[test]
    fn test_with_risk_score() {
        let reporter = MarkdownReporter::new();
        let result = ScanResult {
            version: env!("CARGO_PKG_VERSION").to_string(),
            scanned_at: "2024-01-01T00:00:00Z".to_string(),
            target: "test".to_string(),
            findings: vec![Finding {
                id: "TEST-001".to_string(),
                name: "Test Rule".to_string(),
                severity: Severity::Critical,
                category: Category::Exfiltration,
                confidence: Confidence::Certain,
                location: Location {
                    file: "test.yaml".to_string(),
                    line: 10,
                    column: Some(5),
                },
                code: "test pattern".to_string(),
                message: "Test finding description".to_string(),
                recommendation: "Fix this issue".to_string(),
                fix_hint: Some("Run: fix command".to_string()),
                cwe_ids: vec!["CWE-200".to_string()],
                rule_severity: Some(RuleSeverity::Error),
                client: Some("Claude".to_string()),
                context: Some(ContentContext::Comment),
            }],
            summary: Summary {
                critical: 1,
                high: 0,
                medium: 0,
                low: 0,
                passed: false,
                errors: 1,
                warnings: 0,
            },
            risk_score: None,
            elapsed_ms: 0,
        };
        // Calculate risk score from the findings
        let mut result = result;
        result.risk_score = Some(crate::scoring::RiskScore::from_findings(&result.findings));
        let output = reporter.report(&result);

        assert!(output.contains("Risk Score"));
        assert!(output.contains("Critical"));
    }

    #[test]
    fn test_all_severities() {
        let reporter = MarkdownReporter::new();
        let result = ScanResult {
            version: env!("CARGO_PKG_VERSION").to_string(),
            scanned_at: "2024-01-01T00:00:00Z".to_string(),
            target: "test".to_string(),
            findings: vec![
                Finding {
                    id: "CRIT-001".to_string(),
                    name: "Critical Rule".to_string(),
                    severity: Severity::Critical,
                    category: Category::Exfiltration,
                    confidence: Confidence::Certain,
                    location: Location {
                        file: "critical.yaml".to_string(),
                        line: 1,
                        column: None,
                    },
                    code: "critical".to_string(),
                    message: "Critical issue".to_string(),
                    recommendation: "Fix immediately".to_string(),
                    fix_hint: None,
                    cwe_ids: vec![],
                    rule_severity: Some(RuleSeverity::Error),
                    client: None,
                    context: None,
                },
                Finding {
                    id: "MED-001".to_string(),
                    name: "Medium Rule".to_string(),
                    severity: Severity::Medium,
                    category: Category::Overpermission,
                    confidence: Confidence::Firm,
                    location: Location {
                        file: "medium.yaml".to_string(),
                        line: 5,
                        column: Some(3),
                    },
                    code: "medium".to_string(),
                    message: "Medium issue".to_string(),
                    recommendation: "Consider fixing".to_string(),
                    fix_hint: None,
                    cwe_ids: vec![],
                    rule_severity: Some(RuleSeverity::Warn),
                    client: None,
                    context: None,
                },
                Finding {
                    id: "LOW-001".to_string(),
                    name: "Low Rule".to_string(),
                    severity: Severity::Low,
                    category: Category::Persistence,
                    confidence: Confidence::Tentative,
                    location: Location {
                        file: "low.yaml".to_string(),
                        line: 10,
                        column: None,
                    },
                    code: "low".to_string(),
                    message: "Low issue".to_string(),
                    recommendation: "May fix".to_string(),
                    fix_hint: None,
                    cwe_ids: vec![],
                    rule_severity: None,
                    client: None,
                    context: None,
                },
            ],
            summary: Summary {
                critical: 1,
                high: 0,
                medium: 1,
                low: 1,
                passed: false,
                errors: 1,
                warnings: 1,
            },
            risk_score: None,
            elapsed_ms: 0,
        };
        let output = reporter.report(&result);

        assert!(output.contains("CRIT-001"));
        assert!(output.contains("MED-001"));
        assert!(output.contains("LOW-001"));
    }

    #[test]
    fn test_badge_format() {
        let reporter = MarkdownReporter::new().with_badge();
        let mut result = create_test_result();
        result.summary.passed = true;
        result.summary.critical = 0;
        result.summary.high = 0;
        result.summary.medium = 0;
        result.summary.low = 0;
        result.findings.clear();
        let output = reporter.report(&result);

        // When no findings, badge shows "verified-brightgreen"
        assert!(output.contains("verified-brightgreen"));
    }

    #[test]
    fn test_reporter_default() {
        let reporter = MarkdownReporter::default();
        let result = create_test_result();
        let output = reporter.report(&result);
        assert!(output.contains("# Security Audit Report"));
    }
}
