use crate::reporter::Reporter;
use crate::rules::{Category, ScanResult};

pub struct HtmlReporter;

impl HtmlReporter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for HtmlReporter {
    fn default() -> Self {
        Self::new()
    }
}

impl Reporter for HtmlReporter {
    fn report(&self, result: &ScanResult) -> String {
        let status_class = if result.summary.passed {
            "passed"
        } else {
            "failed"
        };
        let status_text = if result.summary.passed {
            "PASSED"
        } else {
            "FAILED"
        };

        let risk_score_html = if let Some(ref score) = result.risk_score {
            let level_lower = format!("{:?}", score.level).to_lowercase();
            let level_display = format!("{:?}", score.level);
            let percentage = (score.total as f32 / 10.0).min(100.0);
            format!(
                r#"
        <div class="risk-score">
            <h2>Risk Score</h2>
            <div class="score-display">
                <span class="score-value risk-{level_lower}">{}</span>
                <span class="score-label">{level_display}</span>
            </div>
            <div class="score-bar">
                <div class="score-fill" style="width: {percentage}%"></div>
            </div>
        </div>"#,
                score.total,
            )
        } else {
            String::new()
        };

        let findings_html: String = result
            .findings
            .iter()
            .map(|f| {
                let severity_class = format!("{:?}", f.severity).to_lowercase();
                let category_display = format_category(&f.category);
                format!(
                    r#"
            <div class="finding severity-{}">
                <div class="finding-header">
                    <span class="finding-id">{}</span>
                    <span class="severity-badge {}">{:?}</span>
                    <span class="category-badge">{}</span>
                </div>
                <div class="finding-message">{}</div>
                <div class="finding-location">
                    <code>{}:{}</code>
                </div>
                <div class="finding-code">
                    <pre><code>{}</code></pre>
                </div>
                <div class="finding-recommendation">
                    <strong>Recommendation:</strong> {}
                </div>
            </div>"#,
                    severity_class,
                    f.id,
                    severity_class,
                    f.severity,
                    category_display,
                    html_escape(&f.message),
                    html_escape(&f.location.file),
                    f.location.line,
                    html_escape(&f.code),
                    html_escape(&f.recommendation)
                )
            })
            .collect();

        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>cc-audit Security Report</title>
    <style>
        :root {{
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #2563eb;
            --passed: #16a34a;
            --failed: #dc2626;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background: #f3f4f6;
            padding: 2rem;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        .header {{
            background: white;
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}

        .header h1 {{
            font-size: 1.75rem;
            margin-bottom: 0.5rem;
        }}

        .header-meta {{
            color: #6b7280;
            font-size: 0.9rem;
        }}

        .status {{
            display: inline-flex;
            align-items: center;
            padding: 0.5rem 1rem;
            border-radius: 9999px;
            font-weight: 600;
            margin-top: 1rem;
        }}

        .status.passed {{
            background: #dcfce7;
            color: var(--passed);
        }}

        .status.failed {{
            background: #fee2e2;
            color: var(--failed);
        }}

        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .summary-card {{
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}

        .summary-card h3 {{
            font-size: 0.875rem;
            color: #6b7280;
            text-transform: uppercase;
            margin-bottom: 0.5rem;
        }}

        .summary-value {{
            font-size: 2rem;
            font-weight: 700;
        }}

        .summary-value.critical {{ color: var(--critical); }}
        .summary-value.high {{ color: var(--high); }}
        .summary-value.medium {{ color: var(--medium); }}
        .summary-value.low {{ color: var(--low); }}

        .risk-score {{
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}

        .risk-score h2 {{
            margin-bottom: 1rem;
        }}

        .score-display {{
            display: flex;
            align-items: baseline;
            gap: 1rem;
            margin-bottom: 1rem;
        }}

        .score-value {{
            font-size: 3rem;
            font-weight: 700;
        }}

        .score-value.risk-safe {{ color: var(--passed); }}
        .score-value.risk-low {{ color: var(--low); }}
        .score-value.risk-medium {{ color: var(--medium); }}
        .score-value.risk-high {{ color: var(--high); }}
        .score-value.risk-critical {{ color: var(--critical); }}

        .score-label {{
            font-size: 1.25rem;
            color: #6b7280;
        }}

        .score-bar {{
            height: 8px;
            background: #e5e7eb;
            border-radius: 4px;
            overflow: hidden;
        }}

        .score-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--low), var(--medium), var(--critical));
            border-radius: 4px;
            transition: width 0.5s ease;
        }}

        .findings {{
            background: white;
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}

        .findings h2 {{
            margin-bottom: 1rem;
        }}

        .finding {{
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
        }}

        .finding.severity-critical {{ border-left: 4px solid var(--critical); }}
        .finding.severity-high {{ border-left: 4px solid var(--high); }}
        .finding.severity-medium {{ border-left: 4px solid var(--medium); }}
        .finding.severity-low {{ border-left: 4px solid var(--low); }}

        .finding-header {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.5rem;
        }}

        .finding-id {{
            font-weight: 600;
            font-family: monospace;
        }}

        .severity-badge {{
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .severity-badge.critical {{ background: #fee2e2; color: var(--critical); }}
        .severity-badge.high {{ background: #ffedd5; color: var(--high); }}
        .severity-badge.medium {{ background: #fef3c7; color: var(--medium); }}
        .severity-badge.low {{ background: #dbeafe; color: var(--low); }}

        .category-badge {{
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            background: #f3f4f6;
            color: #4b5563;
        }}

        .finding-message {{
            font-size: 0.95rem;
            margin-bottom: 0.5rem;
        }}

        .finding-location {{
            font-size: 0.875rem;
            color: #6b7280;
            margin-bottom: 0.5rem;
        }}

        .finding-code {{
            background: #1f2937;
            border-radius: 6px;
            padding: 0.75rem;
            margin-bottom: 0.5rem;
            overflow-x: auto;
        }}

        .finding-code pre {{
            margin: 0;
        }}

        .finding-code code {{
            color: #e5e7eb;
            font-family: 'SF Mono', Monaco, monospace;
            font-size: 0.875rem;
        }}

        .finding-recommendation {{
            font-size: 0.875rem;
            color: #4b5563;
        }}

        .no-findings {{
            text-align: center;
            padding: 3rem;
            color: #6b7280;
        }}

        .footer {{
            text-align: center;
            margin-top: 2rem;
            color: #9ca3af;
            font-size: 0.875rem;
        }}

        .footer a {{
            color: #6b7280;
            text-decoration: none;
        }}

        .footer a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>cc-audit Security Report</h1>
            <div class="header-meta">
                <div>Target: <code>{}</code></div>
                <div>Version: {}</div>
                <div>Generated: {}</div>
            </div>
            <div class="status {}">
                {}
            </div>
        </div>

        <div class="summary">
            <div class="summary-card">
                <h3>Critical</h3>
                <div class="summary-value critical">{}</div>
            </div>
            <div class="summary-card">
                <h3>High</h3>
                <div class="summary-value high">{}</div>
            </div>
            <div class="summary-card">
                <h3>Medium</h3>
                <div class="summary-value medium">{}</div>
            </div>
            <div class="summary-card">
                <h3>Low</h3>
                <div class="summary-value low">{}</div>
            </div>
            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="summary-value">{}</div>
            </div>
        </div>

        {}

        <div class="findings">
            <h2>Findings</h2>
            {}
        </div>

        <div class="footer">
            Generated by <a href="https://github.com/ryo-ebata/cc-audit">cc-audit</a> v{}
        </div>
    </div>
</body>
</html>"#,
            html_escape(&result.target),
            result.version,
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            status_class,
            status_text,
            result.summary.critical,
            result.summary.high,
            result.summary.medium,
            result.summary.low,
            result.summary.critical
                + result.summary.high
                + result.summary.medium
                + result.summary.low,
            risk_score_html,
            if result.findings.is_empty() {
                "<div class=\"no-findings\">No security issues found.</div>".to_string()
            } else {
                findings_html
            },
            result.version
        )
    }
}

fn format_category(category: &Category) -> &'static str {
    match category {
        Category::Exfiltration => "Exfiltration",
        Category::PromptInjection => "Prompt Injection",
        Category::Persistence => "Persistence",
        Category::PrivilegeEscalation => "Privilege Escalation",
        Category::Obfuscation => "Obfuscation",
        Category::SupplyChain => "Supply Chain",
        Category::SecretLeak => "Secret Leak",
        Category::Overpermission => "Overpermission",
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Category, Severity};
    use crate::test_utils::fixtures::{create_finding, create_test_result};

    #[test]
    fn test_html_output_structure() {
        let reporter = HtmlReporter::new();
        let result = create_test_result(vec![]);
        let output = reporter.report(&result);

        assert!(output.contains("<!DOCTYPE html>"));
        assert!(output.contains("cc-audit Security Report"));
        assert!(output.contains("PASSED"));
    }

    #[test]
    fn test_html_output_with_findings() {
        let reporter = HtmlReporter::new();
        let finding = create_finding(
            "EX-001",
            Severity::Critical,
            Category::Exfiltration,
            "Test finding",
            "test.sh",
            10,
        );
        let result = create_test_result(vec![finding]);
        let output = reporter.report(&result);

        assert!(output.contains("EX-001"));
        assert!(output.contains("severity-critical"));
        assert!(output.contains("FAILED"));
    }

    #[test]
    fn test_html_escapes_special_chars() {
        let reporter = HtmlReporter::new();
        let mut finding = create_finding(
            "TEST-001",
            Severity::High,
            Category::Exfiltration,
            "Test <script>alert('xss')</script>",
            "test.sh",
            1,
        );
        finding.code = "<script>malicious</script>".to_string();
        let result = create_test_result(vec![finding]);
        let output = reporter.report(&result);

        assert!(!output.contains("<script>alert"));
        assert!(output.contains("&lt;script&gt;"));
    }

    #[test]
    #[allow(clippy::default_constructed_unit_structs)]
    fn test_html_default_trait() {
        let reporter = HtmlReporter::default();
        let result = create_test_result(vec![]);
        let output = reporter.report(&result);
        assert!(output.contains("cc-audit"));
    }

    #[test]
    fn test_format_category_all_variants() {
        // Test that all Category variants are properly formatted
        assert_eq!(format_category(&Category::Exfiltration), "Exfiltration");
        assert_eq!(
            format_category(&Category::PromptInjection),
            "Prompt Injection"
        );
        assert_eq!(format_category(&Category::Persistence), "Persistence");
        assert_eq!(
            format_category(&Category::PrivilegeEscalation),
            "Privilege Escalation"
        );
        assert_eq!(format_category(&Category::Obfuscation), "Obfuscation");
        assert_eq!(format_category(&Category::SupplyChain), "Supply Chain");
        assert_eq!(format_category(&Category::SecretLeak), "Secret Leak");
        assert_eq!(format_category(&Category::Overpermission), "Overpermission");
    }

    #[test]
    fn test_html_output_with_all_categories() {
        let reporter = HtmlReporter::new();
        let findings = vec![
            create_finding(
                "PI-001",
                Severity::Critical,
                Category::PromptInjection,
                "Prompt injection",
                "test.md",
                1,
            ),
            create_finding(
                "PS-001",
                Severity::High,
                Category::Persistence,
                "Persistence",
                "test.sh",
                2,
            ),
            create_finding(
                "PE-001",
                Severity::High,
                Category::PrivilegeEscalation,
                "Privilege escalation",
                "test.sh",
                3,
            ),
            create_finding(
                "OB-001",
                Severity::Medium,
                Category::Obfuscation,
                "Obfuscation",
                "test.js",
                4,
            ),
            create_finding(
                "SC-001",
                Severity::Critical,
                Category::SupplyChain,
                "Supply chain",
                "package.json",
                5,
            ),
            create_finding(
                "SL-001",
                Severity::Critical,
                Category::SecretLeak,
                "Secret leak",
                "config.yaml",
                6,
            ),
            create_finding(
                "OP-001",
                Severity::Medium,
                Category::Overpermission,
                "Overpermission",
                "mcp.json",
                7,
            ),
        ];
        let result = create_test_result(findings);
        let output = reporter.report(&result);

        // Check that all categories are displayed
        assert!(output.contains("Prompt Injection"));
        assert!(output.contains("Persistence"));
        assert!(output.contains("Privilege Escalation"));
        assert!(output.contains("Obfuscation"));
        assert!(output.contains("Supply Chain"));
        assert!(output.contains("Secret Leak"));
        assert!(output.contains("Overpermission"));
    }
}
