//! Result formatting and output generation.

use crate::{
    BadgeFormat, CheckArgs, Config, JsonReporter, OutputFormat, Reporter, SarifReporter,
    ScanResult, TerminalReporter,
};

use super::client::resolve_scan_paths_from_check_args;
use super::config::EffectiveConfig;

/// Generate a badge URL based on scan result.
fn generate_badge_url(result: &ScanResult) -> String {
    let (status, color) = if result.summary.critical == 0 && result.summary.high == 0 {
        if result.summary.medium == 0 && result.summary.low == 0 {
            ("verified", "brightgreen")
        } else {
            ("warning", "yellow")
        }
    } else {
        ("failed", "red")
    };

    format!(
        "https://img.shields.io/badge/cc--audit-{}-{}",
        status, color
    )
}

/// Generate badge output based on badge format.
fn generate_badge_output(result: &ScanResult, format: &BadgeFormat) -> String {
    let badge_url = generate_badge_url(result);

    match format {
        BadgeFormat::Url => badge_url,
        BadgeFormat::Html => format!(r#"<img src="{}" alt="cc-audit status">"#, badge_url),
        BadgeFormat::Markdown => format!(
            "[![cc-audit]({})](https://github.com/ryo-ebata/cc-audit)",
            badge_url
        ),
    }
}

/// Format scan result using CheckArgs settings.
pub fn format_result_check_args(args: &CheckArgs, result: &ScanResult) -> String {
    // Resolve paths and determine project root for config loading
    let scan_paths = resolve_scan_paths_from_check_args(args);
    let project_root = scan_paths.first().and_then(|p| {
        if p.is_dir() {
            Some(p.as_path())
        } else {
            p.parent()
        }
    });

    // Load config and merge with CheckArgs
    let config = Config::load(project_root);
    let effective = EffectiveConfig::from_check_args_and_config(args, &config);

    format_result_with_config(&effective, result)
}

/// Format result using effective config (avoids reloading config).
pub fn format_result_with_config(effective: &EffectiveConfig, result: &ScanResult) -> String {
    let mut output = match effective.format {
        OutputFormat::Terminal => {
            let reporter = TerminalReporter::new(effective.strict, effective.verbose)
                .with_fix_hints(effective.fix_hint)
                .with_friendly(!effective.compact);
            reporter.report(result)
        }
        OutputFormat::Json => {
            let reporter = JsonReporter::new();
            reporter.report(result)
        }
        OutputFormat::Sarif => {
            let reporter = SarifReporter::new();
            reporter.report(result)
        }
        OutputFormat::Html => {
            let reporter = crate::reporter::html::HtmlReporter::new();
            reporter.report(result)
        }
        OutputFormat::Markdown => {
            let mut reporter = crate::reporter::markdown::MarkdownReporter::new();
            // For markdown format with markdown badge_format, let the reporter handle it
            if effective.badge && matches!(effective.badge_format, BadgeFormat::Markdown) {
                reporter = reporter.with_badge();
            }
            reporter.report(result)
        }
    };

    // Add badge output for non-markdown badge formats, or for non-markdown output formats
    if effective.badge
        && (effective.format != OutputFormat::Markdown
            || !matches!(effective.badge_format, BadgeFormat::Markdown))
    {
        let badge = generate_badge_output(result, &effective.badge_format);
        output.push('\n');
        output.push_str(&badge);
        output.push('\n');
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Confidence, Summary};

    fn create_test_result() -> ScanResult {
        ScanResult {
            version: env!("CARGO_PKG_VERSION").to_string(),
            scanned_at: "2024-01-01T00:00:00Z".to_string(),
            target: "/test/path".to_string(),
            summary: Summary {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                passed: true,
                errors: 0,
                warnings: 0,
            },
            findings: vec![],
            risk_score: None,
            elapsed_ms: 0,
        }
    }

    #[test]
    fn test_format_result_with_config_terminal() {
        let effective = EffectiveConfig {
            format: OutputFormat::Terminal,
            strict: false,
            warn_only: false,
            min_severity: None,
            min_rule_severity: None,
            scan_type: crate::ScanType::Skill,
            recursive: true,
            ci: false,
            verbose: false,
            min_confidence: Confidence::Tentative,
            skip_comments: false,
            fix_hint: false,
            compact: false,
            no_malware_scan: false,
            deep_scan: false,
            watch: false,
            output: None,
            fix: false,
            fix_dry_run: false,
            malware_db: None,
            custom_rules: None,
            strict_secrets: false,
            remote: None,
            git_ref: "HEAD".to_string(),
            remote_auth: None,
            parallel_clones: 4,
            remote_list: None,
            awesome_claude_code: false,
            badge: false,
            badge_format: crate::BadgeFormat::Markdown,
            summary: false,
            all_clients: false,
            client: None,
            no_cve_scan: false,
            cve_db: None,
            sbom: false,
            sbom_format: None,
            sbom_npm: false,
            sbom_cargo: false,
        };

        let result = create_test_result();
        let output = format_result_with_config(&effective, &result);
        assert!(output.contains("No security issues found"));
    }

    #[test]
    fn test_format_result_with_config_json() {
        let effective = EffectiveConfig {
            format: OutputFormat::Json,
            strict: false,
            warn_only: false,
            min_severity: None,
            min_rule_severity: None,
            scan_type: crate::ScanType::Skill,
            recursive: true,
            ci: false,
            verbose: false,
            min_confidence: Confidence::Tentative,
            skip_comments: false,
            fix_hint: false,
            compact: false,
            no_malware_scan: false,
            deep_scan: false,
            watch: false,
            output: None,
            fix: false,
            fix_dry_run: false,
            malware_db: None,
            custom_rules: None,
            strict_secrets: false,
            remote: None,
            git_ref: "HEAD".to_string(),
            remote_auth: None,
            parallel_clones: 4,
            remote_list: None,
            awesome_claude_code: false,
            badge: false,
            badge_format: crate::BadgeFormat::Markdown,
            summary: false,
            all_clients: false,
            client: None,
            no_cve_scan: false,
            cve_db: None,
            sbom: false,
            sbom_format: None,
            sbom_npm: false,
            sbom_cargo: false,
        };

        let result = create_test_result();
        let output = format_result_with_config(&effective, &result);
        assert!(output.contains("\"version\""));
        assert!(output.contains("\"findings\""));
    }
}
