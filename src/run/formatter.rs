//! Result formatting and output generation.

use crate::{
    Config, JsonReporter, OutputFormat, Reporter, SarifReporter, ScanResult, TerminalReporter,
};

use super::client::resolve_scan_paths;
use super::config::EffectiveConfig;
use crate::Cli;

/// Format scan result using CLI settings.
pub fn format_result(cli: &Cli, result: &ScanResult) -> String {
    // Resolve paths and determine project root for config loading
    let scan_paths = resolve_scan_paths(cli);
    let project_root = scan_paths.first().and_then(|p| {
        if p.is_dir() {
            Some(p.as_path())
        } else {
            p.parent()
        }
    });

    // Load config and merge with CLI
    let config = Config::load(project_root);
    let effective = EffectiveConfig::from_cli_and_config(cli, &config);

    format_result_with_config(&effective, result)
}

/// Format result using effective config (avoids reloading config).
pub fn format_result_with_config(effective: &EffectiveConfig, result: &ScanResult) -> String {
    match effective.format {
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
            let reporter = crate::reporter::markdown::MarkdownReporter::new();
            reporter.report(result)
        }
    }
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
