//! Effective configuration after merging CLI and config file.

use crate::{
    BadgeFormat, Cli, ClientType, Confidence, Config, CustomRuleLoader, DynamicRule, OutputFormat,
    RuleSeverity, ScanType, Severity,
};
use std::path::Path;

/// Effective scan configuration after merging CLI and config file.
#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    pub format: OutputFormat,
    pub strict: bool,
    pub warn_only: bool,
    pub min_severity: Option<Severity>,
    pub min_rule_severity: Option<RuleSeverity>,
    pub scan_type: ScanType,
    pub recursive: bool,
    pub ci: bool,
    pub verbose: bool,
    pub min_confidence: Confidence,
    pub skip_comments: bool,
    pub fix_hint: bool,
    pub no_malware_scan: bool,
    pub deep_scan: bool,
    pub watch: bool,
    pub output: Option<String>,
    pub fix: bool,
    pub fix_dry_run: bool,
    pub malware_db: Option<String>,
    pub custom_rules: Option<String>,

    // v1.1.0: Remote scan options
    pub remote: Option<String>,
    pub git_ref: String,
    pub remote_auth: Option<String>,
    pub parallel_clones: usize,

    // v1.1.0: Badge options
    pub badge: bool,
    pub badge_format: BadgeFormat,
    pub summary: bool,

    // v1.1.0: Client scan options
    pub all_clients: bool,
    pub client: Option<ClientType>,

    // v1.1.0: CVE scan options
    pub no_cve_scan: bool,
    pub cve_db: Option<String>,
}

impl EffectiveConfig {
    /// Merge CLI options with config file settings.
    ///
    /// - Boolean flags: CLI OR config (either can enable)
    /// - Enum options: config provides defaults, CLI always takes precedence
    /// - Path options: CLI takes precedence, fallback to config
    pub fn from_cli_and_config(cli: &Cli, config: &Config) -> Self {
        // Parse format from config if available
        let format = parse_output_format(config.scan.format.as_deref()).unwrap_or(cli.format);

        // Parse scan_type from config if available
        let scan_type = parse_scan_type(config.scan.scan_type.as_deref()).unwrap_or(cli.scan_type);

        // Parse min_confidence from config if available
        let min_confidence =
            parse_confidence(config.scan.min_confidence.as_deref()).unwrap_or(cli.min_confidence);

        // Path options: CLI takes precedence, fallback to config
        let malware_db = cli
            .malware_db
            .as_ref()
            .map(|p| p.display().to_string())
            .or_else(|| config.scan.malware_db.clone());

        let custom_rules = cli
            .custom_rules
            .as_ref()
            .map(|p| p.display().to_string())
            .or_else(|| config.scan.custom_rules.clone());

        let output = cli
            .output
            .as_ref()
            .map(|p| p.display().to_string())
            .or_else(|| config.scan.output.clone());

        // v1.1.0: Remote scan options
        let remote = cli.remote.clone().or_else(|| config.scan.remote.clone());
        let git_ref = if cli.git_ref != "HEAD" {
            cli.git_ref.clone()
        } else {
            config
                .scan
                .git_ref
                .clone()
                .unwrap_or_else(|| "HEAD".to_string())
        };
        let remote_auth = cli
            .remote_auth
            .clone()
            .or_else(|| config.scan.remote_auth.clone())
            .or_else(|| std::env::var("GITHUB_TOKEN").ok());
        let parallel_clones = config.scan.parallel_clones.unwrap_or(cli.parallel_clones);

        // v1.1.0: Badge options
        let badge = cli.badge || config.scan.badge;
        let badge_format =
            parse_badge_format(config.scan.badge_format.as_deref()).unwrap_or(cli.badge_format);
        let summary = cli.summary || config.scan.summary;

        // v1.1.0: Client scan options
        let all_clients = cli.all_clients || config.scan.all_clients;
        let client = cli
            .client
            .or_else(|| parse_client_type(config.scan.client.as_deref()));

        // v1.1.0: CVE scan options
        let no_cve_scan = cli.no_cve_scan || config.scan.no_cve_scan;
        let cve_db = cli
            .cve_db
            .as_ref()
            .map(|p| p.display().to_string())
            .or_else(|| config.scan.cve_db.clone());

        Self {
            format,
            // Boolean flags: OR operation (config can enable, CLI can enable)
            strict: cli.strict || config.scan.strict,
            warn_only: cli.warn_only,
            min_severity: cli.min_severity,
            min_rule_severity: cli.min_rule_severity,
            scan_type,
            recursive: cli.recursive || config.scan.recursive,
            ci: cli.ci || config.scan.ci,
            verbose: cli.verbose || config.scan.verbose,
            min_confidence,
            skip_comments: cli.skip_comments || config.scan.skip_comments,
            fix_hint: cli.fix_hint || config.scan.fix_hint,
            no_malware_scan: cli.no_malware_scan || config.scan.no_malware_scan,
            deep_scan: cli.deep_scan || config.scan.deep_scan,
            watch: cli.watch || config.scan.watch,
            fix: cli.fix || config.scan.fix,
            fix_dry_run: cli.fix_dry_run || config.scan.fix_dry_run,
            output,
            malware_db,
            custom_rules,
            // v1.1.0 options
            remote,
            git_ref,
            remote_auth,
            parallel_clones,
            badge,
            badge_format,
            summary,
            all_clients,
            client,
            no_cve_scan,
            cve_db,
        }
    }
}

/// Parse badge format from string using FromStr.
pub fn parse_badge_format(s: Option<&str>) -> Option<BadgeFormat> {
    s?.parse().ok()
}

/// Parse client type from string using FromStr.
pub fn parse_client_type(s: Option<&str>) -> Option<ClientType> {
    s?.parse().ok()
}

/// Parse output format from string using FromStr.
pub fn parse_output_format(s: Option<&str>) -> Option<OutputFormat> {
    s?.parse().ok()
}

/// Parse scan type from string using FromStr.
pub fn parse_scan_type(s: Option<&str>) -> Option<ScanType> {
    s?.parse().ok()
}

/// Parse confidence level from string using FromStr.
pub fn parse_confidence(s: Option<&str>) -> Option<Confidence> {
    s?.parse().ok()
}

/// Load custom rules from effective config (CLI or config file).
pub fn load_custom_rules_from_effective(effective: &EffectiveConfig) -> Vec<DynamicRule> {
    match &effective.custom_rules {
        Some(path_str) => {
            let path = Path::new(path_str);
            match CustomRuleLoader::load_from_file(path) {
                Ok(rules) => {
                    if !rules.is_empty() {
                        eprintln!("Loaded {} custom rule(s) from {}", rules.len(), path_str);
                    }
                    rules
                }
                Err(e) => {
                    eprintln!("Warning: Failed to load custom rules: {}", e);
                    Vec::new()
                }
            }
        }
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_output_format() {
        assert_eq!(
            parse_output_format(Some("terminal")),
            Some(OutputFormat::Terminal)
        );
        assert_eq!(parse_output_format(Some("json")), Some(OutputFormat::Json));
        assert_eq!(
            parse_output_format(Some("sarif")),
            Some(OutputFormat::Sarif)
        );
        assert_eq!(parse_output_format(Some("html")), Some(OutputFormat::Html));
        assert_eq!(
            parse_output_format(Some("TERMINAL")),
            Some(OutputFormat::Terminal)
        );
        assert_eq!(parse_output_format(Some("invalid")), None);
        assert_eq!(parse_output_format(None), None);
    }

    #[test]
    fn test_parse_scan_type() {
        assert_eq!(parse_scan_type(Some("skill")), Some(ScanType::Skill));
        assert_eq!(parse_scan_type(Some("hook")), Some(ScanType::Hook));
        assert_eq!(parse_scan_type(Some("mcp")), Some(ScanType::Mcp));
        assert_eq!(parse_scan_type(Some("docker")), Some(ScanType::Docker));
        assert_eq!(parse_scan_type(Some("SKILL")), Some(ScanType::Skill));
        assert_eq!(parse_scan_type(Some("invalid")), None);
        assert_eq!(parse_scan_type(None), None);
    }

    #[test]
    fn test_parse_confidence() {
        assert_eq!(
            parse_confidence(Some("tentative")),
            Some(Confidence::Tentative)
        );
        assert_eq!(parse_confidence(Some("firm")), Some(Confidence::Firm));
        assert_eq!(parse_confidence(Some("certain")), Some(Confidence::Certain));
        assert_eq!(
            parse_confidence(Some("TENTATIVE")),
            Some(Confidence::Tentative)
        );
        assert_eq!(parse_confidence(Some("invalid")), None);
        assert_eq!(parse_confidence(None), None);
    }

    #[test]
    fn test_parse_client_type() {
        assert_eq!(parse_client_type(Some("claude")), Some(ClientType::Claude));
        assert_eq!(parse_client_type(Some("cursor")), Some(ClientType::Cursor));
        assert_eq!(
            parse_client_type(Some("windsurf")),
            Some(ClientType::Windsurf)
        );
        assert_eq!(parse_client_type(Some("vscode")), Some(ClientType::Vscode));
        assert_eq!(parse_client_type(Some("CLAUDE")), Some(ClientType::Claude));
        assert_eq!(parse_client_type(Some("invalid")), None);
        assert_eq!(parse_client_type(None), None);
    }

    #[test]
    fn test_parse_badge_format() {
        assert_eq!(
            parse_badge_format(Some("markdown")),
            Some(BadgeFormat::Markdown)
        );
        assert_eq!(parse_badge_format(Some("md")), Some(BadgeFormat::Markdown));
        assert_eq!(parse_badge_format(Some("html")), Some(BadgeFormat::Html));
        assert_eq!(parse_badge_format(Some("url")), Some(BadgeFormat::Url));
        assert_eq!(parse_badge_format(Some("invalid")), None);
        assert_eq!(parse_badge_format(None), None);
    }
}
