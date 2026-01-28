//! Effective configuration after merging CLI and config file.

use crate::{
    BadgeFormat, CheckArgs, ClientType, Confidence, Config, CustomRuleLoader, DynamicRule,
    OutputFormat, RuleSeverity, ScanType, Severity,
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
    pub compact: bool,
    pub no_malware_scan: bool,
    pub deep_scan: bool,
    pub watch: bool,
    pub output: Option<String>,
    pub fix: bool,
    pub fix_dry_run: bool,
    pub malware_db: Option<String>,
    pub custom_rules: Option<String>,
    /// Strict secrets mode: disable dummy key heuristics for test files.
    pub strict_secrets: bool,

    // v1.1.0: Remote scan options
    pub remote: Option<String>,
    pub git_ref: String,
    pub remote_auth: Option<String>,
    pub parallel_clones: usize,
    /// File containing list of repository URLs to scan.
    pub remote_list: Option<String>,
    /// Scan all repositories from awesome-claude-code.
    pub awesome_claude_code: bool,

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

    // v1.2.0: SBOM options
    /// Generate SBOM (Software Bill of Materials).
    pub sbom: bool,
    /// SBOM output format: "cyclonedx", "spdx".
    pub sbom_format: Option<String>,
    /// Include npm dependencies in SBOM.
    pub sbom_npm: bool,
    /// Include Cargo dependencies in SBOM.
    pub sbom_cargo: bool,
}

impl EffectiveConfig {
    /// Merge CheckArgs options with config file settings.
    ///
    /// - Boolean flags: CLI OR config (either can enable)
    /// - Enum options: config provides defaults, CLI always takes precedence
    /// - Path options: CLI takes precedence, fallback to config
    ///
    /// Note: CheckArgs uses `no_recursive` (default false = recursive enabled).
    pub fn from_check_args_and_config(args: &CheckArgs, config: &Config) -> Self {
        // For enum options: CLI takes precedence when explicitly set (non-default)
        let format = if args.format != OutputFormat::default() {
            args.format
        } else {
            parse_output_format(config.scan.format.as_deref()).unwrap_or(args.format)
        };

        let scan_type = if args.scan_type != ScanType::default() {
            args.scan_type
        } else {
            parse_scan_type(config.scan.scan_type.as_deref()).unwrap_or(args.scan_type)
        };

        // min_confidence: CLI takes precedence if explicitly set, else config, else default
        let min_confidence = args
            .min_confidence
            .or_else(|| parse_confidence(config.scan.min_confidence.as_deref()))
            .unwrap_or(Confidence::Tentative);

        // Path options: CLI takes precedence, fallback to config
        let malware_db = args
            .malware_db
            .as_ref()
            .map(|p| p.display().to_string())
            .or_else(|| config.scan.malware_db.clone());

        let custom_rules = args
            .custom_rules
            .as_ref()
            .map(|p| p.display().to_string())
            .or_else(|| config.scan.custom_rules.clone());

        let output = args
            .output
            .as_ref()
            .map(|p| p.display().to_string())
            .or_else(|| config.scan.output.clone());

        // Remote scan options
        let remote = args.remote.clone().or_else(|| config.scan.remote.clone());
        let git_ref = if args.git_ref != "HEAD" {
            args.git_ref.clone()
        } else {
            config
                .scan
                .git_ref
                .clone()
                .unwrap_or_else(|| "HEAD".to_string())
        };
        let remote_auth = args
            .remote_auth
            .clone()
            .or_else(|| config.scan.remote_auth.clone())
            .or_else(|| std::env::var("GITHUB_TOKEN").ok());
        let parallel_clones = config.scan.parallel_clones.unwrap_or(args.parallel_clones);

        // Badge options
        let badge = args.badge || config.scan.badge;
        let badge_format =
            parse_badge_format(config.scan.badge_format.as_deref()).unwrap_or(args.badge_format);
        let summary = args.summary || config.scan.summary;

        // Client scan options
        let all_clients = args.all_clients || config.scan.all_clients;
        let client = args
            .client
            .or_else(|| parse_client_type(config.scan.client.as_deref()));

        // CVE scan options
        let no_cve_scan = args.no_cve_scan || config.scan.no_cve_scan;
        let cve_db = args
            .cve_db
            .as_ref()
            .map(|p| p.display().to_string())
            .or_else(|| config.scan.cve_db.clone());

        // Additional remote options
        let remote_list = args
            .remote_list
            .as_ref()
            .map(|p| p.display().to_string())
            .or_else(|| config.scan.remote_list.clone());
        let awesome_claude_code = args.awesome_claude_code || config.scan.awesome_claude_code;

        // SBOM options
        let sbom = args.sbom || config.scan.sbom;
        let sbom_format = args
            .sbom_format
            .clone()
            .or_else(|| config.scan.sbom_format.clone());
        let sbom_npm = args.sbom_npm || config.scan.sbom_npm;
        let sbom_cargo = args.sbom_cargo || config.scan.sbom_cargo;

        // strict_secrets: CLI OR config
        let strict_secrets = args.strict_secrets || config.scan.strict_secrets;

        // Parse min_severity from config if CLI doesn't provide it
        let min_severity = args
            .min_severity
            .or_else(|| parse_severity(config.scan.min_severity.as_deref()));

        // Parse min_rule_severity from config if CLI doesn't provide it
        let min_rule_severity = args
            .min_rule_severity
            .or_else(|| parse_rule_severity(config.scan.min_rule_severity.as_deref()));

        // Note: args.no_recursive means NOT recursive (default false = recursive)
        // If CLI says --no-recursive, disable recursion regardless of config
        // Otherwise, use config value
        let recursive = !args.no_recursive && config.scan.recursive;

        Self {
            format,
            strict: args.strict || config.scan.strict,
            warn_only: args.warn_only || config.scan.warn_only,
            min_severity,
            min_rule_severity,
            scan_type,
            recursive,
            ci: args.ci || config.scan.ci,
            verbose: config.scan.verbose, // Note: verbose is in Cli, not CheckArgs
            min_confidence,
            skip_comments: args.skip_comments || config.scan.skip_comments,
            fix_hint: args.fix_hint || config.scan.fix_hint,
            compact: args.compact || config.scan.compact,
            no_malware_scan: args.no_malware_scan || config.scan.no_malware_scan,
            deep_scan: args.deep_scan || config.scan.deep_scan,
            watch: args.watch || config.scan.watch,
            fix: args.fix || config.scan.fix,
            fix_dry_run: args.fix_dry_run || config.scan.fix_dry_run,
            output,
            malware_db,
            custom_rules,
            strict_secrets,
            // Remote options
            remote,
            git_ref,
            remote_auth,
            parallel_clones,
            remote_list,
            awesome_claude_code,
            badge,
            badge_format,
            summary,
            all_clients,
            client,
            no_cve_scan,
            cve_db,
            // SBOM options
            sbom,
            sbom_format,
            sbom_npm,
            sbom_cargo,
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

/// Parse severity level from string using FromStr.
pub fn parse_severity(s: Option<&str>) -> Option<Severity> {
    s?.parse().ok()
}

/// Parse rule severity level from string using FromStr.
pub fn parse_rule_severity(s: Option<&str>) -> Option<RuleSeverity> {
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
