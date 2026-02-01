//! String parsers for configuration values.
//!
//! These functions parse string representations from CLI args
//! or config files into typed enums.

use crate::{BadgeFormat, ClientType, Confidence, OutputFormat, RuleSeverity, ScanType, Severity};

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_badge_format_valid() {
        assert_eq!(parse_badge_format(Some("url")), Some(BadgeFormat::Url));
        assert_eq!(
            parse_badge_format(Some("markdown")),
            Some(BadgeFormat::Markdown)
        );
        assert_eq!(parse_badge_format(Some("html")), Some(BadgeFormat::Html));
    }

    #[test]
    fn test_parse_badge_format_invalid() {
        assert_eq!(parse_badge_format(Some("unknown")), None);
    }

    #[test]
    fn test_parse_badge_format_none() {
        assert_eq!(parse_badge_format(None), None);
    }

    #[test]
    fn test_parse_client_type_valid() {
        assert!(parse_client_type(Some("claude")).is_some());
        assert!(parse_client_type(Some("cursor")).is_some());
    }

    #[test]
    fn test_parse_client_type_invalid() {
        assert_eq!(parse_client_type(Some("unknown_client")), None);
    }

    #[test]
    fn test_parse_client_type_none() {
        assert_eq!(parse_client_type(None), None);
    }

    #[test]
    fn test_parse_output_format_valid() {
        assert_eq!(parse_output_format(Some("json")), Some(OutputFormat::Json));
        assert_eq!(
            parse_output_format(Some("terminal")),
            Some(OutputFormat::Terminal)
        );
        assert_eq!(
            parse_output_format(Some("sarif")),
            Some(OutputFormat::Sarif)
        );
    }

    #[test]
    fn test_parse_output_format_invalid() {
        assert_eq!(parse_output_format(Some("xml")), None);
    }

    #[test]
    fn test_parse_output_format_none() {
        assert_eq!(parse_output_format(None), None);
    }

    #[test]
    fn test_parse_scan_type_valid() {
        assert_eq!(parse_scan_type(Some("skill")), Some(ScanType::Skill));
        assert_eq!(parse_scan_type(Some("hook")), Some(ScanType::Hook));
        assert_eq!(parse_scan_type(Some("mcp")), Some(ScanType::Mcp));
        assert_eq!(parse_scan_type(Some("docker")), Some(ScanType::Docker));
    }

    #[test]
    fn test_parse_scan_type_invalid() {
        assert_eq!(parse_scan_type(Some("unknown")), None);
    }

    #[test]
    fn test_parse_scan_type_none() {
        assert_eq!(parse_scan_type(None), None);
    }

    #[test]
    fn test_parse_confidence_valid() {
        assert_eq!(
            parse_confidence(Some("tentative")),
            Some(Confidence::Tentative)
        );
        assert_eq!(parse_confidence(Some("firm")), Some(Confidence::Firm));
        assert_eq!(parse_confidence(Some("certain")), Some(Confidence::Certain));
    }

    #[test]
    fn test_parse_confidence_invalid() {
        assert_eq!(parse_confidence(Some("maybe")), None);
    }

    #[test]
    fn test_parse_confidence_none() {
        assert_eq!(parse_confidence(None), None);
    }

    #[test]
    fn test_parse_severity_valid() {
        assert_eq!(parse_severity(Some("critical")), Some(Severity::Critical));
        assert_eq!(parse_severity(Some("high")), Some(Severity::High));
        assert_eq!(parse_severity(Some("medium")), Some(Severity::Medium));
        assert_eq!(parse_severity(Some("low")), Some(Severity::Low));
    }

    #[test]
    fn test_parse_severity_invalid() {
        assert_eq!(parse_severity(Some("extreme")), None);
    }

    #[test]
    fn test_parse_severity_none() {
        assert_eq!(parse_severity(None), None);
    }

    #[test]
    fn test_parse_rule_severity_valid() {
        assert_eq!(
            parse_rule_severity(Some("error")),
            Some(RuleSeverity::Error)
        );
        assert_eq!(parse_rule_severity(Some("warn")), Some(RuleSeverity::Warn));
    }

    #[test]
    fn test_parse_rule_severity_invalid() {
        assert_eq!(parse_rule_severity(Some("info")), None);
    }

    #[test]
    fn test_parse_rule_severity_none() {
        assert_eq!(parse_rule_severity(None), None);
    }
}
