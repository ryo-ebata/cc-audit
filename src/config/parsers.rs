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
