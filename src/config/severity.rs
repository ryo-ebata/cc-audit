//! Rule severity configuration.

use crate::rules::RuleSeverity;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Rule severity configuration - controls how findings affect CI exit code.
///
/// Priority: ignore > warn > default
///
/// Example:
/// ```yaml
/// severity:
///   default: error      # All rules are errors by default
///   warn:
///     - PI-001          # Treat as warning only
///     - PI-002
///   ignore:
///     - OP-001          # Completely ignore
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SeverityConfig {
    /// Default severity for all rules (error by default).
    pub default: RuleSeverity,
    /// Rule IDs to treat as warnings (report only, exit 0).
    #[serde(default)]
    pub warn: HashSet<String>,
    /// Rule IDs to ignore completely (no report).
    /// Note: These are merged with disabled_rules.
    #[serde(default)]
    pub ignore: HashSet<String>,
}

impl Default for SeverityConfig {
    fn default() -> Self {
        Self {
            default: RuleSeverity::Error,
            warn: HashSet::new(),
            ignore: HashSet::new(),
        }
    }
}

impl SeverityConfig {
    /// Get the effective RuleSeverity for a rule ID.
    /// Returns None if the rule should be ignored.
    pub fn get_rule_severity(&self, rule_id: &str) -> Option<RuleSeverity> {
        // Priority: ignore > warn > default
        if self.ignore.contains(rule_id) {
            return None; // Ignore this rule
        }
        if self.warn.contains(rule_id) {
            return Some(RuleSeverity::Warn);
        }
        Some(self.default)
    }
}
