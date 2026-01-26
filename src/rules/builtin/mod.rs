mod dependency;
mod docker;
mod exfiltration;
mod injection;
mod obfuscation;
mod permission;
mod persistence;
mod plugin_rules;
mod privilege;
mod secrets;
mod subagent_rules;
mod supplychain;

use crate::rules::types::Rule;
use std::sync::LazyLock;

static ALL_RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    let mut rules = Vec::with_capacity(50);
    rules.extend(exfiltration::rules());
    rules.extend(privilege::rules());
    rules.extend(persistence::rules());
    rules.extend(injection::rules());
    rules.extend(permission::rules());
    rules.extend(obfuscation::rules());
    rules.extend(supplychain::rules());
    rules.extend(secrets::rules());
    rules.extend(docker::rules());
    rules.extend(dependency::rules());
    rules.extend(subagent_rules::rules());
    rules.extend(plugin_rules::rules());
    rules
});

pub fn all_rules() -> &'static [Rule] {
    &ALL_RULES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_rules_compile() {
        // Force LazyLock initialization - if any regex pattern is invalid, this will panic
        let rules = all_rules();
        assert!(!rules.is_empty(), "Rules should not be empty");

        // Verify each rule has valid patterns
        for rule in rules {
            assert!(
                !rule.patterns.is_empty(),
                "Rule {} should have at least one pattern",
                rule.id
            );
        }
    }

    #[test]
    fn test_all_rules_have_required_fields() {
        for rule in all_rules() {
            assert!(!rule.id.is_empty(), "Rule ID should not be empty");
            assert!(
                !rule.name.is_empty(),
                "Rule {} name should not be empty",
                rule.id
            );
            assert!(
                !rule.description.is_empty(),
                "Rule {} description should not be empty",
                rule.id
            );
            assert!(
                !rule.message.is_empty(),
                "Rule {} message should not be empty",
                rule.id
            );
            assert!(
                !rule.recommendation.is_empty(),
                "Rule {} recommendation should not be empty",
                rule.id
            );
            assert!(
                !rule.cwe_ids.is_empty(),
                "Rule {} should have at least one CWE ID",
                rule.id
            );
        }
    }
}
