mod exfiltration;
mod injection;
mod obfuscation;
mod permission;
mod persistence;
mod privilege;

use crate::rules::types::Rule;
use std::sync::LazyLock;

static ALL_RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    let mut rules = Vec::with_capacity(20);
    rules.extend(exfiltration::rules());
    rules.extend(privilege::rules());
    rules.extend(persistence::rules());
    rules.extend(injection::rules());
    rules.extend(permission::rules());
    rules.extend(obfuscation::rules());
    rules
});

pub fn all_rules() -> &'static [Rule] {
    &ALL_RULES
}
