# Rules Module

Security rules and rule engine for finding detection.

## Overview

This module provides the rule system for detecting security issues:
- Built-in security rules organized by category
- Custom rule loading from YAML/JSON
- Rule engine for pattern matching

## Directory Structure

```
rules/
├── mod.rs           # Module exports
├── types.rs         # Core types (Rule, Finding, Severity, etc.)
├── engine.rs        # RuleEngine - Pattern matching
├── custom.rs        # Custom rule loading
├── snapshot_test.rs # Snapshot tests (test only)
└── builtin/         # Built-in rules by category
    ├── mod.rs
    ├── exfiltration.rs
    ├── privilege.rs
    ├── persistence.rs
    ├── injection.rs
    ├── permission.rs
    ├── obfuscation.rs
    ├── supplychain.rs
    ├── secrets.rs
    ├── docker.rs
    ├── dependency.rs
    ├── subagent_rules.rs
    └── plugin_rules.rs
```

## Key Types

### Rule

```rust
pub struct Rule {
    pub id: String,              // e.g., "EX-001"
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub category: Category,
    pub patterns: Vec<CompiledRegex>,
    pub message: String,
    pub recommendation: String,
    pub cwe_ids: Vec<String>,
    pub confidence: Confidence,
}
```

### Finding

```rust
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub name: String,
    pub severity: Severity,
    pub category: Category,
    pub message: String,
    pub file_path: String,
    pub line_number: usize,
    pub matched_content: String,
    pub recommendation: String,
    pub rule_severity: Option<RuleSeverity>,
}
```

### Severity

```rust
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}
```

### Category

```rust
pub enum Category {
    Exfiltration,
    PrivilegeEscalation,
    Persistence,
    Injection,
    Permission,
    Obfuscation,
    SupplyChain,
    Secrets,
    Docker,
    Dependency,
    Subagent,
    Plugin,
}
```

### Confidence

```rust
pub enum Confidence {
    Firm,      // High confidence
    Tentative, // Medium confidence
    Weak,      // Low confidence
}
```

## Built-in Rules

| File | Rule IDs | Category |
|------|----------|----------|
| `exfiltration.rs` | EX-* | Data exfiltration |
| `privilege.rs` | PR-* | Privilege escalation |
| `persistence.rs` | PE-* | Persistence mechanisms |
| `injection.rs` | IN-* | Code injection |
| `permission.rs` | PM-* | Permission issues |
| `obfuscation.rs` | OB-* | Code obfuscation |
| `supplychain.rs` | SC-* | Supply chain attacks |
| `secrets.rs` | SE-* | Secret exposure |
| `docker.rs` | DK-* | Docker security |
| `dependency.rs` | DP-* | Dependency issues |
| `subagent_rules.rs` | SA-* | Subagent issues |
| `plugin_rules.rs` | PL-* | Plugin issues |

## RuleEngine

```rust
pub struct RuleEngine {
    rules: Vec<Rule>,
    disabled_rules: HashSet<String>,
}

impl RuleEngine {
    pub fn new() -> Self;
    pub fn scan_content(&self, content: &str, path: &str) -> Vec<Finding>;
    pub fn disable_rule(&mut self, rule_id: &str);
}
```

## Custom Rules

Load custom rules from YAML:

```yaml
# custom-rules.yaml
rules:
  - id: "CUSTOM-001"
    name: "Custom Pattern"
    severity: "high"
    category: "exfiltration"
    patterns:
      - 'custom_pattern_\w+'
    message: "Custom pattern detected"
    recommendation: "Review this pattern"
```

```rust
let loader = CustomRuleLoader::new();
let custom_rules = loader.load_from_file("custom-rules.yaml")?;
```

## Usage Example

```rust
use cc_audit::rules::{RuleEngine, Severity, Category};

let engine = RuleEngine::new();

// Scan content
let content = fs::read_to_string("SKILL.md")?;
let findings = engine.scan_content(&content, "SKILL.md");

for finding in findings {
    println!("[{}] {}: {}", finding.severity, finding.id, finding.message);
}
```
