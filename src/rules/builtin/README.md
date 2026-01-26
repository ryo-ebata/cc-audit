# Built-in Rules

Pre-defined security rules organized by category.

## Overview

This module contains all built-in security rules for cc-audit. Rules are organized by security category and loaded at startup via `LazyLock`.

## Files

| File | Rule Prefix | Description |
|------|-------------|-------------|
| `exfiltration.rs` | EX-* | Data exfiltration patterns |
| `privilege.rs` | PR-* | Privilege escalation |
| `persistence.rs` | PE-* | Persistence mechanisms |
| `injection.rs` | IN-* | Code/command injection |
| `permission.rs` | PM-* | Permission misconfigurations |
| `obfuscation.rs` | OB-* | Code obfuscation |
| `supplychain.rs` | SC-* | Supply chain attacks |
| `secrets.rs` | SE-* | Secret/credential exposure |
| `docker.rs` | DK-* | Docker security issues |
| `dependency.rs` | DP-* | Dependency vulnerabilities |
| `subagent_rules.rs` | SA-* | Subagent misconfigurations |
| `plugin_rules.rs` | PL-* | Plugin security issues |

## Rule Structure

Each rule file exports a `rules()` function:

```rust
pub fn rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "EX-001".to_string(),
            name: "Data Exfiltration via curl".to_string(),
            severity: Severity::Critical,
            category: Category::Exfiltration,
            patterns: vec![
                Regex::new(r"curl.*-d.*\$\w+").unwrap(),
            ],
            message: "Potential data exfiltration detected".to_string(),
            recommendation: "Review the curl command...".to_string(),
            cwe_ids: vec!["CWE-200".to_string()],
            confidence: Confidence::Firm,
            // ...
        },
        // More rules...
    ]
}
```

## Loading Rules

All rules are loaded lazily at first access:

```rust
// In mod.rs
static ALL_RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    let mut rules = Vec::with_capacity(50);
    rules.extend(exfiltration::rules());
    rules.extend(privilege::rules());
    // ... all other categories
    rules
});

pub fn all_rules() -> &'static [Rule] {
    &ALL_RULES
}
```

## Rule Categories

### Exfiltration (EX-*)
- Data transmission to external servers
- Environment variable extraction
- File content exfiltration

### Privilege Escalation (PR-*)
- sudo without password
- SUID bit manipulation
- Capability manipulation

### Persistence (PE-*)
- Cron job creation
- Startup script modification
- Service installation

### Injection (IN-*)
- Command injection
- Code injection
- SQL injection patterns

### Permission (PM-*)
- Wildcard permissions (`"*"`)
- Excessive tool access
- Unrestricted file access

### Obfuscation (OB-*)
- Base64 encoded commands
- Hex encoded strings
- Eval with dynamic strings

### Supply Chain (SC-*)
- Typosquatting packages
- Malicious registry URLs
- Compromised dependencies

### Secrets (SE-*)
- Hardcoded API keys
- Password patterns
- Token exposure

### Docker (DK-*)
- Privileged containers
- Host path mounts
- Exposed ports

### Dependency (DP-*)
- Known vulnerable versions
- Deprecated packages
- Insecure sources

### Subagent (SA-*)
- Excessive permissions
- Unsafe configurations

### Plugin (PL-*)
- Untrusted sources
- Permission issues

## Adding New Rules

1. Add rule to appropriate category file
2. Include required fields:
   - `id`: Unique identifier (PREFIX-NNN)
   - `name`: Human-readable name
   - `severity`: Critical/High/Medium/Low/Info
   - `category`: Rule category
   - `patterns`: Regex patterns
   - `message`: Finding message
   - `recommendation`: Fix suggestion
   - `cwe_ids`: Related CWE identifiers
   - `confidence`: Firm/Tentative/Weak

3. Run tests to verify patterns compile:
   ```bash
   cargo test rules::builtin
   ```
