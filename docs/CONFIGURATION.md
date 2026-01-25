# Configuration

[日本語](./CONFIGURATION.ja.md)

cc-audit supports project-level configuration via config files.

## Config File Locations

Configuration files are searched in the following order (highest priority first):

1. `.cc-audit.yaml` in project root
2. `.cc-audit.yml` in project root
3. `.cc-audit.json` in project root
4. `.cc-audit.toml` in project root
5. `~/.config/cc-audit/config.yaml` (global config)

## Initialize Configuration

Generate a configuration file template:

```bash
# Create .cc-audit.yaml in current directory
cc-audit --init ./

# Create in a specific directory
cc-audit --init /path/to/project/
```

## Example Configuration

```yaml
# .cc-audit.yaml

# Scan settings
scan:
  format: terminal          # terminal, json, sarif, html
  output: null              # Output file path
  strict: false             # Show medium/low severity findings
  scan_type: skill          # skill, hook, mcp, command, rules, docker, dependency, subagent, plugin
  recursive: false
  ci: false
  verbose: false
  min_confidence: tentative # tentative, firm, certain
  skip_comments: false
  fix_hint: false
  deep_scan: false
  no_malware_scan: false

# Baseline settings
baseline:
  baseline_file: null
  save_baseline: null

# Profile settings
profile:
  load: null
  save: null

# Watch mode settings
watch:
  debounce_ms: 300
  poll_interval_ms: 500

# Ignore settings
ignore:
  directories:
    - my_build_output
    - .cache
  patterns:
    - "*.log"
    - "*.generated.*"
  include_tests: false
  include_node_modules: false
  include_vendor: false

# Disable specific rules
disabled_rules:
  - "PE-001"
  - "EX-002"

# Inline custom rules
rules:
  - id: "CUSTOM-001"
    name: "Internal API access"
    severity: "high"
    category: "exfiltration"
    patterns:
      - 'https?://internal\.company\.com'
    message: "Internal API access detected"
    recommendation: "Ensure this access is authorized"

# Inline malware signatures
malware_signatures:
  - id: "MW-CUSTOM-001"
    name: "Custom C2 pattern"
    pattern: "malicious-domain\\.com"
    severity: "critical"
    category: "exfiltration"
    confidence: "certain"
```

## Default Ignored Directories

| Category | Directories |
|----------|-------------|
| Build output | `target`, `dist`, `build`, `out` |
| Package managers | `node_modules`, `.pnpm`, `.yarn` |
| Version control | `.git`, `.svn`, `.hg` |
| IDE | `.idea`, `.vscode` |
| Cache | `.cache`, `__pycache__`, `.pytest_cache`, `.mypy_cache` |
| Coverage | `coverage`, `.nyc_output` |

## CLI Flag Override

CLI flags and config file settings are merged:

- **Boolean flags** (`strict`, `verbose`, `ci`, etc.): OR operation
- **Enum options** (`format`, `scan_type`, `min_confidence`): Config provides defaults

```bash
# Config has strict: true - strict mode is active even without --strict
cc-audit ./my-skill/

# CLI --verbose + config strict: true - both are active
cc-audit --verbose ./my-skill/
```

---

# Custom Rules

Define your own detection rules using YAML.

## YAML Format

```yaml
version: "1"
rules:
  - id: "CUSTOM-001"
    name: "Internal API endpoint access"
    description: "Detects access to internal API endpoints"
    severity: "high"            # critical, high, medium, low
    category: "exfiltration"    # See categories below
    confidence: "firm"          # certain, firm, tentative
    patterns:
      - 'https?://internal\.company\.com'
      - 'api\.internal\.'
    exclusions:                 # Optional
      - 'localhost'
      - '127\.0\.0\.1'
    message: "Access to internal API endpoint detected"
    recommendation: "Ensure this access is authorized"
    fix_hint: "Remove or replace with public API"  # Optional
    cwe:                        # Optional
      - "CWE-200"
```

## Available Categories

| Category | Aliases |
|----------|---------|
| `exfiltration` | `data-exfiltration` |
| `privilege-escalation` | `privilege` |
| `persistence` | — |
| `prompt-injection` | `injection` |
| `overpermission` | `permission` |
| `obfuscation` | — |
| `supply-chain` | `supplychain` |
| `secret-leak` | `secrets`, `secretleak` |

## Usage

```bash
cc-audit ./my-skill/ --custom-rules ./my-rules.yaml
```

---

# Malware Signatures Database

cc-audit includes a built-in malware signature database.

## Custom Database Format

```json
{
  "version": "1.0.0",
  "updated_at": "2026-01-25",
  "signatures": [
    {
      "id": "MW-CUSTOM-001",
      "name": "Custom C2 beacon pattern",
      "description": "Detects communication with known C2 server",
      "pattern": "https?://malicious-c2\\.example\\.com",
      "severity": "critical",
      "category": "exfiltration",
      "confidence": "certain",
      "reference": "https://example.com/threat-intel"
    }
  ]
}
```

## Built-in Signatures

| ID | Name | Severity |
|----|------|----------|
| MW-001 | C2 Beacon Pattern | Critical |
| MW-002 | Reverse Shell (Bash TCP) | Critical |
| MW-003 | Cryptocurrency Miner | Critical |
| MW-004 | Known Malicious Domain | Critical |
| MW-005 | AWS Credential Harvesting | Critical |
| MW-006 | Browser Data Theft | Critical |
| MW-007 | Keylogger Installation | Critical |
| MW-008 | Hidden File in Home Directory | High |
| MW-009 | Process Injection (Linux) | Critical |
| MW-010 | Anti-Analysis VM Detection | High |

## Usage

```bash
# Use custom malware database
cc-audit ./my-skill/ --malware-db ./custom-signatures.json

# Disable malware scanning
cc-audit ./my-skill/ --no-malware-scan
```
