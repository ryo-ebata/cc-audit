//! Configuration template generation.

use super::types::Config;

impl Config {
    /// Generate a YAML configuration template with comments.
    pub fn generate_template() -> String {
        r#"# cc-audit Configuration File
# Place this file as .cc-audit.yaml in your project root

# =============================================================================
# RULE SEVERITY CONFIGURATION (v3.0.0)
# =============================================================================
# Controls how findings affect CI exit code.
# - error: Causes CI failure (exit 1) - DEFAULT for all rules
# - warn: Report only, does not cause CI failure (exit 0)
# - ignore: Completely skip the rule (no report)
#
# Priority: ignore > warn > default

severity:
  # Default severity for all rules
  default: error

  # Rules to treat as warnings only (report but don't fail CI)
  # warn:
  #   - PI-001    # Prompt injection patterns
  #   - PI-002
  #   - OB-001    # Obfuscation patterns

  # Rules to completely ignore (no report)
  # ignore:
  #   - OP-001    # Overpermission

# =============================================================================
# SCAN CONFIGURATION
# =============================================================================
scan:
  # Output format: terminal, json, sarif, html, markdown
  # format: terminal

  # Strict mode: show medium/low severity findings and treat warnings as errors
  strict: false

  # Scan type: skill, hook, mcp, command, rules, docker, dependency, subagent, plugin
  # scan_type: skill

  # Recursive scan
  recursive: false

  # CI mode: non-interactive output
  ci: false

  # Verbose output
  verbose: false

  # Minimum confidence level: tentative, firm, certain
  # min_confidence: tentative

  # Skip comment lines when scanning
  skip_comments: false

  # Show fix hints in terminal output
  fix_hint: false

  # Disable malware signature scanning
  no_malware_scan: false

  # Watch mode: continuously monitor files for changes
  watch: false

  # Path to a custom malware signatures database (JSON)
  # malware_db: ./custom-malware.json

  # Path to a custom rules file (YAML format)
  # custom_rules: ./custom-rules.yaml

  # Output file path (for HTML/JSON/SARIF output)
  # output: ./report.html

  # Enable deep scan with deobfuscation
  deep_scan: false

  # Auto-fix issues (where possible)
  fix: false

  # Preview auto-fix changes without applying them
  fix_dry_run: false

  # Warn-only mode: treat all findings as warnings (always exit 0)
  warn_only: false

  # Minimum severity level to include: critical, high, medium, low
  # min_severity: high

  # Minimum rule severity to treat as errors: error, warn
  # min_rule_severity: error

  # Strict secrets mode: disable dummy key heuristics for test files
  strict_secrets: false

  # ---------------------------------------------------------------------------
  # CVE Scan Options (v1.1.0)
  # ---------------------------------------------------------------------------
  # Disable CVE vulnerability scanning
  no_cve_scan: false

  # Path to a custom CVE database (JSON)
  # cve_db: ./custom-cve.json

  # ---------------------------------------------------------------------------
  # Remote Scanning Options (v1.1.0)
  # ---------------------------------------------------------------------------
  # Remote repository URL to scan
  # remote: https://github.com/user/repo

  # Git reference to checkout (branch, tag, commit)
  # git_ref: main

  # GitHub authentication token (also reads from GITHUB_TOKEN env var)
  # remote_auth: ghp_xxxxxxxxxxxx

  # Number of parallel clones for batch scanning
  # parallel_clones: 4

  # ---------------------------------------------------------------------------
  # Badge Options (v1.1.0)
  # ---------------------------------------------------------------------------
  # Generate a badge for the scan result
  badge: false

  # Badge format: markdown, html, json
  # badge_format: markdown

  # Show summary only (useful for batch scanning)
  summary: false

  # ---------------------------------------------------------------------------
  # Client Scan Options (v1.1.0)
  # ---------------------------------------------------------------------------
  # Scan all installed AI coding clients (Claude Code, Cursor, etc.)
  all_clients: false

  # Specific client to scan: claude, cursor, windsurf, vscode
  # client: claude

  # ---------------------------------------------------------------------------
  # SBOM Options (v1.2.0)
  # ---------------------------------------------------------------------------
  # Generate SBOM (Software Bill of Materials)
  sbom: false

  # SBOM output format: cyclonedx, spdx
  # sbom_format: cyclonedx

  # Include npm dependencies in SBOM
  sbom_npm: false

  # Include Cargo dependencies in SBOM
  sbom_cargo: false

# =============================================================================
# BASELINE CONFIGURATION (Drift Detection / Rug Pull Prevention)
# =============================================================================
baseline:
  # Create a baseline snapshot when scanning
  enabled: false

  # Check for drift against saved baseline
  check_drift: false

  # Path to save baseline to
  # save_to: ./.cc-audit-baseline.json

  # Path to baseline file to compare against
  # compare_with: ./.cc-audit-baseline.json

# =============================================================================
# WATCH MODE CONFIGURATION
# =============================================================================
watch:
  # Debounce duration in milliseconds
  debounce_ms: 300

  # Poll interval in milliseconds
  poll_interval_ms: 500

# =============================================================================
# IGNORE CONFIGURATION
# =============================================================================
ignore:
  # Directories to ignore (overwrites defaults if specified)
  # directories:
  #   - node_modules
  #   - target
  #   - .git
  #   - dist
  #   - build

  # Glob patterns to ignore
  # patterns:
  #   - "*.log"
  #   - "temp/**"

  # Include test directories in scan
  include_tests: false

  # Include node_modules in scan
  include_node_modules: false

  # Include vendor directories in scan
  include_vendor: false

# =============================================================================
# RULE CONFIGURATION
# =============================================================================

# Rule IDs to disable
# disabled_rules:
#   - "PE-001"
#   - "EX-002"

# Text file detection configuration
# text_files:
#   # Additional file extensions to treat as text
#   extensions:
#     - custom
#     - special
#
#   # Additional special file names
#   special_names:
#     - CUSTOMFILE

# Custom rules (YAML format)
# rules:
#   - id: "CUSTOM-001"
#     name: "Custom Rule Name"
#     severity: "high"  # critical, high, medium, low, info
#     category: "exfiltration"  # exfiltration, privilege_escalation, persistence, etc.
#     patterns:
#       - 'pattern_to_match'
#     message: "Description of the issue"
#     confidence: "firm"  # tentative, firm, certain
#     fix_hint: "How to fix this issue"

# Custom malware signatures
# malware_signatures:
#   - id: "MW-CUSTOM-001"
#     name: "Custom Malware Signature"
#     description: "Description of what this detects"
#     pattern: "malware_pattern"
#     severity: "critical"
#     category: "exfiltration"
#     confidence: "firm"
"#
        .to_string()
    }
}
