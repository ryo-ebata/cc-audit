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

  # Recursive scan (enabled by default)
  recursive: true

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
# Uses glob patterns to determine which paths to ignore during scanning.
# Each pattern is matched against the full path of the file.
#
# Glob pattern syntax:
#   *       - matches any sequence of characters except /
#   **      - matches any sequence of characters including /
#   ?       - matches any single character
#   {a,b}   - matches either a or b
#   [abc]   - matches any character in the set
#   [!abc]  - matches any character not in the set
#
# Examples:
#   - "**/node_modules/**"       # Ignore node_modules anywhere
#   - "**/*.test.{js,ts}"        # Match .test.js or .test.ts files
#   - "**/test{,s}/**"           # Match test or tests directories
#   - "**/*.{log,tmp,bak}"       # Match files by extension
ignore:
  patterns:
    # Build outputs
    - "**/target/**"              # Rust build artifacts
    - "**/dist/**"                # Distribution/build output
    - "**/build/**"               # Build directories
    - "**/out/**"                 # Output directories
    - "**/_build/**"              # Elixir/Phoenix build

    # JavaScript/TypeScript frameworks
    - "**/.next/**"               # Next.js
    - "**/.nuxt/**"               # Nuxt.js
    - "**/.output/**"             # Nitro/Nuxt output
    - "**/.svelte-kit/**"         # SvelteKit
    - "**/.astro/**"              # Astro
    - "**/.remix/**"              # Remix
    - "**/.gatsby/**"             # Gatsby
    - "**/.expo/**"               # Expo
    - "**/storybook-static/**"    # Storybook

    # Package managers
    - "**/node_modules/**"        # npm/yarn/pnpm packages
    - "**/.pnpm/**"               # pnpm virtual store
    - "**/.pnpm-store/**"         # pnpm global store
    - "**/.yarn/**"               # Yarn cache/offline mirror
    - "**/.npm/**"                # npm cache
    - "**/.pnp.*"                 # Yarn PnP loader files
    - "**/bower_components/**"    # Bower packages
    - "**/jspm_packages/**"       # jspm packages

    # Version control
    - "**/.git/**"                # Git repository
    - "**/.svn/**"                # SVN repository
    - "**/.hg/**"                 # Mercurial repository

    # IDEs and editors
    - "**/.idea/**"               # JetBrains IDEs
    - "**/.vscode/**"             # Visual Studio Code
    - "**/.eclipse/**"            # Eclipse
    - "**/.settings/**"           # Eclipse settings

    # Deployment platforms
    - "**/.vercel/**"             # Vercel
    - "**/.netlify/**"            # Netlify
    - "**/.amplify/**"            # AWS Amplify
    - "**/.serverless/**"         # Serverless Framework

    # Cache and bundlers
    - "**/.cache/**"              # General cache
    - "**/.parcel-cache/**"       # Parcel bundler
    - "**/.vite/**"               # Vite cache
    - "**/.turbo/**"              # Turborepo cache
    - "**/.esbuild/**"            # esbuild cache
    - "**/.webpack/**"            # webpack cache
    - "**/.rpt2_cache/**"         # rollup-plugin-typescript2
    - "**/tmp/**"                 # Temporary files
    - "**/temp/**"                # Temporary files

    # Python
    - "**/__pycache__/**"         # Python bytecode cache
    - "**/.pytest_cache/**"       # pytest cache
    - "**/.mypy_cache/**"         # mypy type checker cache
    - "**/.ruff_cache/**"         # Ruff linter cache
    - "**/.venv/**"               # Virtual environment
    - "**/venv/**"                # Virtual environment
    - "**/.tox/**"                # Tox testing tool
    - "**/.nox/**"                # Nox testing tool
    - "**/__pypackages__/**"      # PEP 582
    - "**/site-packages/**"       # Installed packages
    - "**/.eggs/**"               # setuptools eggs

    # Ruby
    - "**/.bundle/**"             # Bundler

    # Java/Gradle/Maven
    - "**/.gradle/**"             # Gradle cache
    - "**/.mvn/**"                # Maven wrapper

    # Go
    - "**/vendor/**"              # Go vendor directory

    # Coverage reports
    - "**/coverage/**"            # Coverage reports
    - "**/.nyc_output/**"         # NYC/Istanbul coverage
    - "**/htmlcov/**"             # Python coverage HTML
    - "**/.coverage/**"           # Python coverage data

    # Logs and reports
    - "**/logs/**"                # Log directories
    - "**/*.log"                  # Log files
    - "**/report/**"              # Report directories
    - "**/reports/**"             # Report directories
    - "**/.report/**"             # Hidden report directories
    - "**/*report*/**"            # Any directory containing 'report' (e.g., playwright-report, test-report)

    # Generated and minified files
    - "*.min.js"                  # Minified JavaScript
    - "*.min.css"                 # Minified CSS
    - "*.d.ts"                    # TypeScript declaration files
    - "*.generated.*"             # Generated files
    - "*.g.ts"                    # Generated TypeScript
    - "*.g.dart"                  # Generated Dart
    - "*.map"                     # Source maps
    - "**/bundle.*"               # Bundle outputs
    - "**/chunk-*"                # Webpack/Vite chunks

    # Temporary and backup files
    - "**/*.tmp"                  # Temporary files
    - "**/*.temp"                 # Temporary files
    - "**/*.bak"                  # Backup files
    - "**/*.swp"                  # Vim swap files
    - "**/*.swo"                  # Vim swap files
    - "**/*~"                     # Backup files (emacs, etc.)

    # OS-specific
    - "**/.DS_Store"              # macOS
    - "**/Thumbs.db"              # Windows
    - "**/desktop.ini"            # Windows

    # Docker
    - "**/.docker/**"             # Docker cache/data

    # Test directories (optional - uncomment if needed)
    # - "**/test/**"              # Test directories
    # - "**/tests/**"             # Test directories
    # - "**/__tests__/**"         # Jest tests
    # - "**/*.test.{js,ts,jsx,tsx}"  # Test files
    # - "**/*.spec.{js,ts,jsx,tsx}"  # Spec files

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_is_valid_yaml() {
        let template = Config::generate_template();

        // Should parse as valid YAML
        let result: Result<serde_yml::Value, _> = serde_yml::from_str(&template);
        assert!(
            result.is_ok(),
            "Template should be valid YAML: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_template_contains_ignore_section() {
        let template = Config::generate_template();

        assert!(template.contains("# IGNORE CONFIGURATION"));
        assert!(template.contains("ignore:"));
        assert!(template.contains("patterns:"));
    }

    #[test]
    fn test_template_contains_glob_syntax_documentation() {
        let template = Config::generate_template();

        // Should document glob pattern syntax
        assert!(template.contains("Glob pattern syntax:"));
        assert!(template.contains("*       - matches any sequence"));
        assert!(template.contains("**      - matches any sequence"));
        assert!(template.contains("?       - matches any single character"));
        assert!(template.contains("{a,b}   - matches either"));
        assert!(template.contains("[abc]   - matches any character in the set"));
    }

    #[test]
    fn test_template_uses_glob_patterns_not_regex() {
        let template = Config::generate_template();

        // Should use glob patterns (starting with **/)
        assert!(template.contains("**/node_modules/**"));
        assert!(template.contains("**/target/**"));
        assert!(template.contains("**/.git/**"));

        // Should NOT use old regex patterns
        assert!(!template.contains("/(target|dist|build|out)/"));
        assert!(!template.contains("/(node_modules|\\.pnpm|\\.yarn)/"));
        assert!(!template.contains("/(\\.git|\\.svn|\\.hg)/"));
    }

    #[test]
    fn test_template_includes_report_and_log_patterns() {
        let template = Config::generate_template();

        // Should include report directories
        assert!(template.contains("**/report/**"));
        assert!(template.contains("**/reports/**"));
        assert!(template.contains("**/.report/**"));

        // Should include wildcard report pattern (e.g., playwright-report, test-report)
        assert!(template.contains("**/*report*/**"));

        // Should include log patterns
        assert!(template.contains("**/logs/**"));
        assert!(template.contains("**/*.log"));
    }

    #[test]
    fn test_template_includes_common_build_artifacts() {
        let template = Config::generate_template();

        // Build outputs
        assert!(template.contains("**/target/**"));
        assert!(template.contains("**/dist/**"));
        assert!(template.contains("**/build/**"));
        assert!(template.contains("**/out/**"));

        // Package managers
        assert!(template.contains("**/node_modules/**"));
        assert!(template.contains("**/.pnpm/**"));
        assert!(template.contains("**/.pnpm-store/**"));
        assert!(template.contains("**/.yarn/**"));
        assert!(template.contains("**/.npm/**"));
        assert!(template.contains("**/.pnp.*"));
        assert!(template.contains("**/jspm_packages/**"));

        // Version control
        assert!(template.contains("**/.git/**"));
        assert!(template.contains("**/.svn/**"));
    }

    #[test]
    fn test_template_includes_framework_specific_patterns() {
        let template = Config::generate_template();

        // JavaScript/TypeScript frameworks
        assert!(template.contains("**/.next/**"));
        assert!(template.contains("**/.nuxt/**"));
        assert!(template.contains("**/.svelte-kit/**"));
        assert!(template.contains("**/.astro/**"));
    }

    #[test]
    fn test_template_includes_cache_and_temp_patterns() {
        let template = Config::generate_template();

        // Cache directories
        assert!(template.contains("**/.cache/**"));
        assert!(template.contains("**/.vite/**"));
        assert!(template.contains("**/.webpack/**"));

        // Temporary files
        assert!(template.contains("**/tmp/**"));
        assert!(template.contains("**/temp/**"));
        assert!(template.contains("**/*.tmp"));
        assert!(template.contains("**/*.bak"));
    }

    #[test]
    fn test_template_includes_python_patterns() {
        let template = Config::generate_template();

        assert!(template.contains("**/__pycache__/**"));
        assert!(template.contains("**/.pytest_cache/**"));
        assert!(template.contains("**/.venv/**"));
        assert!(template.contains("**/venv/**"));
    }

    #[test]
    fn test_template_includes_coverage_patterns() {
        let template = Config::generate_template();

        assert!(template.contains("**/coverage/**"));
        assert!(template.contains("**/.nyc_output/**"));
        assert!(template.contains("**/htmlcov/**"));
    }

    #[test]
    fn test_template_includes_os_specific_patterns() {
        let template = Config::generate_template();

        // macOS
        assert!(template.contains("**/.DS_Store"));

        // Windows
        assert!(template.contains("**/Thumbs.db"));
        assert!(template.contains("**/desktop.ini"));
    }

    #[test]
    fn test_template_includes_severity_configuration() {
        let template = Config::generate_template();

        assert!(template.contains("# RULE SEVERITY CONFIGURATION"));
        assert!(template.contains("severity:"));
        assert!(template.contains("default: error"));
    }

    #[test]
    fn test_template_includes_scan_configuration() {
        let template = Config::generate_template();

        assert!(template.contains("# SCAN CONFIGURATION"));
        assert!(template.contains("scan:"));
    }

    #[test]
    fn test_template_includes_baseline_configuration() {
        let template = Config::generate_template();

        assert!(template.contains("# BASELINE CONFIGURATION"));
        assert!(template.contains("baseline:"));
    }

    #[test]
    fn test_template_includes_watch_configuration() {
        let template = Config::generate_template();

        assert!(template.contains("# WATCH MODE CONFIGURATION"));
        assert!(template.contains("watch:"));
        assert!(template.contains("debounce_ms:"));
    }

    #[test]
    fn test_template_includes_generated_and_minified_files() {
        let template = Config::generate_template();

        // Minified files (v3.2.0)
        assert!(template.contains("\"*.min.js\""));
        assert!(template.contains("\"*.min.css\""));

        // Generated files (v3.2.0)
        assert!(template.contains("\"*.d.ts\""));
        assert!(template.contains("\"*.generated.*\""));
        assert!(template.contains("\"*.g.ts\""));
        assert!(template.contains("\"*.g.dart\""));

        // Source maps (v3.2.0)
        assert!(template.contains("\"*.map\""));

        // Bundle outputs (v3.2.0)
        assert!(template.contains("\"**/bundle.*\""));
        assert!(template.contains("\"**/chunk-*\""));
    }
}
