//! Configuration type definitions.

use crate::malware_db::MalwareSignature;
use crate::rules::custom::YamlRule;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

use super::severity::SeverityConfig;

/// Main configuration structure for cc-audit.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Scan configuration (CLI options).
    pub scan: ScanConfig,
    /// Watch mode configuration.
    pub watch: WatchConfig,
    /// Text file detection configuration.
    pub text_files: TextFilesConfig,
    /// Ignore configuration for scanning.
    pub ignore: IgnoreConfig,
    /// Baseline configuration for drift detection.
    #[serde(default)]
    pub baseline: BaselineConfig,
    /// Rule severity configuration (v0.5.0).
    #[serde(default)]
    pub severity: SeverityConfig,
    /// Rule IDs to disable.
    #[serde(default)]
    pub disabled_rules: HashSet<String>,
    /// Custom rules defined in config file.
    #[serde(default)]
    pub rules: Vec<YamlRule>,
    /// Custom malware signatures defined in config file.
    #[serde(default)]
    pub malware_signatures: Vec<MalwareSignature>,
}

impl Config {
    /// Get the effective set of disabled rules (merges severity.ignore and disabled_rules).
    pub fn effective_disabled_rules(&self) -> HashSet<String> {
        let mut disabled = self.disabled_rules.clone();
        disabled.extend(self.severity.ignore.iter().cloned());
        disabled
    }

    /// Check if a rule should be ignored based on both disabled_rules and severity.ignore.
    pub fn is_rule_disabled(&self, rule_id: &str) -> bool {
        self.disabled_rules.contains(rule_id) || self.severity.ignore.contains(rule_id)
    }

    /// Get the RuleSeverity for a rule, considering both severity config and disabled_rules.
    pub fn get_rule_severity(&self, rule_id: &str) -> Option<crate::rules::RuleSeverity> {
        if self.is_rule_disabled(rule_id) {
            return None;
        }
        self.severity.get_rule_severity(rule_id)
    }
}

/// Scan configuration (corresponds to CLI options).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Output format: "terminal", "json", "sarif", "html", "markdown".
    pub format: Option<String>,
    /// Strict mode: show medium/low severity findings and treat warnings as errors.
    pub strict: bool,
    /// Scan type: "skill", "hook", "mcp", "command", "rules", "docker", "dependency", "subagent", "plugin".
    pub scan_type: Option<String>,
    /// Recursive scan.
    pub recursive: bool,
    /// CI mode: non-interactive output.
    pub ci: bool,
    /// Verbose output.
    pub verbose: bool,
    /// Minimum confidence level: "tentative", "firm", "certain".
    pub min_confidence: Option<String>,
    /// Skip comment lines when scanning.
    pub skip_comments: bool,
    /// Show fix hints in terminal output.
    pub fix_hint: bool,
    /// Use compact output format (disable friendly advice).
    pub compact: bool,
    /// Disable malware signature scanning.
    pub no_malware_scan: bool,
    /// Watch mode: continuously monitor files for changes.
    pub watch: bool,
    /// Path to a custom malware signatures database (JSON).
    pub malware_db: Option<String>,
    /// Path to a custom rules file (YAML format).
    pub custom_rules: Option<String>,
    /// Output file path (for HTML/JSON/SARIF output).
    pub output: Option<String>,
    /// Enable deep scan with deobfuscation.
    pub deep_scan: bool,
    /// Auto-fix issues (where possible).
    pub fix: bool,
    /// Preview auto-fix changes without applying them.
    pub fix_dry_run: bool,
    /// Warn-only mode: treat all findings as warnings (always exit 0).
    pub warn_only: bool,
    /// Minimum severity level to include: "critical", "high", "medium", "low".
    pub min_severity: Option<String>,
    /// Minimum rule severity to treat as errors: "error", "warn".
    pub min_rule_severity: Option<String>,
    /// Strict secrets mode: disable dummy key heuristics for test files.
    pub strict_secrets: bool,

    // ============ Remote Scanning Options (v1.1.0) ============
    /// Remote repository URL to scan.
    pub remote: Option<String>,
    /// Git reference to checkout (branch, tag, commit).
    pub git_ref: Option<String>,
    /// GitHub authentication token (also reads from GITHUB_TOKEN env var).
    pub remote_auth: Option<String>,
    /// Number of parallel clones for batch scanning.
    pub parallel_clones: Option<usize>,
    /// File containing list of repository URLs to scan.
    pub remote_list: Option<String>,
    /// Scan all repositories from awesome-claude-code.
    pub awesome_claude_code: bool,

    // ============ Badge Options (v1.1.0) ============
    /// Generate a badge for the scan result.
    pub badge: bool,
    /// Badge format: "markdown", "html", "json".
    pub badge_format: Option<String>,
    /// Show summary only (useful for batch scanning).
    pub summary: bool,

    // ============ Client Scan Options (v1.1.0) ============
    /// Scan all installed AI coding clients (Claude Code, Cursor, etc.).
    pub all_clients: bool,
    /// Specific client to scan: "claude-code", "cursor", "windsurf", "cline", "roo-code", "claude-desktop", "amazon-q".
    pub client: Option<String>,

    // ============ CVE Scan Options (v1.1.0) ============
    /// Disable CVE vulnerability scanning.
    pub no_cve_scan: bool,
    /// Path to a custom CVE database (JSON).
    pub cve_db: Option<String>,

    // ============ SBOM Options (v1.2.0) ============
    /// Generate SBOM (Software Bill of Materials).
    pub sbom: bool,
    /// SBOM output format: "cyclonedx", "spdx".
    pub sbom_format: Option<String>,
    /// Include npm dependencies in SBOM.
    pub sbom_npm: bool,
    /// Include Cargo dependencies in SBOM.
    pub sbom_cargo: bool,
}

/// Watch mode configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WatchConfig {
    /// Debounce duration in milliseconds.
    pub debounce_ms: u64,
    /// Poll interval in milliseconds.
    pub poll_interval_ms: u64,
}

impl Default for WatchConfig {
    fn default() -> Self {
        Self {
            debounce_ms: 300,
            poll_interval_ms: 500,
        }
    }
}

/// Baseline configuration for drift detection (rug pull prevention).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BaselineConfig {
    /// Create a baseline snapshot when scanning.
    pub enabled: bool,
    /// Check for drift against saved baseline.
    pub check_drift: bool,
    /// Path to save baseline to.
    pub save_to: Option<String>,
    /// Path to baseline file to compare against.
    pub compare_with: Option<String>,
}

/// Text file detection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TextFilesConfig {
    /// File extensions that should be treated as text.
    pub extensions: HashSet<String>,
    /// Special file names that should be treated as text (without extension).
    pub special_names: HashSet<String>,
}

impl Default for TextFilesConfig {
    fn default() -> Self {
        let extensions: HashSet<String> = [
            // Markdown and text
            "md",
            "txt",
            "rst",
            // Configuration
            "json",
            "yaml",
            "yml",
            "toml",
            "xml",
            "ini",
            "conf",
            "cfg",
            "env",
            // Shell
            "sh",
            "bash",
            "zsh",
            "fish",
            // Scripting
            "py",
            "rb",
            "pl",
            "pm",
            "lua",
            "r",
            // Web
            "js",
            "ts",
            "jsx",
            "tsx",
            "html",
            "css",
            "scss",
            "sass",
            "less",
            // Systems
            "rs",
            "go",
            "c",
            "cpp",
            "h",
            "hpp",
            "cc",
            "cxx",
            // JVM
            "java",
            "kt",
            "kts",
            "scala",
            "clj",
            "groovy",
            // .NET
            "cs",
            "fs",
            "vb",
            // Mobile
            "swift",
            "m",
            "mm",
            // Other languages
            "php",
            "ex",
            "exs",
            "hs",
            "ml",
            "vim",
            "el",
            "lisp",
            // Docker
            "dockerfile",
            // Build
            "makefile",
            "cmake",
            "gradle",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        let special_names: HashSet<String> = [
            "Dockerfile",
            "Makefile",
            "Rakefile",
            "Gemfile",
            "Podfile",
            "Vagrantfile",
            "Procfile",
            "LICENSE",
            "README",
            "CHANGELOG",
            "CONTRIBUTING",
            "AUTHORS",
            "CMakeLists.txt",
            "Justfile",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        Self {
            extensions,
            special_names,
        }
    }
}

impl TextFilesConfig {
    /// Check if a path should be treated as a text file.
    pub fn is_text_file(&self, path: &Path) -> bool {
        // Check by extension
        if let Some(ext) = path.extension().and_then(|e| e.to_str())
            && self.extensions.contains(&ext.to_lowercase())
        {
            return true;
        }

        // Check by filename (case-insensitive for special names)
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            // Check exact match first
            if self.special_names.contains(name) {
                return true;
            }
            // Check case-insensitive match
            let name_lower = name.to_lowercase();
            if self
                .special_names
                .iter()
                .any(|n| n.to_lowercase() == name_lower)
            {
                return true;
            }
        }

        false
    }
}

/// Ignore configuration for scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IgnoreConfig {
    /// Directories to ignore (e.g., ["node_modules", "target", ".git"]).
    pub directories: HashSet<String>,
    /// Glob patterns to ignore (e.g., ["*.log", "build/**"]).
    pub patterns: Vec<String>,
    /// Whether to include test directories in scan.
    pub include_tests: bool,
    /// Whether to include node_modules in scan.
    pub include_node_modules: bool,
    /// Whether to include vendor directories in scan.
    pub include_vendor: bool,
}

impl Default for IgnoreConfig {
    fn default() -> Self {
        let directories: HashSet<String> = [
            // Common build output directories
            "target",
            "dist",
            "build",
            "out",
            // Package manager directories
            "node_modules",
            ".pnpm",
            ".yarn",
            // Version control
            ".git",
            ".svn",
            ".hg",
            // IDE directories
            ".idea",
            ".vscode",
            // Cache directories
            ".cache",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            // Coverage directories
            "coverage",
            ".nyc_output",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        Self {
            directories,
            patterns: Vec::new(),
            include_tests: false,
            include_node_modules: false,
            include_vendor: false,
        }
    }
}
