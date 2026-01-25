use crate::malware_db::MalwareSignature;
use crate::rules::RuleSeverity;
use crate::rules::custom::YamlRule;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Main configuration structure for cc-audit
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Scan configuration (CLI options)
    pub scan: ScanConfig,
    /// Watch mode configuration
    pub watch: WatchConfig,
    /// Text file detection configuration
    pub text_files: TextFilesConfig,
    /// Ignore configuration for scanning
    pub ignore: IgnoreConfig,
    /// Baseline configuration for drift detection
    #[serde(default)]
    pub baseline: BaselineConfig,
    /// Rule severity configuration (v0.5.0)
    #[serde(default)]
    pub severity: SeverityConfig,
    /// Rule IDs to disable
    #[serde(default)]
    pub disabled_rules: HashSet<String>,
    /// Custom rules defined in config file
    #[serde(default)]
    pub rules: Vec<YamlRule>,
    /// Custom malware signatures defined in config file
    #[serde(default)]
    pub malware_signatures: Vec<MalwareSignature>,
}

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
    /// Default severity for all rules (error by default)
    pub default: RuleSeverity,
    /// Rule IDs to treat as warnings (report only, exit 0)
    #[serde(default)]
    pub warn: HashSet<String>,
    /// Rule IDs to ignore completely (no report)
    /// Note: These are merged with disabled_rules
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

/// Scan configuration (corresponds to CLI options)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    /// Output format: "terminal", "json", "sarif", "html"
    pub format: Option<String>,
    /// Strict mode: show medium/low severity findings and treat warnings as errors
    pub strict: bool,
    /// Scan type: "skill", "hook", "mcp", "command", "rules", "docker", "dependency", "subagent", "plugin"
    pub scan_type: Option<String>,
    /// Recursive scan
    pub recursive: bool,
    /// CI mode: non-interactive output
    pub ci: bool,
    /// Verbose output
    pub verbose: bool,
    /// Minimum confidence level: "tentative", "firm", "certain"
    pub min_confidence: Option<String>,
    /// Skip comment lines when scanning
    pub skip_comments: bool,
    /// Show fix hints in terminal output
    pub fix_hint: bool,
    /// Disable malware signature scanning
    pub no_malware_scan: bool,
    /// Watch mode: continuously monitor files for changes
    pub watch: bool,
    /// Path to a custom malware signatures database (JSON)
    pub malware_db: Option<String>,
    /// Path to a custom rules file (YAML format)
    pub custom_rules: Option<String>,
    /// Output file path (for HTML/JSON/SARIF output)
    pub output: Option<String>,
    /// Enable deep scan with deobfuscation
    pub deep_scan: bool,
    /// Auto-fix issues (where possible)
    pub fix: bool,
    /// Preview auto-fix changes without applying them
    pub fix_dry_run: bool,
}

impl Config {
    /// Load configuration from a file
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path).map_err(|e| ConfigError::ReadFile {
            path: path.display().to_string(),
            source: e,
        })?;

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        match ext.as_str() {
            "yaml" | "yml" => serde_yaml::from_str(&content).map_err(|e| ConfigError::ParseYaml {
                path: path.display().to_string(),
                source: e,
            }),
            "json" => serde_json::from_str(&content).map_err(|e| ConfigError::ParseJson {
                path: path.display().to_string(),
                source: e,
            }),
            "toml" => toml::from_str(&content).map_err(|e| ConfigError::ParseToml {
                path: path.display().to_string(),
                source: e,
            }),
            _ => Err(ConfigError::UnsupportedFormat(
                path.display().to_string(),
                ext,
            )),
        }
    }

    /// Load configuration from the project directory or global config
    ///
    /// Search order:
    /// 1. `.cc-audit.yaml` in project root
    /// 2. `.cc-audit.json` in project root
    /// 3. `.cc-audit.toml` in project root
    /// 4. `~/.config/cc-audit/config.yaml`
    /// 5. Default configuration
    pub fn load(project_root: Option<&Path>) -> Self {
        // Try project-level config files
        if let Some(root) = project_root {
            for filename in &[
                ".cc-audit.yaml",
                ".cc-audit.yml",
                ".cc-audit.json",
                ".cc-audit.toml",
            ] {
                let path = root.join(filename);
                if path.exists()
                    && let Ok(config) = Self::from_file(&path)
                {
                    return config;
                }
            }
        }

        // Try global config
        if let Some(config_dir) = dirs::config_dir() {
            let global_config = config_dir.join("cc-audit").join("config.yaml");
            if global_config.exists()
                && let Ok(config) = Self::from_file(&global_config)
            {
                return config;
            }
        }

        // Return default
        Self::default()
    }

    /// Get the effective set of disabled rules (merges severity.ignore and disabled_rules)
    pub fn effective_disabled_rules(&self) -> HashSet<String> {
        let mut disabled = self.disabled_rules.clone();
        disabled.extend(self.severity.ignore.iter().cloned());
        disabled
    }

    /// Check if a rule should be ignored based on both disabled_rules and severity.ignore
    pub fn is_rule_disabled(&self, rule_id: &str) -> bool {
        self.disabled_rules.contains(rule_id) || self.severity.ignore.contains(rule_id)
    }

    /// Get the RuleSeverity for a rule, considering both severity config and disabled_rules
    pub fn get_rule_severity(&self, rule_id: &str) -> Option<crate::rules::RuleSeverity> {
        if self.is_rule_disabled(rule_id) {
            return None;
        }
        self.severity.get_rule_severity(rule_id)
    }

    /// Generate a YAML configuration template with comments
    pub fn generate_template() -> String {
        r#"# cc-audit Configuration File
# Place this file as .cc-audit.yaml in your project root

# =============================================================================
# RULE SEVERITY CONFIGURATION (v0.5.0)
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
  # Output format: terminal, json, sarif, html
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

/// Watch mode configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WatchConfig {
    /// Debounce duration in milliseconds
    pub debounce_ms: u64,
    /// Poll interval in milliseconds
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

/// Baseline configuration for drift detection (rug pull prevention)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BaselineConfig {
    /// Create a baseline snapshot when scanning
    pub enabled: bool,
    /// Check for drift against saved baseline
    pub check_drift: bool,
    /// Path to save baseline to
    pub save_to: Option<String>,
    /// Path to baseline file to compare against
    pub compare_with: Option<String>,
}

/// Text file detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TextFilesConfig {
    /// File extensions that should be treated as text
    pub extensions: HashSet<String>,
    /// Special file names that should be treated as text (without extension)
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

/// Ignore configuration for scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IgnoreConfig {
    /// Directories to ignore (e.g., ["node_modules", "target", ".git"])
    pub directories: HashSet<String>,
    /// Glob patterns to ignore (e.g., ["*.log", "build/**"])
    pub patterns: Vec<String>,
    /// Whether to include test directories in scan
    pub include_tests: bool,
    /// Whether to include node_modules in scan
    pub include_node_modules: bool,
    /// Whether to include vendor directories in scan
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

impl TextFilesConfig {
    /// Check if a path should be treated as a text file
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

/// Configuration loading error
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to read config file {path}: {source}")]
    ReadFile {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse YAML config {path}: {source}")]
    ParseYaml {
        path: String,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("Failed to parse JSON config {path}: {source}")]
    ParseJson {
        path: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("Failed to parse TOML config {path}: {source}")]
    ParseToml {
        path: String,
        #[source]
        source: toml::de::Error,
    },

    #[error("Unsupported config format for {0}: .{1}")]
    UnsupportedFormat(String, String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.watch.debounce_ms, 300);
        assert_eq!(config.watch.poll_interval_ms, 500);
        assert!(config.text_files.extensions.contains("md"));
        assert!(config.text_files.extensions.contains("py"));
    }

    #[test]
    fn test_is_text_file_by_extension() {
        let config = TextFilesConfig::default();
        assert!(config.is_text_file(Path::new("test.md")));
        assert!(config.is_text_file(Path::new("test.py")));
        assert!(config.is_text_file(Path::new("test.rs")));
        assert!(config.is_text_file(Path::new("test.json")));
        assert!(!config.is_text_file(Path::new("test.exe")));
        assert!(!config.is_text_file(Path::new("test.bin")));
    }

    #[test]
    fn test_is_text_file_by_name() {
        let config = TextFilesConfig::default();
        assert!(config.is_text_file(Path::new("Dockerfile")));
        assert!(config.is_text_file(Path::new("Makefile")));
        assert!(config.is_text_file(Path::new("LICENSE")));
        assert!(!config.is_text_file(Path::new("unknown_file")));
    }

    #[test]
    fn test_is_text_file_case_insensitive_extension() {
        let config = TextFilesConfig::default();
        assert!(config.is_text_file(Path::new("test.MD")));
        assert!(config.is_text_file(Path::new("test.PY")));
        assert!(config.is_text_file(Path::new("test.Json")));
    }

    #[test]
    fn test_load_yaml_config() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
watch:
  debounce_ms: 500
  poll_interval_ms: 1000
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.watch.debounce_ms, 500);
        assert_eq!(config.watch.poll_interval_ms, 1000);
    }

    #[test]
    fn test_load_json_config() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.json");
        fs::write(
            &config_path,
            r#"{"watch": {"debounce_ms": 200, "poll_interval_ms": 400}}"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.watch.debounce_ms, 200);
        assert_eq!(config.watch.poll_interval_ms, 400);
    }

    #[test]
    fn test_load_toml_config() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.toml");
        fs::write(
            &config_path,
            r#"
[watch]
debounce_ms = 600
poll_interval_ms = 800
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.watch.debounce_ms, 600);
        assert_eq!(config.watch.poll_interval_ms, 800);
    }

    #[test]
    fn test_load_with_project_config() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
watch:
  debounce_ms: 100
"#,
        )
        .unwrap();

        let config = Config::load(Some(dir.path()));
        assert_eq!(config.watch.debounce_ms, 100);
    }

    #[test]
    fn test_load_fallback_to_default() {
        let dir = TempDir::new().unwrap();
        let config = Config::load(Some(dir.path()));
        assert_eq!(config.watch.debounce_ms, 300); // Default value
    }

    #[test]
    fn test_unsupported_format_error() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.xml");
        fs::write(&config_path, "<config></config>").unwrap();

        let result = Config::from_file(&config_path);
        assert!(matches!(result, Err(ConfigError::UnsupportedFormat(_, _))));
    }

    #[test]
    fn test_partial_config_with_defaults() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
watch:
  debounce_ms: 999
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.watch.debounce_ms, 999);
        // poll_interval_ms should use default
        assert_eq!(config.watch.poll_interval_ms, 500);
    }

    #[test]
    fn test_config_error_read_file() {
        let result = Config::from_file(Path::new("/nonexistent/config.yaml"));
        assert!(matches!(result, Err(ConfigError::ReadFile { .. })));
    }

    #[test]
    fn test_custom_text_extensions() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
text_files:
  extensions:
    - custom
    - special
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert!(config.text_files.extensions.contains("custom"));
        assert!(config.text_files.extensions.contains("special"));
    }

    #[test]
    fn test_config_with_rules() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
rules:
  - id: "CUSTOM-001"
    name: "Test Rule"
    severity: "high"
    category: "exfiltration"
    patterns:
      - 'test_pattern'
    message: "Test message"
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].id, "CUSTOM-001");
        assert_eq!(config.rules[0].name, "Test Rule");
        assert_eq!(config.rules[0].severity, "high");
    }

    #[test]
    fn test_config_with_malware_signatures() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
malware_signatures:
  - id: "MW-CUSTOM-001"
    name: "Custom Malware"
    description: "Test malware pattern"
    pattern: "evil_pattern"
    severity: "critical"
    category: "exfiltration"
    confidence: "firm"
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.malware_signatures.len(), 1);
        assert_eq!(config.malware_signatures[0].id, "MW-CUSTOM-001");
        assert_eq!(config.malware_signatures[0].name, "Custom Malware");
        assert_eq!(config.malware_signatures[0].severity, "critical");
    }

    #[test]
    fn test_config_with_rules_and_malware_signatures() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
watch:
  debounce_ms: 100

rules:
  - id: "CUSTOM-001"
    name: "Test Rule"
    severity: "high"
    category: "exfiltration"
    patterns:
      - 'test_pattern'
    message: "Test message"

malware_signatures:
  - id: "MW-CUSTOM-001"
    name: "Custom Malware"
    description: "Test malware pattern"
    pattern: "evil_pattern"
    severity: "critical"
    category: "exfiltration"
    confidence: "firm"
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.watch.debounce_ms, 100);
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.malware_signatures.len(), 1);
    }

    #[test]
    fn test_default_config_has_empty_rules() {
        let config = Config::default();
        assert!(config.rules.is_empty());
        assert!(config.malware_signatures.is_empty());
    }

    #[test]
    fn test_parse_yaml_error() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(&config_path, "invalid: yaml: content: [").unwrap();

        let result = Config::from_file(&config_path);
        assert!(matches!(result, Err(ConfigError::ParseYaml { .. })));
    }

    #[test]
    fn test_parse_json_error() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.json");
        fs::write(&config_path, "{invalid json}").unwrap();

        let result = Config::from_file(&config_path);
        assert!(matches!(result, Err(ConfigError::ParseJson { .. })));
    }

    #[test]
    fn test_parse_toml_error() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.toml");
        fs::write(&config_path, "[invalid toml\nkey = ").unwrap();

        let result = Config::from_file(&config_path);
        assert!(matches!(result, Err(ConfigError::ParseToml { .. })));
    }

    #[test]
    fn test_load_with_invalid_config_falls_back() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        // Write invalid YAML that will fail to parse
        fs::write(&config_path, "invalid: yaml: [").unwrap();

        // Should fall back to default
        let config = Config::load(Some(dir.path()));
        assert_eq!(config.watch.debounce_ms, 300);
    }

    #[test]
    fn test_is_text_file_returns_false_for_unknown() {
        let config = TextFilesConfig::default();
        // No extension, not a special name
        assert!(!config.is_text_file(Path::new("somefile")));
        assert!(!config.is_text_file(Path::new("random_binary")));
    }

    #[test]
    fn test_ignore_config_default() {
        let config = IgnoreConfig::default();
        // Check that common directories are in the default ignore list
        assert!(config.directories.contains("node_modules"));
        assert!(config.directories.contains("target"));
        assert!(config.directories.contains(".git"));
        assert!(config.directories.contains("dist"));
        assert!(config.directories.contains("build"));
        // Default flags
        assert!(!config.include_tests);
        assert!(!config.include_node_modules);
        assert!(!config.include_vendor);
        // No custom patterns by default
        assert!(config.patterns.is_empty());
    }

    #[test]
    fn test_config_with_ignore_settings() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
ignore:
  directories:
    - custom_dir
    - my_cache
  patterns:
    - "*.log"
    - "temp/**"
  include_tests: true
  include_node_modules: false
  include_vendor: true
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert!(config.ignore.directories.contains("custom_dir"));
        assert!(config.ignore.directories.contains("my_cache"));
        assert_eq!(config.ignore.patterns.len(), 2);
        assert!(config.ignore.patterns.contains(&"*.log".to_string()));
        assert!(config.ignore.patterns.contains(&"temp/**".to_string()));
        assert!(config.ignore.include_tests);
        assert!(!config.ignore.include_node_modules);
        assert!(config.ignore.include_vendor);
    }

    #[test]
    fn test_config_with_disabled_rules() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
disabled_rules:
  - "PE-001"
  - "EX-002"
  - "CUSTOM-RULE"
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.disabled_rules.len(), 3);
        assert!(config.disabled_rules.contains("PE-001"));
        assert!(config.disabled_rules.contains("EX-002"));
        assert!(config.disabled_rules.contains("CUSTOM-RULE"));
    }

    #[test]
    fn test_default_config_has_empty_disabled_rules() {
        let config = Config::default();
        assert!(config.disabled_rules.is_empty());
    }

    #[test]
    fn test_config_ignore_default_when_partial() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
ignore:
  include_tests: true
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        // include_tests is set to true
        assert!(config.ignore.include_tests);
        // Other values should be default
        assert!(!config.ignore.include_node_modules);
        assert!(!config.ignore.include_vendor);
    }

    #[test]
    fn test_scan_config_default() {
        let config = ScanConfig::default();
        assert!(config.format.is_none());
        assert!(!config.strict);
        assert!(config.scan_type.is_none());
        assert!(!config.recursive);
        assert!(!config.ci);
        assert!(!config.verbose);
        assert!(config.min_confidence.is_none());
        assert!(!config.skip_comments);
        assert!(!config.fix_hint);
        assert!(!config.no_malware_scan);
        // New fields
        assert!(!config.watch);
        assert!(config.malware_db.is_none());
        assert!(config.custom_rules.is_none());
        assert!(config.output.is_none());
        assert!(!config.deep_scan);
        assert!(!config.fix);
        assert!(!config.fix_dry_run);
    }

    #[test]
    fn test_config_with_scan_settings() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
scan:
  format: json
  strict: true
  scan_type: docker
  recursive: true
  ci: true
  verbose: true
  min_confidence: firm
  skip_comments: true
  fix_hint: true
  no_malware_scan: true
  watch: true
  malware_db: ./custom-malware.json
  custom_rules: ./custom-rules.yaml
  output: ./report.html
  deep_scan: true
  fix: true
  fix_dry_run: true
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.scan.format, Some("json".to_string()));
        assert!(config.scan.strict);
        assert_eq!(config.scan.scan_type, Some("docker".to_string()));
        assert!(config.scan.recursive);
        assert!(config.scan.ci);
        assert!(config.scan.verbose);
        assert_eq!(config.scan.min_confidence, Some("firm".to_string()));
        assert!(config.scan.skip_comments);
        assert!(config.scan.fix_hint);
        assert!(config.scan.no_malware_scan);
        // New fields
        assert!(config.scan.watch);
        assert_eq!(
            config.scan.malware_db,
            Some("./custom-malware.json".to_string())
        );
        assert_eq!(
            config.scan.custom_rules,
            Some("./custom-rules.yaml".to_string())
        );
        assert_eq!(config.scan.output, Some("./report.html".to_string()));
        assert!(config.scan.deep_scan);
        assert!(config.scan.fix);
        assert!(config.scan.fix_dry_run);
    }

    #[test]
    fn test_config_with_partial_scan_settings() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
scan:
  strict: true
  verbose: true
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        // Set values
        assert!(config.scan.strict);
        assert!(config.scan.verbose);
        // Default values
        assert!(config.scan.format.is_none());
        assert!(config.scan.scan_type.is_none());
        assert!(!config.scan.recursive);
        assert!(!config.scan.ci);
        assert!(config.scan.min_confidence.is_none());
        assert!(!config.scan.skip_comments);
        assert!(!config.scan.fix_hint);
        assert!(!config.scan.no_malware_scan);
    }

    #[test]
    fn test_default_config_has_default_scan() {
        let config = Config::default();
        assert!(!config.scan.strict);
        assert!(!config.scan.verbose);
        assert!(config.scan.format.is_none());
    }

    #[test]
    fn test_generate_template() {
        let template = Config::generate_template();
        // Check that template contains key sections
        assert!(template.contains("# cc-audit Configuration File"));
        assert!(template.contains("severity:"));
        assert!(template.contains("default: error"));
        assert!(template.contains("scan:"));
        assert!(template.contains("watch:"));
        assert!(template.contains("ignore:"));
        assert!(template.contains("# disabled_rules:"));
        assert!(template.contains("# rules:"));
        assert!(template.contains("# malware_signatures:"));
    }

    #[test]
    fn test_generate_template_is_valid_yaml() {
        let template = Config::generate_template();
        // The template should be parseable as YAML (comments are ignored)
        let result: Result<Config, _> = serde_yaml::from_str(&template);
        assert!(result.is_ok(), "Template should be valid YAML");
    }

    // ========== SeverityConfig Tests ==========

    #[test]
    fn test_severity_config_default() {
        let config = SeverityConfig::default();
        assert_eq!(config.default, crate::rules::RuleSeverity::Error);
        assert!(config.warn.is_empty());
        assert!(config.ignore.is_empty());
    }

    #[test]
    fn test_severity_config_get_rule_severity_default() {
        let config = SeverityConfig::default();
        assert_eq!(
            config.get_rule_severity("EX-001"),
            Some(crate::rules::RuleSeverity::Error)
        );
    }

    #[test]
    fn test_severity_config_get_rule_severity_warn() {
        let mut config = SeverityConfig::default();
        config.warn.insert("PI-001".to_string());

        assert_eq!(
            config.get_rule_severity("PI-001"),
            Some(crate::rules::RuleSeverity::Warn)
        );
        assert_eq!(
            config.get_rule_severity("EX-001"),
            Some(crate::rules::RuleSeverity::Error)
        );
    }

    #[test]
    fn test_severity_config_get_rule_severity_ignore() {
        let mut config = SeverityConfig::default();
        config.ignore.insert("OP-001".to_string());

        assert_eq!(config.get_rule_severity("OP-001"), None);
        assert_eq!(
            config.get_rule_severity("EX-001"),
            Some(crate::rules::RuleSeverity::Error)
        );
    }

    #[test]
    fn test_severity_config_priority_ignore_over_warn() {
        let mut config = SeverityConfig::default();
        config.warn.insert("RULE-001".to_string());
        config.ignore.insert("RULE-001".to_string());

        // ignore takes priority over warn
        assert_eq!(config.get_rule_severity("RULE-001"), None);
    }

    #[test]
    fn test_config_severity_parsing() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
severity:
  default: warn
  warn:
    - PI-001
    - PI-002
  ignore:
    - OP-001
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.severity.default, crate::rules::RuleSeverity::Warn);
        assert!(config.severity.warn.contains("PI-001"));
        assert!(config.severity.warn.contains("PI-002"));
        assert!(config.severity.ignore.contains("OP-001"));
    }

    #[test]
    fn test_config_effective_disabled_rules() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
disabled_rules:
  - RULE-A
  - RULE-B
severity:
  ignore:
    - RULE-C
    - RULE-D
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        let effective = config.effective_disabled_rules();

        // Both disabled_rules and severity.ignore should be merged
        assert!(effective.contains("RULE-A"));
        assert!(effective.contains("RULE-B"));
        assert!(effective.contains("RULE-C"));
        assert!(effective.contains("RULE-D"));
        assert_eq!(effective.len(), 4);
    }

    #[test]
    fn test_config_is_rule_disabled() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
disabled_rules:
  - RULE-A
severity:
  ignore:
    - RULE-B
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert!(config.is_rule_disabled("RULE-A"));
        assert!(config.is_rule_disabled("RULE-B"));
        assert!(!config.is_rule_disabled("RULE-C"));
    }

    #[test]
    fn test_config_get_rule_severity() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
disabled_rules:
  - RULE-A
severity:
  default: error
  warn:
    - RULE-B
  ignore:
    - RULE-C
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();

        // RULE-A is in disabled_rules
        assert_eq!(config.get_rule_severity("RULE-A"), None);

        // RULE-B is in severity.warn
        assert_eq!(
            config.get_rule_severity("RULE-B"),
            Some(crate::rules::RuleSeverity::Warn)
        );

        // RULE-C is in severity.ignore
        assert_eq!(config.get_rule_severity("RULE-C"), None);

        // RULE-D uses default (error)
        assert_eq!(
            config.get_rule_severity("RULE-D"),
            Some(crate::rules::RuleSeverity::Error)
        );
    }

    // ========== BaselineConfig Tests ==========

    #[test]
    fn test_baseline_config_default() {
        let config = BaselineConfig::default();
        assert!(!config.enabled);
        assert!(!config.check_drift);
        assert!(config.save_to.is_none());
        assert!(config.compare_with.is_none());
    }

    #[test]
    fn test_config_with_baseline_settings() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
baseline:
  enabled: true
  check_drift: true
  save_to: ./.cc-audit-baseline.json
  compare_with: ./previous-baseline.json
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert!(config.baseline.enabled);
        assert!(config.baseline.check_drift);
        assert_eq!(
            config.baseline.save_to,
            Some("./.cc-audit-baseline.json".to_string())
        );
        assert_eq!(
            config.baseline.compare_with,
            Some("./previous-baseline.json".to_string())
        );
    }

    #[test]
    fn test_default_config_has_default_baseline() {
        let config = Config::default();
        assert!(!config.baseline.enabled);
        assert!(!config.baseline.check_drift);
        assert!(config.baseline.save_to.is_none());
        assert!(config.baseline.compare_with.is_none());
    }

    #[test]
    fn test_generate_template_contains_new_sections() {
        let template = Config::generate_template();
        // Check that template contains new sections
        assert!(template.contains("baseline:"));
        assert!(template.contains("deep_scan:"));
        assert!(template.contains("fix:"));
        assert!(template.contains("fix_dry_run:"));
        assert!(template.contains("malware_db:"));
        assert!(template.contains("custom_rules:"));
        assert!(template.contains("output:"));
        assert!(template.contains("subagent"));
        assert!(template.contains("plugin"));
    }
}
