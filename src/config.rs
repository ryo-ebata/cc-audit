use crate::malware_db::MalwareSignature;
use crate::rules::custom::YamlRule;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

/// Main configuration structure for cc-audit
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Watch mode configuration
    pub watch: WatchConfig,
    /// Text file detection configuration
    pub text_files: TextFilesConfig,
    /// Custom rules defined in config file
    pub rules: Vec<YamlRule>,
    /// Custom malware signatures defined in config file
    pub malware_signatures: Vec<MalwareSignature>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            watch: WatchConfig::default(),
            text_files: TextFilesConfig::default(),
            rules: Vec::new(),
            malware_signatures: Vec::new(),
        }
    }
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
            "yaml" | "yml" => {
                serde_yaml::from_str(&content).map_err(|e| ConfigError::ParseYaml {
                    path: path.display().to_string(),
                    source: e,
                })
            }
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
            for filename in &[".cc-audit.yaml", ".cc-audit.yml", ".cc-audit.json", ".cc-audit.toml"] {
                let path = root.join(filename);
                if path.exists() {
                    if let Ok(config) = Self::from_file(&path) {
                        return config;
                    }
                }
            }
        }

        // Try global config
        if let Some(config_dir) = dirs::config_dir() {
            let global_config = config_dir.join("cc-audit").join("config.yaml");
            if global_config.exists() {
                if let Ok(config) = Self::from_file(&global_config) {
                    return config;
                }
            }
        }

        // Return default
        Self::default()
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
            "md", "txt", "rst",
            // Configuration
            "json", "yaml", "yml", "toml", "xml", "ini", "conf", "cfg", "env",
            // Shell
            "sh", "bash", "zsh", "fish",
            // Scripting
            "py", "rb", "pl", "pm", "lua", "r",
            // Web
            "js", "ts", "jsx", "tsx", "html", "css", "scss", "sass", "less",
            // Systems
            "rs", "go", "c", "cpp", "h", "hpp", "cc", "cxx",
            // JVM
            "java", "kt", "kts", "scala", "clj", "groovy",
            // .NET
            "cs", "fs", "vb",
            // Mobile
            "swift", "m", "mm",
            // Other languages
            "php", "ex", "exs", "hs", "ml", "vim", "el", "lisp",
            // Docker
            "dockerfile",
            // Build
            "makefile", "cmake", "gradle",
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
    /// Check if a path should be treated as a text file
    pub fn is_text_file(&self, path: &Path) -> bool {
        // Check by extension
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if self.extensions.contains(&ext.to_lowercase()) {
                return true;
            }
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
}
