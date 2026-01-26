//! Configuration loading functions.

use std::fs;
use std::path::Path;

use super::error::ConfigError;
use super::types::Config;

impl Config {
    /// Load configuration from a file.
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

    /// Load configuration from the project directory or global config.
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
}
