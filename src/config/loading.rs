//! Configuration loading functions.

use std::fs;
use std::path::{Path, PathBuf};

use super::error::ConfigError;
use super::types::Config;

/// Result of trying to find a configuration file.
#[derive(Debug)]
pub struct ConfigLoadResult {
    /// The loaded configuration.
    pub config: Config,
    /// The path to the configuration file, if found.
    pub path: Option<PathBuf>,
}

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

    /// Try to find a configuration file in the project directory or parent directories.
    /// Returns `None` if no configuration file is found.
    ///
    /// Search order:
    /// 1. Walk up from project root to find `.cc-audit.yaml`, `.yml`, `.json`, or `.toml`
    /// 2. `~/.config/cc-audit/config.yaml`
    pub fn find_config_file(project_root: Option<&Path>) -> Option<PathBuf> {
        const CONFIG_FILENAMES: &[&str] = &[
            ".cc-audit.yaml",
            ".cc-audit.yml",
            ".cc-audit.json",
            ".cc-audit.toml",
        ];

        // Walk up directory tree to find config file (like git finds .git)
        if let Some(root) = project_root {
            let mut current = root;
            loop {
                for filename in CONFIG_FILENAMES {
                    let path = current.join(filename);
                    if path.exists() {
                        return Some(path);
                    }
                }

                // Move to parent directory
                match current.parent() {
                    Some(parent) if !parent.as_os_str().is_empty() => {
                        current = parent;
                    }
                    _ => break,
                }
            }
        }

        // Try global config
        if let Some(config_dir) = dirs::config_dir() {
            let global_config = config_dir.join("cc-audit").join("config.yaml");
            if global_config.exists() {
                return Some(global_config);
            }
        }

        None
    }

    /// Try to load configuration from the project directory or global config.
    /// Returns both the configuration and the path where it was found.
    pub fn try_load(project_root: Option<&Path>) -> ConfigLoadResult {
        if let Some(path) = Self::find_config_file(project_root)
            && let Ok(config) = Self::from_file(&path)
        {
            return ConfigLoadResult {
                config,
                path: Some(path),
            };
        }

        ConfigLoadResult {
            config: Self::default(),
            path: None,
        }
    }

    /// Load configuration from the project directory or global config.
    /// Returns default configuration if no file is found.
    ///
    /// Search order:
    /// 1. `.cc-audit.yaml` in project root
    /// 2. `.cc-audit.json` in project root
    /// 3. `.cc-audit.toml` in project root
    /// 4. `~/.config/cc-audit/config.yaml`
    /// 5. Default configuration
    pub fn load(project_root: Option<&Path>) -> Self {
        Self::try_load(project_root).config
    }
}
