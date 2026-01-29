//! Configuration loading functions.

use std::fs;
use std::path::{Path, PathBuf};
use tracing::debug;

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

        debug!(project_root = ?project_root, "Searching for configuration file");

        // Walk up directory tree to find config file (like git finds .git)
        if let Some(root) = project_root {
            // Canonicalize to resolve relative paths (e.g., "subdir" -> "/abs/path/subdir")
            // so that parent() traversal works correctly.
            let canonical = fs::canonicalize(root).unwrap_or_else(|e| {
                debug!(error = %e, path = %root.display(), "Failed to canonicalize project root, using as-is");
                root.to_path_buf()
            });

            let mut current = canonical.as_path();
            loop {
                debug!(directory = %current.display(), "Checking directory for config file");
                for filename in CONFIG_FILENAMES {
                    let path = current.join(filename);
                    if path.exists() {
                        debug!(path = %path.display(), "Found configuration file");
                        return Some(path);
                    }
                }

                match current.parent() {
                    Some(parent) if !parent.as_os_str().is_empty() => current = parent,
                    _ => {
                        debug!("Reached filesystem root, stopping search");
                        break;
                    }
                }
            }
        }

        // Fall back to global config (~/.config/cc-audit/config.yaml)
        if let Some(config_dir) = dirs::config_dir() {
            let global_config = config_dir.join("cc-audit").join("config.yaml");
            if global_config.exists() {
                debug!(path = %global_config.display(), "Found global configuration file");
                return Some(global_config);
            }
        }

        debug!("No configuration file found");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Helper to canonicalize and compare two paths for equality.
    fn assert_paths_eq(actual: &Path, expected: &Path) {
        assert_eq!(
            actual.canonicalize().unwrap(),
            expected.canonicalize().unwrap()
        );
    }

    #[test]
    fn test_find_config_file_walks_up_to_parent() {
        let temp_dir = TempDir::new().unwrap();
        let subdir = temp_dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();

        let config_path = temp_dir.path().join(".cc-audit.yaml");
        fs::write(&config_path, "# Test config\n").unwrap();

        let found = Config::find_config_file(Some(&subdir))
            .expect("should find config in parent directory");

        assert_paths_eq(&found, &config_path);
    }

    #[test]
    fn test_find_config_file_with_relative_path() {
        let temp_dir = TempDir::new().unwrap();
        let subdir = temp_dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();

        let config_path = temp_dir.path().join(".cc-audit.yaml");
        fs::write(&config_path, "# Test config\n").unwrap();

        // Temporarily change cwd so that a relative path resolves correctly.
        // NOTE: set_current_dir is process-global and not thread-safe.
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(temp_dir.path()).unwrap();
        let found = Config::find_config_file(Some(Path::new("subdir")));
        std::env::set_current_dir(original_dir).unwrap();

        assert!(found.is_some(), "should find config via relative path");
    }

    #[test]
    fn test_find_config_file_returns_none_when_missing() {
        let temp_dir = TempDir::new().unwrap();
        let subdir = temp_dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();

        let found = Config::find_config_file(Some(&subdir));

        assert!(found.is_none());
    }

    #[test]
    fn test_find_config_file_in_same_directory() {
        let temp_dir = TempDir::new().unwrap();

        let config_path = temp_dir.path().join(".cc-audit.yaml");
        fs::write(&config_path, "# Test config\n").unwrap();

        let found = Config::find_config_file(Some(temp_dir.path()))
            .expect("should find config in same directory");

        assert_paths_eq(&found, &config_path);
    }

    #[test]
    fn test_find_config_file_traverses_multiple_levels() {
        let temp_dir = TempDir::new().unwrap();
        let level3 = temp_dir.path().join("level1").join("level2").join("level3");
        fs::create_dir_all(&level3).unwrap();

        let config_path = temp_dir.path().join(".cc-audit.yaml");
        fs::write(&config_path, "# Test config\n").unwrap();

        let found =
            Config::find_config_file(Some(&level3)).expect("should find config 3 levels up");

        assert_paths_eq(&found, &config_path);
    }

    #[test]
    fn test_find_config_file_prefers_closest_config() {
        let temp_dir = TempDir::new().unwrap();
        let subdir = temp_dir.path().join("subdir");
        fs::create_dir(&subdir).unwrap();

        let parent_config = temp_dir.path().join(".cc-audit.yaml");
        let subdir_config = subdir.join(".cc-audit.yaml");
        fs::write(&parent_config, "# Parent config\n").unwrap();
        fs::write(&subdir_config, "# Subdir config\n").unwrap();

        let found = Config::find_config_file(Some(&subdir)).expect("should find closest config");

        assert_paths_eq(&found, &subdir_config);
    }
}
