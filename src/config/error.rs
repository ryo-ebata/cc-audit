//! Configuration error types.

/// Configuration loading error.
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
