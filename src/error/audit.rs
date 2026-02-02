//! Unified error type for cc-audit.

use std::path::PathBuf;
use thiserror::Error;

use super::context::{IoOperation, ParseFormat};

/// Unified error type for all cc-audit operations.
#[derive(Error, Debug)]
pub enum CcAuditError {
    /// I/O operation failed.
    #[error("Failed to {operation} {path}: {source}")]
    Io {
        path: PathBuf,
        operation: IoOperation,
        #[source]
        source: std::io::Error,
    },

    /// Parse error with preserved source.
    #[error("Failed to parse {format} in {path}")]
    Parse {
        path: PathBuf,
        format: ParseFormat,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// File not found.
    #[error("File not found: {0}")]
    FileNotFound(PathBuf),

    /// Path is not a directory.
    #[error("Path is not a directory: {0}")]
    NotADirectory(PathBuf),

    /// Path is not a file.
    #[error("Path is not a file: {0}")]
    NotAFile(PathBuf),

    /// Invalid format with message.
    #[error("Invalid format in {path}: {message}")]
    InvalidFormat { path: PathBuf, message: String },

    /// Regex compilation error.
    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    /// Hook operation failed.
    #[error("Hook error: {0}")]
    Hook(#[from] crate::hooks::HookError),

    /// Malware database error.
    #[error("Malware database error: {0}")]
    MalwareDb(#[from] crate::malware_db::MalwareDbError),

    /// File watch error.
    #[error("Watch error: {0}")]
    Watch(#[from] notify::Error),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// YAML parse error (legacy compatibility).
    #[error("YAML parse error in {path}: {source}")]
    YamlParse {
        path: String,
        #[source]
        source: serde_yml::Error,
    },

    /// Invalid skill format (legacy compatibility).
    #[error("Invalid SKILL.md format: {0}")]
    InvalidSkillFormat(String),

    /// JSON error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

impl CcAuditError {
    /// Create an I/O read error.
    pub fn read_error(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            operation: IoOperation::Read,
            source,
        }
    }

    /// Create an I/O write error.
    pub fn write_error(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            operation: IoOperation::Write,
            source,
        }
    }

    /// Create a parse error with JSON format.
    pub fn json_parse_error(path: impl Into<PathBuf>, source: serde_json::Error) -> Self {
        Self::Parse {
            path: path.into(),
            format: ParseFormat::Json,
            source: Box::new(source),
        }
    }

    /// Create a parse error with YAML format.
    pub fn yaml_parse_error(path: impl Into<PathBuf>, source: serde_yml::Error) -> Self {
        Self::Parse {
            path: path.into(),
            format: ParseFormat::Yaml,
            source: Box::new(source),
        }
    }

    /// Create a parse error with TOML format.
    pub fn toml_parse_error(path: impl Into<PathBuf>, source: toml::de::Error) -> Self {
        Self::Parse {
            path: path.into(),
            format: ParseFormat::Toml,
            source: Box::new(source),
        }
    }

    /// Get the root cause of the error chain.
    pub fn root_cause(&self) -> &dyn std::error::Error {
        let mut current: &dyn std::error::Error = self;
        while let Some(source) = current.source() {
            current = source;
        }
        current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_read_error() {
        let err = CcAuditError::read_error(
            "/path/to/file",
            io::Error::new(io::ErrorKind::NotFound, "not found"),
        );
        assert!(err.to_string().contains("/path/to/file"));
        assert!(err.to_string().contains("read"));
    }

    #[test]
    fn test_write_error() {
        let err = CcAuditError::write_error(
            "/path/to/file",
            io::Error::new(io::ErrorKind::PermissionDenied, "denied"),
        );
        assert!(err.to_string().contains("/path/to/file"));
        assert!(err.to_string().contains("write"));
    }

    #[test]
    fn test_file_not_found() {
        let err = CcAuditError::FileNotFound(PathBuf::from("/missing/file"));
        assert!(err.to_string().contains("/missing/file"));
    }

    #[test]
    fn test_root_cause() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "root cause");
        let err = CcAuditError::read_error("/path", io_err);
        let root = err.root_cause();
        assert!(root.to_string().contains("root cause"));
    }

    #[test]
    fn test_json_parse_error() {
        let json_str = "{ invalid }";
        let json_err = serde_json::from_str::<serde_json::Value>(json_str).unwrap_err();
        let err = CcAuditError::json_parse_error("/test.json", json_err);
        assert!(err.to_string().contains("/test.json"));
        assert!(err.to_string().contains("JSON"));
    }

    #[test]
    fn test_yaml_parse_error() {
        let yaml_str = "invalid: yaml: content";
        let yaml_err = serde_yml::from_str::<serde_yml::Value>(yaml_str).unwrap_err();
        let err = CcAuditError::yaml_parse_error("/test.yaml", yaml_err);
        assert!(err.to_string().contains("/test.yaml"));
        assert!(err.to_string().contains("YAML"));
    }

    #[test]
    fn test_toml_parse_error() {
        let toml_str = "invalid toml [";
        let toml_err = toml::from_str::<toml::Value>(toml_str).unwrap_err();
        let err = CcAuditError::toml_parse_error("/test.toml", toml_err);
        assert!(err.to_string().contains("/test.toml"));
        assert!(err.to_string().contains("TOML"));
    }

    #[test]
    fn test_not_a_directory() {
        let err = CcAuditError::NotADirectory(PathBuf::from("/test/file"));
        assert!(err.to_string().contains("/test/file"));
    }

    #[test]
    fn test_not_a_file() {
        let err = CcAuditError::NotAFile(PathBuf::from("/test/dir"));
        assert!(err.to_string().contains("/test/dir"));
    }

    #[test]
    fn test_invalid_format() {
        let err = CcAuditError::InvalidFormat {
            path: PathBuf::from("/test/file"),
            message: "missing field".to_string(),
        };
        assert!(err.to_string().contains("/test/file"));
        assert!(err.to_string().contains("missing field"));
    }

    #[test]
    fn test_config_error() {
        let err = CcAuditError::Config("invalid value".to_string());
        assert!(err.to_string().contains("invalid value"));
    }

    #[test]
    fn test_invalid_skill_format() {
        let err = CcAuditError::InvalidSkillFormat("missing frontmatter".to_string());
        assert!(err.to_string().contains("missing frontmatter"));
    }

    #[test]
    fn test_error_debug() {
        let err = CcAuditError::FileNotFound(PathBuf::from("/test"));
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("FileNotFound"));
    }

    #[test]
    fn test_root_cause_no_source() {
        let err = CcAuditError::Config("test".to_string());
        let root = err.root_cause();
        // For errors without source, root cause is the error itself
        assert!(root.to_string().contains("test"));
    }
}
