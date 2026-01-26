//! Scanner-specific error types.

use std::path::PathBuf;
use thiserror::Error;

/// Error type for scanner operations.
#[derive(Error, Debug)]
pub enum ScanError {
    #[error("File not found: {0}")]
    FileNotFound(PathBuf),

    #[error("Path is not a file: {0}")]
    NotAFile(PathBuf),

    #[error("Path is not a directory: {0}")]
    NotADirectory(PathBuf),

    #[error("Failed to read file: {path}")]
    ReadError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse YAML in {path}")]
    YamlParseError {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("Failed to parse JSON in {path}")]
    JsonParseError {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("Invalid format in {path}: {message}")]
    InvalidFormat { path: PathBuf, message: String },

    #[error("Regex compilation error: {0}")]
    RegexError(#[from] regex::Error),
}

impl ScanError {
    /// Create a FileNotFound error from a path-like type.
    pub fn file_not_found(path: impl Into<PathBuf>) -> Self {
        Self::FileNotFound(path.into())
    }

    /// Create a NotADirectory error from a path-like type.
    pub fn not_a_directory(path: impl Into<PathBuf>) -> Self {
        Self::NotADirectory(path.into())
    }

    /// Create a ReadError from a path and IO error.
    pub fn read_error(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::ReadError {
            path: path.into(),
            source,
        }
    }

    /// Create a YamlParseError from a path and YAML error.
    pub fn yaml_error(path: impl Into<PathBuf>, source: serde_yaml::Error) -> Self {
        Self::YamlParseError {
            path: path.into(),
            source,
        }
    }

    /// Create a JsonParseError from a path and JSON error.
    pub fn json_error(path: impl Into<PathBuf>, source: serde_json::Error) -> Self {
        Self::JsonParseError {
            path: path.into(),
            source,
        }
    }

    /// Create an InvalidFormat error.
    pub fn invalid_format(path: impl Into<PathBuf>, message: impl Into<String>) -> Self {
        Self::InvalidFormat {
            path: path.into(),
            message: message.into(),
        }
    }
}

/// Result type alias for scanner operations.
pub type ScanResult<T> = std::result::Result<T, ScanError>;

/// Convert from ScanError to the legacy AuditError for backwards compatibility.
impl From<ScanError> for crate::error::AuditError {
    fn from(err: ScanError) -> Self {
        match err {
            ScanError::FileNotFound(path) => {
                crate::error::AuditError::FileNotFound(path.display().to_string())
            }
            ScanError::NotAFile(path) => {
                crate::error::AuditError::NotADirectory(path.display().to_string())
            }
            ScanError::NotADirectory(path) => {
                crate::error::AuditError::NotADirectory(path.display().to_string())
            }
            ScanError::ReadError { path, source } => crate::error::AuditError::ReadError {
                path: path.display().to_string(),
                source,
            },
            ScanError::YamlParseError { path, source } => {
                crate::error::AuditError::YamlParseError {
                    path: path.display().to_string(),
                    source,
                }
            }
            ScanError::JsonParseError { path, .. } => crate::error::AuditError::ParseError {
                path: path.display().to_string(),
                message: "JSON parse error".to_string(),
            },
            ScanError::InvalidFormat { path, message } => crate::error::AuditError::ParseError {
                path: path.display().to_string(),
                message,
            },
            ScanError::RegexError(e) => crate::error::AuditError::RegexError(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_file_not_found() {
        let err = ScanError::file_not_found("/path/to/file");
        assert!(err.to_string().contains("/path/to/file"));
    }

    #[test]
    fn test_not_a_directory() {
        let err = ScanError::not_a_directory(Path::new("/path/to/file"));
        assert!(err.to_string().contains("/path/to/file"));
    }

    #[test]
    fn test_read_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let err = ScanError::read_error("/path/to/file", io_err);
        assert!(err.to_string().contains("/path/to/file"));
    }

    #[test]
    fn test_invalid_format() {
        let err = ScanError::invalid_format("/path/to/file", "missing field");
        assert!(err.to_string().contains("/path/to/file"));
        assert!(err.to_string().contains("missing field"));
    }

    #[test]
    fn test_conversion_to_audit_error() {
        let scan_err = ScanError::file_not_found("/test/path");
        let audit_err: crate::error::AuditError = scan_err.into();
        assert!(audit_err.to_string().contains("/test/path"));
    }

    #[test]
    fn test_yaml_error() {
        let yaml_str = "invalid: yaml: content";
        let yaml_err = serde_yaml::from_str::<serde_yaml::Value>(yaml_str).unwrap_err();
        let err = ScanError::yaml_error("/path/to/file.yaml", yaml_err);
        assert!(err.to_string().contains("/path/to/file.yaml"));
    }

    #[test]
    fn test_json_error() {
        let json_str = "{ invalid json }";
        let json_err = serde_json::from_str::<serde_json::Value>(json_str).unwrap_err();
        let err = ScanError::json_error("/path/to/file.json", json_err);
        assert!(err.to_string().contains("/path/to/file.json"));
    }

    #[test]
    fn test_not_a_file() {
        let err = ScanError::NotAFile(PathBuf::from("/path/to/dir"));
        assert!(err.to_string().contains("/path/to/dir"));
    }

    #[test]
    fn test_conversion_not_a_file_to_audit_error() {
        let scan_err = ScanError::NotAFile(PathBuf::from("/test/dir"));
        let audit_err: crate::error::AuditError = scan_err.into();
        assert!(audit_err.to_string().contains("/test/dir"));
    }

    #[test]
    fn test_conversion_not_a_directory_to_audit_error() {
        let scan_err = ScanError::not_a_directory("/test/file");
        let audit_err: crate::error::AuditError = scan_err.into();
        assert!(audit_err.to_string().contains("/test/file"));
    }

    #[test]
    fn test_conversion_read_error_to_audit_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let scan_err = ScanError::read_error("/test/path", io_err);
        let audit_err: crate::error::AuditError = scan_err.into();
        assert!(audit_err.to_string().contains("/test/path"));
    }

    #[test]
    fn test_conversion_yaml_error_to_audit_error() {
        let yaml_str = "invalid: yaml: content";
        let yaml_err = serde_yaml::from_str::<serde_yaml::Value>(yaml_str).unwrap_err();
        let scan_err = ScanError::yaml_error("/test.yaml", yaml_err);
        let audit_err: crate::error::AuditError = scan_err.into();
        assert!(audit_err.to_string().contains("/test.yaml"));
    }

    #[test]
    fn test_conversion_json_error_to_audit_error() {
        let json_str = "{ invalid }";
        let json_err = serde_json::from_str::<serde_json::Value>(json_str).unwrap_err();
        let scan_err = ScanError::json_error("/test.json", json_err);
        let audit_err: crate::error::AuditError = scan_err.into();
        assert!(audit_err.to_string().contains("/test.json"));
    }

    #[test]
    fn test_conversion_invalid_format_to_audit_error() {
        let scan_err = ScanError::invalid_format("/test/file", "bad format");
        let audit_err: crate::error::AuditError = scan_err.into();
        assert!(audit_err.to_string().contains("bad format"));
    }

    #[test]
    #[allow(clippy::invalid_regex)]
    fn test_conversion_regex_error_to_audit_error() {
        let regex_err = regex::Regex::new(r"[invalid\[").unwrap_err();
        let scan_err = ScanError::RegexError(regex_err);
        let audit_err: crate::error::AuditError = scan_err.into();
        assert!(audit_err.to_string().contains("Regex"));
    }

    #[test]
    fn test_scan_error_debug() {
        let err = ScanError::file_not_found("/test");
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("FileNotFound"));
    }
}
