//! Handler-specific error types.

use std::path::PathBuf;
use thiserror::Error;

/// Error type for CLI handler operations.
#[derive(Error, Debug)]
pub enum HandlerError {
    #[error("Configuration file already exists: {0}")]
    ConfigAlreadyExists(PathBuf),

    #[error("Failed to write file: {path}")]
    WriteError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to read file: {path}")]
    ReadError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Scan failed for {path}: {reason}")]
    ScanFailed { path: PathBuf, reason: String },

    #[error("Invalid arguments: {0}")]
    InvalidArguments(String),

    #[error("Hook operation failed")]
    HookError(#[from] crate::hooks::HookError),

    #[error("Remote operation failed")]
    RemoteError(#[from] crate::remote::RemoteError),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Baseline operation failed: {0}")]
    BaselineError(String),

    #[error("Watch mode error: {0}")]
    WatchError(String),

    #[error("No paths specified")]
    NoPathsSpecified,

    #[error("Path not found: {0}")]
    PathNotFound(PathBuf),
}

impl HandlerError {
    /// Create a WriteError from a path and IO error.
    pub fn write_error(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::WriteError {
            path: path.into(),
            source,
        }
    }

    /// Create a ReadError from a path and IO error.
    pub fn read_error(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::ReadError {
            path: path.into(),
            source,
        }
    }

    /// Create a ScanFailed error.
    pub fn scan_failed(path: impl Into<PathBuf>, reason: impl Into<String>) -> Self {
        Self::ScanFailed {
            path: path.into(),
            reason: reason.into(),
        }
    }
}

/// Result type alias for handler operations.
pub type HandlerResult<T> = std::result::Result<T, HandlerError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_already_exists() {
        let err = HandlerError::ConfigAlreadyExists(PathBuf::from("/path/to/config"));
        assert!(err.to_string().contains("/path/to/config"));
    }

    #[test]
    fn test_write_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err = HandlerError::write_error("/path/to/file", io_err);
        assert!(err.to_string().contains("/path/to/file"));
    }

    #[test]
    fn test_scan_failed() {
        let err = HandlerError::scan_failed("/scan/path", "timeout");
        assert!(err.to_string().contains("/scan/path"));
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn test_invalid_arguments() {
        let err = HandlerError::InvalidArguments("missing required field".to_string());
        assert!(err.to_string().contains("missing required field"));
    }
}
