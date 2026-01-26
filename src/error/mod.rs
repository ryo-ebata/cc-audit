//! Error types for cc-audit.
//!
//! This module provides a unified error handling system with:
//! - `CcAuditError`: The new unified error type with full context preservation
//! - `AuditError`: Legacy error type for backwards compatibility
//! - Context types for better error messages

mod audit;
mod context;

pub use audit::CcAuditError;
pub use context::{IoOperation, ParseFormat};

use crate::hooks::HookError;
use crate::malware_db::MalwareDbError;
use thiserror::Error;

/// Legacy error type for backwards compatibility.
///
/// New code should prefer using `CcAuditError` for better error context.
#[derive(Error, Debug)]
pub enum AuditError {
    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Failed to read file: {path}")]
    ReadError {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse YAML frontmatter: {path}")]
    YamlParseError {
        path: String,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("Invalid SKILL.md format: {0}")]
    InvalidSkillFormat(String),

    #[error("Regex compilation error: {0}")]
    RegexError(#[from] regex::Error),

    #[error("Path is not a directory: {0}")]
    NotADirectory(String),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("Failed to parse file: {path} - {message}")]
    ParseError { path: String, message: String },

    #[error("Hook operation failed: {0}")]
    Hook(#[from] HookError),

    #[error("Malware database error: {0}")]
    MalwareDb(#[from] MalwareDbError),

    #[error("File watch error: {0}")]
    Watch(#[from] notify::Error),

    #[error("Configuration error: {0}")]
    Config(String),
}

/// Result type alias for operations using the legacy AuditError.
pub type Result<T> = std::result::Result<T, AuditError>;

/// Result type alias for operations using the new CcAuditError.
pub type CcResult<T> = std::result::Result<T, CcAuditError>;

/// Convert from CcAuditError to AuditError for backwards compatibility.
impl From<CcAuditError> for AuditError {
    fn from(err: CcAuditError) -> Self {
        match err {
            CcAuditError::Io { path, source, .. } => AuditError::ReadError {
                path: path.display().to_string(),
                source,
            },
            CcAuditError::Parse { path, .. } => AuditError::ParseError {
                path: path.display().to_string(),
                message: "parse error".to_string(),
            },
            CcAuditError::FileNotFound(path) => {
                AuditError::FileNotFound(path.display().to_string())
            }
            CcAuditError::NotADirectory(path) => {
                AuditError::NotADirectory(path.display().to_string())
            }
            CcAuditError::NotAFile(path) => AuditError::NotADirectory(path.display().to_string()),
            CcAuditError::InvalidFormat { path, message } => AuditError::ParseError {
                path: path.display().to_string(),
                message,
            },
            CcAuditError::Regex(e) => AuditError::RegexError(e),
            CcAuditError::Hook(e) => AuditError::Hook(e),
            CcAuditError::MalwareDb(e) => AuditError::MalwareDb(e),
            CcAuditError::Watch(e) => AuditError::Watch(e),
            CcAuditError::Config(s) => AuditError::Config(s),
            CcAuditError::YamlParse { path, source } => AuditError::YamlParseError { path, source },
            CcAuditError::InvalidSkillFormat(s) => AuditError::InvalidSkillFormat(s),
            CcAuditError::Json(e) => AuditError::JsonError(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_file_not_found() {
        let err = AuditError::FileNotFound("/path/to/file".to_string());
        assert_eq!(err.to_string(), "File not found: /path/to/file");
    }

    #[test]
    fn test_error_display_read_error() {
        let err = AuditError::ReadError {
            path: "/path/to/file".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
        };
        assert_eq!(err.to_string(), "Failed to read file: /path/to/file");
    }

    #[test]
    fn test_error_display_invalid_skill_format() {
        let err = AuditError::InvalidSkillFormat("missing frontmatter".to_string());
        assert_eq!(
            err.to_string(),
            "Invalid SKILL.md format: missing frontmatter"
        );
    }

    #[test]
    fn test_error_display_not_a_directory() {
        let err = AuditError::NotADirectory("/path/to/file".to_string());
        assert_eq!(err.to_string(), "Path is not a directory: /path/to/file");
    }

    #[test]
    fn test_error_display_parse_error() {
        let err = AuditError::ParseError {
            path: "/path/to/file".to_string(),
            message: "invalid JSON".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Failed to parse file: /path/to/file - invalid JSON"
        );
    }

    #[test]
    fn test_error_from_hook_error() {
        let hook_error = HookError::NotAGitRepository;
        let err: AuditError = hook_error.into();
        assert!(err.to_string().contains("Hook operation failed"));
    }

    #[test]
    fn test_error_from_malware_db_error() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let malware_error = MalwareDbError::ReadFile(io_error);
        let err: AuditError = malware_error.into();
        assert!(err.to_string().contains("Malware database error"));
    }

    #[test]
    fn test_error_display_config() {
        let err = AuditError::Config("invalid value".to_string());
        assert_eq!(err.to_string(), "Configuration error: invalid value");
    }

    #[test]
    fn test_cc_audit_error_to_audit_error() {
        let cc_err = CcAuditError::FileNotFound(std::path::PathBuf::from("/test/path"));
        let audit_err: AuditError = cc_err.into();
        assert!(audit_err.to_string().contains("/test/path"));
    }
}
