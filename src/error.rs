use crate::hooks::HookError;
use crate::malware_db::MalwareDbError;
use thiserror::Error;

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

pub type Result<T> = std::result::Result<T, AuditError>;

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
}
