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
}
