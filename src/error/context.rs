//! Error context types for better error messages.

/// I/O operation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOperation {
    Read,
    Write,
    Create,
    Delete,
    SetPermissions,
}

impl std::fmt::Display for IoOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
            Self::Create => write!(f, "create"),
            Self::Delete => write!(f, "delete"),
            Self::SetPermissions => write!(f, "set permissions"),
        }
    }
}

/// Parse format types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseFormat {
    Json,
    Yaml,
    Toml,
    Frontmatter,
}

impl std::fmt::Display for ParseFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json => write!(f, "JSON"),
            Self::Yaml => write!(f, "YAML"),
            Self::Toml => write!(f, "TOML"),
            Self::Frontmatter => write!(f, "frontmatter"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_io_operation_display() {
        assert_eq!(IoOperation::Read.to_string(), "read");
        assert_eq!(IoOperation::Write.to_string(), "write");
        assert_eq!(IoOperation::Create.to_string(), "create");
        assert_eq!(IoOperation::Delete.to_string(), "delete");
        assert_eq!(IoOperation::SetPermissions.to_string(), "set permissions");
    }

    #[test]
    fn test_parse_format_display() {
        assert_eq!(ParseFormat::Json.to_string(), "JSON");
        assert_eq!(ParseFormat::Yaml.to_string(), "YAML");
        assert_eq!(ParseFormat::Toml.to_string(), "TOML");
        assert_eq!(ParseFormat::Frontmatter.to_string(), "frontmatter");
    }

    #[test]
    fn test_io_operation_debug() {
        let op = IoOperation::Read;
        let debug_str = format!("{:?}", op);
        assert!(debug_str.contains("Read"));
    }

    #[test]
    fn test_io_operation_clone() {
        let op = IoOperation::Write;
        let cloned = op;
        assert_eq!(cloned, IoOperation::Write);
    }

    #[test]
    fn test_io_operation_copy() {
        let op = IoOperation::Create;
        let copied = op;
        assert_eq!(copied, IoOperation::Create);
    }

    #[test]
    fn test_parse_format_debug() {
        let fmt = ParseFormat::Json;
        let debug_str = format!("{:?}", fmt);
        assert!(debug_str.contains("Json"));
    }

    #[test]
    fn test_parse_format_clone() {
        let fmt = ParseFormat::Yaml;
        let cloned = fmt;
        assert_eq!(cloned, ParseFormat::Yaml);
    }

    #[test]
    fn test_parse_format_copy() {
        let fmt = ParseFormat::Toml;
        let copied = fmt;
        assert_eq!(copied, ParseFormat::Toml);
    }

    #[test]
    fn test_parse_format_equality() {
        assert_eq!(ParseFormat::Json, ParseFormat::Json);
        assert_ne!(ParseFormat::Json, ParseFormat::Yaml);
    }

    #[test]
    fn test_io_operation_equality() {
        assert_eq!(IoOperation::Read, IoOperation::Read);
        assert_ne!(IoOperation::Read, IoOperation::Write);
    }
}
