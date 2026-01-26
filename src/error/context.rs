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
    }

    #[test]
    fn test_parse_format_display() {
        assert_eq!(ParseFormat::Json.to_string(), "JSON");
        assert_eq!(ParseFormat::Yaml.to_string(), "YAML");
    }
}
