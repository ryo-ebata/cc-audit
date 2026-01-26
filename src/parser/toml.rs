//! TOML content parser.

use super::traits::{ContentParser, ContentType, ParsedContent};
use crate::error::Result;

/// Parser for TOML files (Cargo.toml, pyproject.toml, etc.).
pub struct TomlParser;

impl TomlParser {
    /// Create a new TOML parser.
    pub fn new() -> Self {
        Self
    }

    /// Parse TOML content to a serde_json::Value.
    pub fn parse_value(content: &str) -> Option<serde_json::Value> {
        toml::from_str::<toml::Value>(content)
            .ok()
            .and_then(|v| serde_json::to_value(v).ok())
    }

    /// Parse TOML content to a toml::Value.
    pub fn parse_toml_value(content: &str) -> Option<toml::Value> {
        toml::from_str(content).ok()
    }
}

impl Default for TomlParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentParser for TomlParser {
    fn parse(&self, content: &str, path: &str) -> Result<ParsedContent> {
        let mut parsed =
            ParsedContent::new(ContentType::Toml, content.to_string(), path.to_string());

        // Try to parse as structured TOML (convert to JSON Value for uniformity)
        if let Some(value) = Self::parse_value(content) {
            parsed = parsed.with_structured_data(value);
        }

        Ok(parsed)
    }

    fn supported_extensions(&self) -> &[&str] {
        &[".toml"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_toml() {
        let parser = TomlParser::new();
        let content = r#"
[package]
name = "test"
version = "1.0.0"
"#;
        let result = parser.parse(content, "Cargo.toml").unwrap();

        assert_eq!(result.content_type, ContentType::Toml);
        assert!(result.structured_data.is_some());
        let data = result.structured_data.unwrap();
        assert_eq!(data["package"]["name"].as_str(), Some("test"));
    }

    #[test]
    fn test_parse_invalid_toml() {
        let parser = TomlParser::new();
        let content = "invalid = toml [";
        let result = parser.parse(content, "config.toml").unwrap();

        assert_eq!(result.content_type, ContentType::Toml);
        assert!(result.structured_data.is_none());
    }

    #[test]
    fn test_supported_extensions() {
        let parser = TomlParser::new();
        assert!(parser.can_parse("Cargo.toml"));
        assert!(parser.can_parse("pyproject.toml"));
        assert!(!parser.can_parse("config.json"));
    }

    #[test]
    fn test_parse_pyproject_toml() {
        let parser = TomlParser::new();
        let content = r#"
[project]
name = "myproject"
version = "0.1.0"

[project.dependencies]
requests = "^2.28"
"#;
        let result = parser.parse(content, "pyproject.toml").unwrap();

        assert!(result.structured_data.is_some());
        let data = result.structured_data.unwrap();
        assert_eq!(data["project"]["name"].as_str(), Some("myproject"));
    }
}
