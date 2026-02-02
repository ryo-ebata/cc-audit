//! YAML content parser.

use super::traits::{ContentParser, ContentType, ParsedContent};
use crate::error::Result;

/// Parser for YAML files (docker-compose.yml, subagent configs, etc.).
pub struct YamlParser;

impl YamlParser {
    /// Create a new YAML parser.
    pub fn new() -> Self {
        Self
    }

    /// Parse YAML content to a serde_json::Value.
    pub fn parse_value(content: &str) -> Option<serde_json::Value> {
        serde_yml::from_str(content).ok()
    }

    /// Parse YAML content to a serde_yml::Value.
    pub fn parse_yaml_value(content: &str) -> Option<serde_yml::Value> {
        serde_yml::from_str(content).ok()
    }
}

impl Default for YamlParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentParser for YamlParser {
    fn parse(&self, content: &str, path: &str) -> Result<ParsedContent> {
        let mut parsed =
            ParsedContent::new(ContentType::Yaml, content.to_string(), path.to_string());

        // Try to parse as structured YAML (convert to JSON Value for uniformity)
        if let Some(value) = Self::parse_value(content) {
            parsed = parsed.with_structured_data(value);
        }

        Ok(parsed)
    }

    fn supported_extensions(&self) -> &[&str] {
        &[".yml", ".yaml"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_yaml() {
        let parser = YamlParser::new();
        let content = "name: test\nversion: 1.0";
        let result = parser.parse(content, "config.yml").unwrap();

        assert_eq!(result.content_type, ContentType::Yaml);
        assert!(result.structured_data.is_some());
        let data = result.structured_data.unwrap();
        assert_eq!(data["name"].as_str(), Some("test"));
    }

    #[test]
    fn test_parse_invalid_yaml() {
        let parser = YamlParser::new();
        let content = "invalid: yaml: content: [";
        let result = parser.parse(content, "config.yml").unwrap();

        // Parser still returns content, just without structured_data
        assert_eq!(result.content_type, ContentType::Yaml);
    }

    #[test]
    fn test_supported_extensions() {
        let parser = YamlParser::new();
        assert!(parser.can_parse("config.yml"));
        assert!(parser.can_parse("config.yaml"));
        assert!(!parser.can_parse("config.json"));
    }

    #[test]
    fn test_parse_docker_compose() {
        let parser = YamlParser::new();
        let content = r#"
version: '3.8'
services:
  app:
    image: myapp:latest
    ports:
      - "8080:80"
"#;
        let result = parser.parse(content, "docker-compose.yml").unwrap();

        assert!(result.structured_data.is_some());
        let data = result.structured_data.unwrap();
        assert!(data["services"]["app"]["image"].is_string());
    }
}
