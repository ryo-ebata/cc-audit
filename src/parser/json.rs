//! JSON content parser.

use super::traits::{ContentParser, ContentType, ParsedContent};
use crate::error::Result;

/// Parser for JSON files (mcp.json, package.json, settings.json, etc.).
pub struct JsonParser;

impl JsonParser {
    /// Create a new JSON parser.
    pub fn new() -> Self {
        Self
    }

    /// Parse JSON content to a Value.
    pub fn parse_value(content: &str) -> Option<serde_json::Value> {
        serde_json::from_str(content).ok()
    }
}

impl Default for JsonParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentParser for JsonParser {
    fn parse(&self, content: &str, path: &str) -> Result<ParsedContent> {
        let mut parsed =
            ParsedContent::new(ContentType::Json, content.to_string(), path.to_string());

        // Try to parse as structured JSON
        if let Some(value) = Self::parse_value(content) {
            parsed = parsed.with_structured_data(value);
        }

        Ok(parsed)
    }

    fn supported_extensions(&self) -> &[&str] {
        &[".json"]
    }

    fn can_parse(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();
        path_lower.ends_with(".json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_json() {
        let parser = JsonParser::new();
        let content = r#"{"name": "test", "version": "1.0"}"#;
        let result = parser.parse(content, "config.json").unwrap();

        assert_eq!(result.content_type, ContentType::Json);
        assert!(result.structured_data.is_some());
        let data = result.structured_data.unwrap();
        assert_eq!(data["name"].as_str(), Some("test"));
    }

    #[test]
    fn test_parse_invalid_json() {
        let parser = JsonParser::new();
        let content = "not valid json";
        let result = parser.parse(content, "config.json").unwrap();

        assert_eq!(result.content_type, ContentType::Json);
        assert!(result.structured_data.is_none());
    }

    #[test]
    fn test_supported_extensions() {
        let parser = JsonParser::new();
        assert!(parser.can_parse("mcp.json"));
        assert!(parser.can_parse("package.json"));
        assert!(!parser.can_parse("config.yaml"));
    }

    #[test]
    fn test_parse_complex_json() {
        let parser = JsonParser::new();
        let content = r#"{
            "mcpServers": {
                "example": {
                    "command": "npx",
                    "args": ["-y", "@example/mcp-server"]
                }
            }
        }"#;
        let result = parser.parse(content, "mcp.json").unwrap();

        assert!(result.structured_data.is_some());
        let data = result.structured_data.unwrap();
        assert!(data["mcpServers"]["example"]["command"].is_string());
    }
}
