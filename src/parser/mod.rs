//! Content parsing layer (L4).
//!
//! This module provides parsers for different file formats:
//! - Markdown (SKILL.md, CLAUDE.md, commands)
//! - JSON (mcp.json, package.json, settings.json)
//! - YAML (docker-compose.yml, subagent configs)
//! - TOML (Cargo.toml, pyproject.toml)
//! - Dockerfile
//!
//! Each parser implements the `ContentParser` trait and extracts
//! structured data for the detection engine (L5).

pub mod dockerfile;
pub mod frontmatter;
pub mod json;
pub mod markdown;
pub mod toml;
pub mod traits;
pub mod yaml;

// Re-exports for convenience
pub use dockerfile::DockerfileParser;
pub use frontmatter::FrontmatterParser;
pub use json::JsonParser;
pub use markdown::MarkdownParser;
pub use toml::TomlParser;
pub use traits::{ContentParser, ContentType, ParsedContent};
pub use yaml::YamlParser;

use crate::error::Result;

/// Registry of all available parsers.
pub struct ParserRegistry {
    parsers: Vec<Box<dyn ContentParser>>,
}

impl ParserRegistry {
    /// Create a new registry with all default parsers.
    pub fn new() -> Self {
        Self {
            parsers: vec![
                Box::new(MarkdownParser::new()),
                Box::new(JsonParser::new()),
                Box::new(YamlParser::new()),
                Box::new(TomlParser::new()),
                Box::new(DockerfileParser::new()),
            ],
        }
    }

    /// Find a parser that can handle the given path.
    pub fn find_parser(&self, path: &str) -> Option<&dyn ContentParser> {
        self.parsers
            .iter()
            .find(|p| p.can_parse(path))
            .map(|p| p.as_ref())
    }

    /// Parse content using the appropriate parser.
    pub fn parse(&self, content: &str, path: &str) -> Result<ParsedContent> {
        if let Some(parser) = self.find_parser(path) {
            parser.parse(content, path)
        } else {
            // Default to plain text
            Ok(ParsedContent::new(
                ContentType::PlainText,
                content.to_string(),
                path.to_string(),
            ))
        }
    }
}

impl Default for ParserRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_find_parser() {
        let registry = ParserRegistry::new();

        assert!(registry.find_parser("test.md").is_some());
        assert!(registry.find_parser("config.json").is_some());
        assert!(registry.find_parser("docker-compose.yml").is_some());
        assert!(registry.find_parser("Cargo.toml").is_some());
        assert!(registry.find_parser("Dockerfile").is_some());
    }

    #[test]
    fn test_registry_parse_unknown() {
        let registry = ParserRegistry::new();
        let result = registry.parse("content", "unknown.xyz").unwrap();

        assert_eq!(result.content_type, ContentType::PlainText);
    }

    #[test]
    fn test_registry_parse_markdown() {
        let registry = ParserRegistry::new();
        let result = registry
            .parse("---\nname: test\n---\n# Content", "SKILL.md")
            .unwrap();

        assert_eq!(result.content_type, ContentType::Markdown);
        assert!(result.frontmatter.is_some());
    }

    #[test]
    fn test_registry_parse_json() {
        let registry = ParserRegistry::new();
        let result = registry
            .parse(r#"{"name": "test"}"#, "config.json")
            .unwrap();

        assert_eq!(result.content_type, ContentType::Json);
        assert!(result.structured_data.is_some());
    }
}
