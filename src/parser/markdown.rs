//! Markdown content parser.

use super::frontmatter::FrontmatterParser;
use super::traits::{ContentParser, ContentType, ParsedContent};
use crate::error::Result;

/// Parser for Markdown files (SKILL.md, CLAUDE.md, commands, etc.).
pub struct MarkdownParser;

impl MarkdownParser {
    /// Create a new Markdown parser.
    pub fn new() -> Self {
        Self
    }

    /// Extract the body content (after frontmatter).
    pub fn extract_body(content: &str) -> &str {
        if let Some(fm) = FrontmatterParser::extract(content) {
            // Skip past frontmatter + closing ---
            let fm_end = content.find("---").unwrap_or(0) + 3 + fm.len() + 3;
            if fm_end < content.len() {
                return &content[fm_end..];
            }
        }
        content
    }
}

impl Default for MarkdownParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentParser for MarkdownParser {
    fn parse(&self, content: &str, path: &str) -> Result<ParsedContent> {
        let mut parsed =
            ParsedContent::new(ContentType::Markdown, content.to_string(), path.to_string());

        // Extract frontmatter if present
        if let Some(fm) = FrontmatterParser::extract(content) {
            parsed = parsed.with_frontmatter(fm.to_string());

            // Try to parse as structured YAML
            if let Some(yaml) = FrontmatterParser::parse_json(content) {
                parsed = parsed.with_structured_data(yaml);
            }
        }

        Ok(parsed)
    }

    fn supported_extensions(&self) -> &[&str] {
        &[".md", ".markdown"]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_markdown_with_frontmatter() {
        let parser = MarkdownParser::new();
        let content = "---\nname: test\n---\n# Content";
        let result = parser.parse(content, "test.md").unwrap();

        assert_eq!(result.content_type, ContentType::Markdown);
        assert!(result.frontmatter.is_some());
        assert!(result.structured_data.is_some());
    }

    #[test]
    fn test_parse_markdown_without_frontmatter() {
        let parser = MarkdownParser::new();
        let content = "# Just Content\n\nNo frontmatter here.";
        let result = parser.parse(content, "test.md").unwrap();

        assert_eq!(result.content_type, ContentType::Markdown);
        assert!(result.frontmatter.is_none());
        assert!(result.structured_data.is_none());
    }

    #[test]
    fn test_extract_body() {
        let content = "---\nname: test\n---\n# Body Content";
        let body = MarkdownParser::extract_body(content);
        assert!(body.contains("Body Content"));
    }

    #[test]
    fn test_supported_extensions() {
        let parser = MarkdownParser::new();
        assert!(parser.can_parse("SKILL.md"));
        assert!(parser.can_parse("README.markdown"));
        assert!(!parser.can_parse("config.json"));
    }
}
