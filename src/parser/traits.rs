//! Parser traits for the content parsing layer (L4).

use crate::error::Result;
use serde::{Deserialize, Serialize};

/// The type of content detected in a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContentType {
    /// Markdown document (SKILL.md, CLAUDE.md, commands, etc.)
    Markdown,
    /// JSON configuration (mcp.json, package.json, etc.)
    Json,
    /// YAML configuration (docker-compose.yml, subagent configs)
    Yaml,
    /// TOML configuration (Cargo.toml, pyproject.toml)
    Toml,
    /// Dockerfile
    Dockerfile,
    /// Plain text
    PlainText,
    /// Unknown/binary content
    Unknown,
}

impl ContentType {
    /// Detect content type from file extension.
    pub fn from_extension(ext: &str) -> Self {
        match ext.to_lowercase().as_str() {
            "md" | "markdown" => Self::Markdown,
            "json" => Self::Json,
            "yml" | "yaml" => Self::Yaml,
            "toml" => Self::Toml,
            "dockerfile" => Self::Dockerfile,
            "txt" | "text" => Self::PlainText,
            _ => Self::Unknown,
        }
    }

    /// Detect content type from filename.
    pub fn from_filename(filename: &str) -> Self {
        let lower = filename.to_lowercase();

        // Special filenames
        if lower == "dockerfile" || lower.starts_with("dockerfile.") {
            return Self::Dockerfile;
        }

        // Check extension
        if let Some(ext) = filename.rsplit('.').next() {
            let content_type = Self::from_extension(ext);
            if content_type != Self::Unknown {
                return content_type;
            }
        }

        Self::Unknown
    }
}

/// Parsed content from a file.
#[derive(Debug, Clone)]
pub struct ParsedContent {
    /// The detected content type.
    pub content_type: ContentType,
    /// The raw file content.
    pub raw_content: String,
    /// Parsed structured data (if applicable).
    pub structured_data: Option<serde_json::Value>,
    /// Extracted frontmatter (for markdown files).
    pub frontmatter: Option<String>,
    /// Source file path.
    pub source_path: String,
}

impl ParsedContent {
    /// Create a new ParsedContent with minimal data.
    pub fn new(content_type: ContentType, raw_content: String, source_path: String) -> Self {
        Self {
            content_type,
            raw_content,
            structured_data: None,
            frontmatter: None,
            source_path,
        }
    }

    /// Add structured data to the parsed content.
    pub fn with_structured_data(mut self, data: serde_json::Value) -> Self {
        self.structured_data = Some(data);
        self
    }

    /// Add frontmatter to the parsed content.
    pub fn with_frontmatter(mut self, frontmatter: String) -> Self {
        self.frontmatter = Some(frontmatter);
        self
    }
}

/// Trait for content parsers (L4).
///
/// Each parser handles a specific file format and extracts
/// structured data for the detection engine.
pub trait ContentParser: Send + Sync {
    /// Parse the file content.
    fn parse(&self, content: &str, path: &str) -> Result<ParsedContent>;

    /// Get the file extensions this parser supports.
    fn supported_extensions(&self) -> &[&str];

    /// Check if this parser can handle the given file.
    fn can_parse(&self, path: &str) -> bool {
        let path_lower = path.to_lowercase();
        self.supported_extensions()
            .iter()
            .any(|ext| path_lower.ends_with(ext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_type_from_extension() {
        assert_eq!(ContentType::from_extension("md"), ContentType::Markdown);
        assert_eq!(ContentType::from_extension("json"), ContentType::Json);
        assert_eq!(ContentType::from_extension("yml"), ContentType::Yaml);
        assert_eq!(ContentType::from_extension("yaml"), ContentType::Yaml);
        assert_eq!(ContentType::from_extension("toml"), ContentType::Toml);
        assert_eq!(ContentType::from_extension("txt"), ContentType::PlainText);
        assert_eq!(ContentType::from_extension("exe"), ContentType::Unknown);
    }

    #[test]
    fn test_content_type_from_filename() {
        assert_eq!(
            ContentType::from_filename("SKILL.md"),
            ContentType::Markdown
        );
        assert_eq!(
            ContentType::from_filename("package.json"),
            ContentType::Json
        );
        assert_eq!(
            ContentType::from_filename("Dockerfile"),
            ContentType::Dockerfile
        );
        assert_eq!(
            ContentType::from_filename("Dockerfile.prod"),
            ContentType::Dockerfile
        );
        assert_eq!(
            ContentType::from_filename("docker-compose.yml"),
            ContentType::Yaml
        );
    }

    #[test]
    fn test_parsed_content_builder() {
        let content = ParsedContent::new(
            ContentType::Markdown,
            "# Test".to_string(),
            "test.md".to_string(),
        )
        .with_frontmatter("name: test".to_string());

        assert_eq!(content.content_type, ContentType::Markdown);
        assert_eq!(content.frontmatter, Some("name: test".to_string()));
    }
}
