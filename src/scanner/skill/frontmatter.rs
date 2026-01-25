/// Parses YAML frontmatter from markdown files
pub struct FrontmatterParser;

impl FrontmatterParser {
    /// Extract frontmatter content from a markdown file
    ///
    /// Frontmatter is delimited by `---` at the start and end.
    /// Returns None if no valid frontmatter is found.
    ///
    /// # Example
    /// ```ignore
    /// let content = "---\nname: test\n---\n# Content";
    /// let frontmatter = FrontmatterParser::extract(content);
    /// assert_eq!(frontmatter, Some("name: test\n"));
    /// ```
    pub fn extract(content: &str) -> Option<&str> {
        content.strip_prefix("---").and_then(|after_start| {
            after_start
                .find("---")
                .map(|end_idx| &after_start[..end_idx])
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_frontmatter() {
        let content = "---\nname: test\ndescription: A test\n---\n# Content";
        let result = FrontmatterParser::extract(content);
        assert_eq!(result, Some("\nname: test\ndescription: A test\n"));
    }

    #[test]
    fn test_frontmatter_with_allowed_tools() {
        let content = "---\nname: skill\nallowed-tools: Read, Write\n---\n# Skill";
        let result = FrontmatterParser::extract(content);
        assert!(result.is_some());
        assert!(result.unwrap().contains("allowed-tools"));
    }

    #[test]
    fn test_no_frontmatter() {
        let content = "# Just Markdown\nNo frontmatter here.";
        assert!(FrontmatterParser::extract(content).is_none());
    }

    #[test]
    fn test_incomplete_frontmatter() {
        let content = "---\nname: test\nNo closing dashes";
        assert!(FrontmatterParser::extract(content).is_none());
    }

    #[test]
    fn test_empty_frontmatter() {
        let content = "------\n# Content";
        let result = FrontmatterParser::extract(content);
        assert_eq!(result, Some(""));
    }

    #[test]
    fn test_frontmatter_with_nested_dashes() {
        let content = "---\nname: test\ndata: \"some---thing\"\n---\n# Content";
        let result = FrontmatterParser::extract(content);
        // Should extract up to the first closing ---
        assert!(result.is_some());
    }

    #[test]
    fn test_content_not_starting_with_dashes() {
        let content = "# Title\n---\nname: test\n---";
        assert!(FrontmatterParser::extract(content).is_none());
    }
}
