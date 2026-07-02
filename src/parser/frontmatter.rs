//! YAML frontmatter parser for markdown files.

/// Parses YAML frontmatter from markdown files.
pub struct FrontmatterParser;

impl FrontmatterParser {
    /// Extract frontmatter content from a markdown file.
    ///
    /// Frontmatter is delimited by `---` at the start and end.
    /// Returns None if no valid frontmatter is found.
    ///
    /// # Example
    /// ```
    /// use cc_audit::parser::FrontmatterParser;
    /// let content = "---\nname: test\n---\n# Content";
    /// let frontmatter = FrontmatterParser::extract(content);
    /// assert_eq!(frontmatter, Some("\nname: test\n"));
    /// ```
    pub fn extract(content: &str) -> Option<&str> {
        // The opening delimiter must be a line consisting solely of `---`.
        // Requiring a line break right after `---` rejects `----`, `---x`, and a
        // top-of-file `------` thematic break (issue #131).
        let after_open = content.strip_prefix("---")?;
        if !after_open.starts_with('\n') && !after_open.starts_with("\r\n") {
            return None;
        }

        // The closing delimiter must also be a line that is solely `---`
        // (trailing whitespace allowed). A raw substring search would match a
        // `---` inside a quoted value and truncate the frontmatter early,
        // pushing later lines (e.g. `allowed-tools: *`) out of the scanned
        // region and evading OP-001.
        let mut offset = 0;
        for line in after_open.split_inclusive('\n') {
            if line.trim_end_matches(['\r', '\n']).trim_end() == "---" {
                return Some(&after_open[..offset]);
            }
            offset += line.len();
        }

        None
    }

    /// Parse frontmatter as a YAML value.
    ///
    /// Returns None if no frontmatter exists or parsing fails.
    pub fn parse_yaml(content: &str) -> Option<serde_norway::Value> {
        Self::extract(content).and_then(|fm| serde_norway::from_str(fm.trim()).ok())
    }

    /// Parse frontmatter as a JSON value.
    ///
    /// Returns None if no frontmatter exists or parsing fails.
    pub fn parse_json(content: &str) -> Option<serde_json::Value> {
        Self::extract(content)
            .and_then(|fm| serde_norway::from_str::<serde_json::Value>(fm.trim()).ok())
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
    fn test_thematic_break_is_not_empty_frontmatter() {
        // `------` (a markdown thematic break) is NOT an opening `---` delimiter
        // line, so it must not be parsed as empty frontmatter (issue #131).
        let content = "------\n# Content";
        assert!(FrontmatterParser::extract(content).is_none());
    }

    #[test]
    fn test_inline_dashes_in_value_do_not_truncate() {
        // A `---` inside a quoted value must NOT be treated as the closing
        // delimiter; the real closing `---` is on its own line (issue #131).
        let content = "---\ndescription: \"harmless a---b\"\nallowed-tools: *\n---\n# Body";
        let result = FrontmatterParser::extract(content);
        assert_eq!(
            result,
            Some("\ndescription: \"harmless a---b\"\nallowed-tools: *\n")
        );
    }

    #[test]
    fn test_closing_delimiter_must_be_own_line() {
        // A `---` that is part of a longer token on a line is not a closing
        // delimiter; without a real closing line, there is no frontmatter.
        let content = "---\nname: test\nvalue: a---b\nno closing line";
        assert!(FrontmatterParser::extract(content).is_none());
    }

    #[test]
    fn test_content_not_starting_with_dashes() {
        let content = "# Title\n---\nname: test\n---";
        assert!(FrontmatterParser::extract(content).is_none());
    }

    #[test]
    fn test_parse_yaml() {
        let content = "---\nname: test\nversion: 1.0\n---\n# Content";
        let yaml = FrontmatterParser::parse_yaml(content);
        assert!(yaml.is_some());
        let yaml = yaml.unwrap();
        assert_eq!(yaml["name"].as_str(), Some("test"));
    }

    #[test]
    fn test_parse_json() {
        let content = "---\nname: test\nversion: 1.0\n---\n# Content";
        let json = FrontmatterParser::parse_json(content);
        assert!(json.is_some());
        let json = json.unwrap();
        assert_eq!(json["name"].as_str(), Some("test"));
    }
}
