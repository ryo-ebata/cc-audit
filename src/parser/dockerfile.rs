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

        for line in content.lines() {
            let trimmed = line.trim();

            if in_run {
                // Continuation of previous RUN command
                if let Some(stripped) = trimmed.strip_suffix('\\') {
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
                if let Some(stripped) = cmd.strip_suffix('\\') {
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
