//! Dependency extractor for SBOM generation.

use super::builder::{Component, ComponentType, SbomError};
use serde_json::Value;
use std::fs;
use std::path::Path;

/// Extractor for dependencies from various configuration files.
pub struct DependencyExtractor;

impl DependencyExtractor {
    /// Create a new dependency extractor.
    pub fn new() -> Self {
        Self
    }

    /// Extract MCP servers from a directory.
    pub fn extract_mcp_servers(&self, path: &Path) -> Result<Vec<Component>, SbomError> {
        let mut components = Vec::new();

        // Check for mcp.json
        let mcp_json_path = path.join("mcp.json");
        if mcp_json_path.exists() {
            components.extend(self.parse_mcp_json(&mcp_json_path)?);
        }

        // Check for .claude/mcp_servers.json (Claude Code config)
        let claude_mcp_path = path.join(".claude").join("mcp_servers.json");
        if claude_mcp_path.exists() {
            components.extend(self.parse_mcp_json(&claude_mcp_path)?);
        }

        // Check for claude_desktop_config.json
        let desktop_config = path.join("claude_desktop_config.json");
        if desktop_config.exists() {
            components.extend(self.parse_claude_desktop_config(&desktop_config)?);
        }

        Ok(components)
    }

    /// Parse mcp.json format.
    fn parse_mcp_json(&self, path: &Path) -> Result<Vec<Component>, SbomError> {
        let content = fs::read_to_string(path)?;
        let json: Value =
            serde_json::from_str(&content).map_err(|e| SbomError::JsonParse(e.to_string()))?;

        let mut components = Vec::new();

        // Handle mcpServers object format
        if let Some(servers) = json.get("mcpServers").and_then(|v| v.as_object()) {
            for (name, config) in servers {
                let mut comp = Component::new(name, ComponentType::McpServer);

                // Try to extract command/args for npm package detection
                if let Some(args) = config.get("args").and_then(|v| v.as_array()) {
                    for arg in args {
                        if let Some(arg_str) = arg.as_str() {
                            // Detect npm package names
                            if arg_str.starts_with('@') || !arg_str.contains('/') {
                                if let Some(version) = Self::extract_npm_version(arg_str) {
                                    comp =
                                        comp.with_purl(Component::npm_purl(arg_str, Some(version)));
                                } else {
                                    comp = comp.with_purl(Component::npm_purl(arg_str, None));
                                }
                            }
                        }
                    }
                }

                components.push(comp);
            }
        }

        Ok(components)
    }

    /// Parse claude_desktop_config.json format.
    fn parse_claude_desktop_config(&self, path: &Path) -> Result<Vec<Component>, SbomError> {
        let content = fs::read_to_string(path)?;
        let json: Value =
            serde_json::from_str(&content).map_err(|e| SbomError::JsonParse(e.to_string()))?;

        let mut components = Vec::new();

        // Same format as mcp.json
        if let Some(servers) = json.get("mcpServers").and_then(|v| v.as_object()) {
            for (name, _config) in servers {
                components.push(Component::new(name, ComponentType::McpServer));
            }
        }

        Ok(components)
    }

    /// Extract skills from a directory.
    pub fn extract_skills(&self, path: &Path) -> Result<Vec<Component>, SbomError> {
        let mut components = Vec::new();

        // Check for .claude/skills directory
        let skills_dir = path.join(".claude").join("skills");
        if skills_dir.is_dir()
            && let Ok(entries) = fs::read_dir(&skills_dir)
        {
            for entry in entries.flatten() {
                let entry_path = entry.path();
                if entry_path.is_file()
                    && entry_path.extension().is_some_and(|e| e == "md")
                    && let Some(name) = entry_path.file_stem().and_then(|s| s.to_str())
                {
                    let mut comp = Component::new(name, ComponentType::Skill);

                    // Try to parse frontmatter for metadata
                    if let Ok(content) = fs::read_to_string(&entry_path)
                        && let Some(desc) = Self::extract_skill_description(&content)
                    {
                        comp = comp.with_description(desc);
                    }

                    components.push(comp);
                }
            }
        }

        Ok(components)
    }

    /// Extract skill description from frontmatter.
    fn extract_skill_description(content: &str) -> Option<String> {
        // Simple frontmatter parsing
        if !content.starts_with("---") {
            return None;
        }

        let parts: Vec<&str> = content.splitn(3, "---").collect();
        if parts.len() < 3 {
            return None;
        }

        let frontmatter = parts[1];

        // Look for description field
        for line in frontmatter.lines() {
            let line = line.trim();
            if let Some(desc) = line.strip_prefix("description:") {
                return Some(desc.trim().trim_matches('"').trim_matches('\'').to_string());
            }
        }

        None
    }

    /// Extract npm dependencies from package.json.
    pub fn extract_npm_dependencies(&self, path: &Path) -> Result<Vec<Component>, SbomError> {
        let package_json_path = path.join("package.json");
        if !package_json_path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&package_json_path)?;
        let json: Value =
            serde_json::from_str(&content).map_err(|e| SbomError::JsonParse(e.to_string()))?;

        let mut components = Vec::new();

        // Extract from dependencies
        if let Some(deps) = json.get("dependencies").and_then(|v| v.as_object()) {
            for (name, version) in deps {
                let version_str = version.as_str().unwrap_or("");
                let clean_version = Self::clean_npm_version(version_str);

                let comp = Component::new(name, ComponentType::Library)
                    .with_version(&clean_version)
                    .with_purl(Component::npm_purl(name, Some(&clean_version)));

                components.push(comp);
            }
        }

        // Extract from devDependencies (optional)
        if let Some(deps) = json.get("devDependencies").and_then(|v| v.as_object()) {
            for (name, version) in deps {
                let version_str = version.as_str().unwrap_or("");
                let clean_version = Self::clean_npm_version(version_str);

                let comp = Component::new(name, ComponentType::Library)
                    .with_version(&clean_version)
                    .with_purl(Component::npm_purl(name, Some(&clean_version)));

                components.push(comp);
            }
        }

        Ok(components)
    }

    /// Extract Cargo dependencies from Cargo.toml.
    pub fn extract_cargo_dependencies(&self, path: &Path) -> Result<Vec<Component>, SbomError> {
        let cargo_toml_path = path.join("Cargo.toml");
        if !cargo_toml_path.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&cargo_toml_path)?;
        let toml: toml::Value =
            toml::from_str(&content).map_err(|e| SbomError::TomlParse(e.to_string()))?;

        let mut components = Vec::new();

        // Extract from [dependencies]
        if let Some(deps) = toml.get("dependencies").and_then(|v| v.as_table()) {
            for (name, value) in deps {
                let version = Self::extract_cargo_version(value);

                let comp = Component::new(name, ComponentType::Library)
                    .with_version(&version)
                    .with_purl(format!("pkg:cargo/{}@{}", name, version));

                components.push(comp);
            }
        }

        // Extract from [dev-dependencies]
        if let Some(deps) = toml.get("dev-dependencies").and_then(|v| v.as_table()) {
            for (name, value) in deps {
                let version = Self::extract_cargo_version(value);

                let comp = Component::new(name, ComponentType::Library)
                    .with_version(&version)
                    .with_purl(format!("pkg:cargo/{}@{}", name, version));

                components.push(comp);
            }
        }

        Ok(components)
    }

    /// Extract version from Cargo.toml dependency value.
    fn extract_cargo_version(value: &toml::Value) -> String {
        match value {
            toml::Value::String(v) => v.clone(),
            toml::Value::Table(t) => t
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("*")
                .to_string(),
            _ => "*".to_string(),
        }
    }

    /// Extract npm version from package specifier.
    fn extract_npm_version(spec: &str) -> Option<&str> {
        // Handle @scope/package@version or package@version
        if let Some(idx) = spec.rfind('@')
            && idx > 0
            && !spec[..idx].ends_with('/')
        {
            return Some(&spec[idx + 1..]);
        }
        None
    }

    /// Clean npm version string (remove ^, ~, etc.)
    fn clean_npm_version(version: &str) -> String {
        version
            .trim_start_matches(['^', '~', '>', '<', '=', ' '].as_ref())
            .split_whitespace()
            .next()
            .unwrap_or(version)
            .to_string()
    }
}

impl Default for DependencyExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_clean_npm_version() {
        assert_eq!(DependencyExtractor::clean_npm_version("^1.2.3"), "1.2.3");
        assert_eq!(DependencyExtractor::clean_npm_version("~1.2.3"), "1.2.3");
        assert_eq!(DependencyExtractor::clean_npm_version(">=1.0.0"), "1.0.0");
        assert_eq!(DependencyExtractor::clean_npm_version("1.2.3"), "1.2.3");
    }

    #[test]
    fn test_extract_npm_version() {
        assert_eq!(
            DependencyExtractor::extract_npm_version("express@4.18.0"),
            Some("4.18.0")
        );
        assert_eq!(
            DependencyExtractor::extract_npm_version("@scope/package@1.0.0"),
            Some("1.0.0")
        );
        assert_eq!(DependencyExtractor::extract_npm_version("express"), None);
    }

    #[test]
    fn test_extract_mcp_servers() {
        let temp_dir = TempDir::new().unwrap();
        let mcp_json = temp_dir.path().join("mcp.json");
        fs::write(
            &mcp_json,
            r#"{"mcpServers": {"test-server": {"command": "npx"}}}"#,
        )
        .unwrap();

        let extractor = DependencyExtractor::new();
        let components = extractor.extract_mcp_servers(temp_dir.path()).unwrap();

        assert_eq!(components.len(), 1);
        assert_eq!(components[0].name, "test-server");
        assert_eq!(components[0].component_type, ComponentType::McpServer);
    }

    #[test]
    fn test_extract_skills() {
        let temp_dir = TempDir::new().unwrap();
        let skills_dir = temp_dir.path().join(".claude").join("skills");
        fs::create_dir_all(&skills_dir).unwrap();
        fs::write(
            skills_dir.join("test-skill.md"),
            r#"---
description: A test skill
---
# Test Skill
"#,
        )
        .unwrap();

        let extractor = DependencyExtractor::new();
        let components = extractor.extract_skills(temp_dir.path()).unwrap();

        assert_eq!(components.len(), 1);
        assert_eq!(components[0].name, "test-skill");
        assert_eq!(components[0].component_type, ComponentType::Skill);
        assert_eq!(components[0].description, Some("A test skill".to_string()));
    }

    #[test]
    fn test_extract_npm_dependencies() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(
            temp_dir.path().join("package.json"),
            r#"{"dependencies": {"express": "^4.18.0", "lodash": "~4.17.21"}}"#,
        )
        .unwrap();

        let extractor = DependencyExtractor::new();
        let components = extractor.extract_npm_dependencies(temp_dir.path()).unwrap();

        assert_eq!(components.len(), 2);

        let names: Vec<_> = components.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"express"));
        assert!(names.contains(&"lodash"));
    }

    #[test]
    fn test_extract_cargo_dependencies() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(
            temp_dir.path().join("Cargo.toml"),
            r#"
[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
"#,
        )
        .unwrap();

        let extractor = DependencyExtractor::new();
        let components = extractor
            .extract_cargo_dependencies(temp_dir.path())
            .unwrap();

        assert_eq!(components.len(), 2);

        let names: Vec<_> = components.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"serde"));
        assert!(names.contains(&"tokio"));
    }

    #[test]
    fn test_extract_skill_description() {
        let content = r#"---
name: test
description: This is a test
---
# Content
"#;
        let desc = DependencyExtractor::extract_skill_description(content);
        assert_eq!(desc, Some("This is a test".to_string()));
    }

    #[test]
    fn test_extract_skill_description_no_frontmatter() {
        let content = "# Just content";
        let desc = DependencyExtractor::extract_skill_description(content);
        assert!(desc.is_none());
    }

    #[test]
    fn test_extract_skill_description_incomplete_frontmatter() {
        let content = "---\nname: test\n---";
        let desc = DependencyExtractor::extract_skill_description(content);
        assert!(desc.is_none());
    }

    #[test]
    fn test_extract_skill_description_quoted() {
        let content = r#"---
description: "quoted description"
---
# Content
"#;
        let desc = DependencyExtractor::extract_skill_description(content);
        assert_eq!(desc, Some("quoted description".to_string()));
    }

    #[test]
    fn test_extract_skill_description_single_quoted() {
        let content = r#"---
description: 'single quoted'
---
# Content
"#;
        let desc = DependencyExtractor::extract_skill_description(content);
        assert_eq!(desc, Some("single quoted".to_string()));
    }

    #[test]
    fn test_parse_claude_desktop_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("claude_desktop_config.json");
        fs::write(
            &config_path,
            r#"{"mcpServers": {"desktop-server": {"command": "npx", "args": ["server"]}}}"#,
        )
        .unwrap();

        let extractor = DependencyExtractor::new();
        let components = extractor.extract_mcp_servers(temp_dir.path()).unwrap();

        assert_eq!(components.len(), 1);
        assert_eq!(components[0].name, "desktop-server");
    }

    #[test]
    fn test_extract_mcp_servers_from_claude_dir() {
        let temp_dir = TempDir::new().unwrap();
        let claude_dir = temp_dir.path().join(".claude");
        fs::create_dir_all(&claude_dir).unwrap();

        let mcp_servers_path = claude_dir.join("mcp_servers.json");
        fs::write(
            &mcp_servers_path,
            r#"{"mcpServers": {"claude-server": {"command": "npx"}}}"#,
        )
        .unwrap();

        let extractor = DependencyExtractor::new();
        let components = extractor.extract_mcp_servers(temp_dir.path()).unwrap();

        assert_eq!(components.len(), 1);
        assert_eq!(components[0].name, "claude-server");
    }

    #[test]
    fn test_extract_mcp_servers_with_npm_args() {
        let temp_dir = TempDir::new().unwrap();
        let mcp_json = temp_dir.path().join("mcp.json");
        fs::write(
            &mcp_json,
            r#"{"mcpServers": {"npm-server": {"command": "npx", "args": ["@example/mcp-server@1.0.0"]}}}"#,
        )
        .unwrap();

        let extractor = DependencyExtractor::new();
        let components = extractor.extract_mcp_servers(temp_dir.path()).unwrap();

        assert_eq!(components.len(), 1);
        assert_eq!(components[0].name, "npm-server");
        assert!(components[0].purl.is_some());
    }

    #[test]
    fn test_extract_npm_dependencies_with_dev() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(
            temp_dir.path().join("package.json"),
            r#"{"dependencies": {"express": "^4.18.0"}, "devDependencies": {"jest": "^29.0.0"}}"#,
        )
        .unwrap();

        let extractor = DependencyExtractor::new();
        let components = extractor.extract_npm_dependencies(temp_dir.path()).unwrap();

        assert_eq!(components.len(), 2);

        let names: Vec<_> = components.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"express"));
        assert!(names.contains(&"jest"));
    }

    #[test]
    fn test_extract_npm_dependencies_no_package_json() {
        let temp_dir = TempDir::new().unwrap();

        let extractor = DependencyExtractor::new();
        let components = extractor.extract_npm_dependencies(temp_dir.path()).unwrap();

        assert!(components.is_empty());
    }

    #[test]
    fn test_extract_cargo_dependencies_with_dev() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(
            temp_dir.path().join("Cargo.toml"),
            r#"
[dependencies]
serde = "1.0"

[dev-dependencies]
tempfile = "3.0"
"#,
        )
        .unwrap();

        let extractor = DependencyExtractor::new();
        let components = extractor
            .extract_cargo_dependencies(temp_dir.path())
            .unwrap();

        assert_eq!(components.len(), 2);

        let names: Vec<_> = components.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"serde"));
        assert!(names.contains(&"tempfile"));
    }

    #[test]
    fn test_extract_cargo_dependencies_no_cargo_toml() {
        let temp_dir = TempDir::new().unwrap();

        let extractor = DependencyExtractor::new();
        let components = extractor
            .extract_cargo_dependencies(temp_dir.path())
            .unwrap();

        assert!(components.is_empty());
    }

    #[test]
    fn test_extract_cargo_version_string() {
        let value = toml::Value::String("1.0.0".to_string());
        let version = DependencyExtractor::extract_cargo_version(&value);
        assert_eq!(version, "1.0.0");
    }

    #[test]
    fn test_extract_cargo_version_table() {
        let mut table = toml::map::Map::new();
        table.insert(
            "version".to_string(),
            toml::Value::String("2.0.0".to_string()),
        );
        let value = toml::Value::Table(table);
        let version = DependencyExtractor::extract_cargo_version(&value);
        assert_eq!(version, "2.0.0");
    }

    #[test]
    fn test_extract_cargo_version_table_no_version() {
        let table = toml::map::Map::new();
        let value = toml::Value::Table(table);
        let version = DependencyExtractor::extract_cargo_version(&value);
        assert_eq!(version, "*");
    }

    #[test]
    fn test_extract_cargo_version_other() {
        let value = toml::Value::Boolean(true);
        let version = DependencyExtractor::extract_cargo_version(&value);
        assert_eq!(version, "*");
    }

    #[test]
    fn test_extract_skills_no_skills_dir() {
        let temp_dir = TempDir::new().unwrap();

        let extractor = DependencyExtractor::new();
        let components = extractor.extract_skills(temp_dir.path()).unwrap();

        assert!(components.is_empty());
    }

    #[test]
    fn test_extract_skills_with_non_md_files() {
        let temp_dir = TempDir::new().unwrap();
        let skills_dir = temp_dir.path().join(".claude").join("skills");
        fs::create_dir_all(&skills_dir).unwrap();

        // Create a non-.md file
        fs::write(skills_dir.join("not-a-skill.txt"), "content").unwrap();

        let extractor = DependencyExtractor::new();
        let components = extractor.extract_skills(temp_dir.path()).unwrap();

        assert!(components.is_empty());
    }

    #[test]
    fn test_extract_npm_version_scoped_without_version() {
        assert_eq!(
            DependencyExtractor::extract_npm_version("@scope/package"),
            None
        );
    }

    #[test]
    fn test_new_extractor() {
        let extractor = DependencyExtractor::new();
        // Just ensure it doesn't panic
        let _ = extractor;
    }
}
