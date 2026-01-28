//! SBOM builder for constructing software bill of materials.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// SBOM output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SbomFormat {
    /// CycloneDX 1.5 format (default)
    #[default]
    CycloneDx,
    /// SPDX 2.3 format (future)
    Spdx,
}

impl std::str::FromStr for SbomFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "cyclonedx" | "cdx" => Ok(Self::CycloneDx),
            "spdx" => Ok(Self::Spdx),
            _ => Err(format!("Unknown SBOM format: {}", s)),
        }
    }
}

/// Type of component in the SBOM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ComponentType {
    /// Application or service
    Application,
    /// Library or package
    Library,
    /// External service
    Service,
    /// MCP server
    McpServer,
    /// Claude Code skill
    Skill,
    /// Claude Code plugin
    Plugin,
    /// Claude Code subagent
    Subagent,
}

impl ComponentType {
    /// Convert to CycloneDX component type string.
    pub fn to_cyclonedx_type(&self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Library => "library",
            Self::Service => "service",
            Self::McpServer => "service",
            Self::Skill => "application",
            Self::Plugin => "library",
            Self::Subagent => "application",
        }
    }
}

/// A component in the SBOM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Component {
    /// Component name
    pub name: String,

    /// Component version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Component type
    #[serde(rename = "type")]
    pub component_type: ComponentType,

    /// Package URL (purl)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,

    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Author or publisher
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    /// License identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,

    /// Repository URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,

    /// SHA-256 hash of the component
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_sha256: Option<String>,
}

impl Component {
    /// Create a new component.
    pub fn new(name: impl Into<String>, component_type: ComponentType) -> Self {
        Self {
            name: name.into(),
            version: None,
            component_type,
            purl: None,
            description: None,
            author: None,
            license: None,
            repository: None,
            hash_sha256: None,
        }
    }

    /// Set the version.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set the purl.
    pub fn with_purl(mut self, purl: impl Into<String>) -> Self {
        self.purl = Some(purl.into());
        self
    }

    /// Set the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the author.
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// Set the license.
    pub fn with_license(mut self, license: impl Into<String>) -> Self {
        self.license = Some(license.into());
        self
    }

    /// Set the repository URL.
    pub fn with_repository(mut self, repo: impl Into<String>) -> Self {
        self.repository = Some(repo.into());
        self
    }

    /// Set the SHA-256 hash.
    pub fn with_hash(mut self, hash: impl Into<String>) -> Self {
        self.hash_sha256 = Some(hash.into());
        self
    }

    /// Generate a purl for npm packages.
    pub fn npm_purl(name: &str, version: Option<&str>) -> String {
        match version {
            Some(v) => format!("pkg:npm/{}@{}", name, v),
            None => format!("pkg:npm/{}", name),
        }
    }

    /// Generate a purl for GitHub repositories.
    pub fn github_purl(owner: &str, repo: &str, version: Option<&str>) -> String {
        match version {
            Some(v) => format!("pkg:github/{}/{}@{}", owner, repo, v),
            None => format!("pkg:github/{}/{}", owner, repo),
        }
    }
}

/// SBOM builder for creating software bill of materials.
pub struct SbomBuilder {
    /// Components in the SBOM
    components: Vec<Component>,

    /// Format to output
    format: SbomFormat,

    /// Include npm dependencies
    include_npm: bool,

    /// Include Cargo dependencies
    include_cargo: bool,
}

impl SbomBuilder {
    /// Create a new SBOM builder.
    pub fn new() -> Self {
        Self {
            components: Vec::new(),
            format: SbomFormat::CycloneDx,
            include_npm: false,
            include_cargo: false,
        }
    }

    /// Set the output format.
    pub fn with_format(mut self, format: SbomFormat) -> Self {
        self.format = format;
        self
    }

    /// Include npm dependencies.
    pub fn with_npm(mut self, include: bool) -> Self {
        self.include_npm = include;
        self
    }

    /// Include Cargo dependencies.
    pub fn with_cargo(mut self, include: bool) -> Self {
        self.include_cargo = include;
        self
    }

    /// Add a component.
    pub fn add_component(&mut self, component: Component) {
        self.components.push(component);
    }

    /// Get the components.
    pub fn components(&self) -> &[Component] {
        &self.components
    }

    /// Get the format.
    pub fn format(&self) -> SbomFormat {
        self.format
    }

    /// Should include npm dependencies.
    pub fn include_npm(&self) -> bool {
        self.include_npm
    }

    /// Should include Cargo dependencies.
    pub fn include_cargo(&self) -> bool {
        self.include_cargo
    }

    /// Build SBOM from a directory.
    pub fn build_from_path(&mut self, path: &Path) -> Result<(), SbomError> {
        use super::extractor::DependencyExtractor;

        let extractor = DependencyExtractor::new();

        // Extract MCP servers
        for component in extractor.extract_mcp_servers(path)? {
            self.add_component(component);
        }

        // Extract skills
        for component in extractor.extract_skills(path)? {
            self.add_component(component);
        }

        // Extract npm dependencies if enabled
        if self.include_npm {
            for component in extractor.extract_npm_dependencies(path)? {
                self.add_component(component);
            }
        }

        // Extract Cargo dependencies if enabled
        if self.include_cargo {
            for component in extractor.extract_cargo_dependencies(path)? {
                self.add_component(component);
            }
        }

        Ok(())
    }

    /// Generate SBOM output as JSON string.
    pub fn to_json(&self) -> Result<String, SbomError> {
        match self.format {
            SbomFormat::CycloneDx => {
                let bom = super::cyclonedx::CycloneDxBom::from_components(&self.components);
                serde_json::to_string_pretty(&bom)
                    .map_err(|e| SbomError::Serialization(e.to_string()))
            }
            SbomFormat::Spdx => {
                let doc = super::spdx::SpdxDocument::from_components(&self.components);
                serde_json::to_string_pretty(&doc)
                    .map_err(|e| SbomError::Serialization(e.to_string()))
            }
        }
    }
}

impl Default for SbomBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for SBOM operations.
#[derive(Debug, thiserror::Error)]
pub enum SbomError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parse error: {0}")]
    JsonParse(String),

    #[error("YAML parse error: {0}")]
    YamlParse(String),

    #[error("TOML parse error: {0}")]
    TomlParse(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_component_new() {
        let comp = Component::new("test-package", ComponentType::Library);
        assert_eq!(comp.name, "test-package");
        assert_eq!(comp.component_type, ComponentType::Library);
        assert!(comp.version.is_none());
    }

    #[test]
    fn test_component_builder() {
        let comp = Component::new("my-mcp-server", ComponentType::McpServer)
            .with_version("1.0.0")
            .with_description("A test MCP server")
            .with_author("Test Author");

        assert_eq!(comp.name, "my-mcp-server");
        assert_eq!(comp.version, Some("1.0.0".to_string()));
        assert_eq!(comp.description, Some("A test MCP server".to_string()));
        assert_eq!(comp.author, Some("Test Author".to_string()));
    }

    #[test]
    fn test_npm_purl() {
        let purl = Component::npm_purl("express", Some("4.18.0"));
        assert_eq!(purl, "pkg:npm/express@4.18.0");

        let purl_no_version = Component::npm_purl("express", None);
        assert_eq!(purl_no_version, "pkg:npm/express");
    }

    #[test]
    fn test_github_purl() {
        let purl = Component::github_purl("owner", "repo", Some("v1.0.0"));
        assert_eq!(purl, "pkg:github/owner/repo@v1.0.0");
    }

    #[test]
    fn test_sbom_builder() {
        let mut builder = SbomBuilder::new()
            .with_format(SbomFormat::CycloneDx)
            .with_npm(true);

        builder.add_component(Component::new("test", ComponentType::Library));

        assert_eq!(builder.components().len(), 1);
        assert!(builder.include_npm());
        assert!(!builder.include_cargo());
    }

    #[test]
    fn test_sbom_format_parse() {
        assert_eq!(
            "cyclonedx".parse::<SbomFormat>().unwrap(),
            SbomFormat::CycloneDx
        );
        assert_eq!("cdx".parse::<SbomFormat>().unwrap(), SbomFormat::CycloneDx);
        assert_eq!("spdx".parse::<SbomFormat>().unwrap(), SbomFormat::Spdx);
        assert!("unknown".parse::<SbomFormat>().is_err());
    }

    #[test]
    fn test_component_type_to_cyclonedx() {
        assert_eq!(
            ComponentType::Application.to_cyclonedx_type(),
            "application"
        );
        assert_eq!(ComponentType::Library.to_cyclonedx_type(), "library");
        assert_eq!(ComponentType::McpServer.to_cyclonedx_type(), "service");
        assert_eq!(ComponentType::Skill.to_cyclonedx_type(), "application");
    }

    #[test]
    fn test_component_type_to_cyclonedx_all() {
        assert_eq!(ComponentType::Service.to_cyclonedx_type(), "service");
        assert_eq!(ComponentType::Plugin.to_cyclonedx_type(), "library");
        assert_eq!(ComponentType::Subagent.to_cyclonedx_type(), "application");
    }

    #[test]
    fn test_component_with_license() {
        let comp = Component::new("test", ComponentType::Library).with_license("MIT");

        assert_eq!(comp.license, Some("MIT".to_string()));
    }

    #[test]
    fn test_component_with_repository() {
        let comp = Component::new("test", ComponentType::Library)
            .with_repository("https://github.com/test/test");

        assert_eq!(
            comp.repository,
            Some("https://github.com/test/test".to_string())
        );
    }

    #[test]
    fn test_component_with_hash() {
        let comp = Component::new("test", ComponentType::Library).with_hash("abc123def456");

        assert_eq!(comp.hash_sha256, Some("abc123def456".to_string()));
    }

    #[test]
    fn test_github_purl_without_version() {
        let purl = Component::github_purl("owner", "repo", None);
        assert_eq!(purl, "pkg:github/owner/repo");
    }

    #[test]
    fn test_sbom_builder_with_cargo() {
        let builder = SbomBuilder::new().with_cargo(true);

        assert!(builder.include_cargo());
        assert!(!builder.include_npm());
    }

    #[test]
    fn test_sbom_builder_format() {
        let builder = SbomBuilder::new().with_format(SbomFormat::Spdx);

        assert_eq!(builder.format(), SbomFormat::Spdx);
    }

    #[test]
    fn test_sbom_builder_default() {
        let builder = SbomBuilder::default();

        assert_eq!(builder.format(), SbomFormat::CycloneDx);
        assert!(!builder.include_npm());
        assert!(!builder.include_cargo());
        assert!(builder.components().is_empty());
    }

    #[test]
    fn test_sbom_format_default() {
        let format = SbomFormat::default();
        assert_eq!(format, SbomFormat::CycloneDx);
    }

    #[test]
    fn test_sbom_format_debug() {
        let format = SbomFormat::CycloneDx;
        assert_eq!(format!("{:?}", format), "CycloneDx");
    }

    #[test]
    fn test_sbom_builder_to_json() {
        let mut builder = SbomBuilder::new();
        builder.add_component(Component::new("test", ComponentType::Library).with_version("1.0.0"));

        let json = builder.to_json().unwrap();
        assert!(json.contains("CycloneDX"));
        assert!(json.contains("test"));
    }

    #[test]
    fn test_sbom_builder_to_json_spdx() {
        let mut builder = SbomBuilder::new().with_format(SbomFormat::Spdx);
        builder.add_component(Component::new("test", ComponentType::Library).with_version("1.0.0"));

        let json = builder.to_json().unwrap();
        assert!(json.contains("SPDX-2.3"));
        assert!(json.contains("test"));
    }

    #[test]
    fn test_sbom_error_display() {
        let err1 = SbomError::JsonParse("test error".to_string());
        assert!(err1.to_string().contains("JSON parse error"));

        let err2 = SbomError::YamlParse("test error".to_string());
        assert!(err2.to_string().contains("YAML parse error"));

        let err3 = SbomError::TomlParse("test error".to_string());
        assert!(err3.to_string().contains("TOML parse error"));

        let err4 = SbomError::Serialization("test error".to_string());
        assert!(err4.to_string().contains("Serialization error"));

        let err5 = SbomError::UnsupportedFormat("test".to_string());
        assert!(err5.to_string().contains("Unsupported format"));
    }

    #[test]
    fn test_sbom_builder_build_from_path() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(
            temp_dir.path().join("mcp.json"),
            r#"{"mcpServers": {"test-server": {"command": "npx"}}}"#,
        )
        .unwrap();

        let mut builder = SbomBuilder::new();
        let result = builder.build_from_path(temp_dir.path());

        assert!(result.is_ok());
        assert_eq!(builder.components().len(), 1);
    }

    #[test]
    fn test_sbom_builder_build_from_path_with_npm() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(
            temp_dir.path().join("package.json"),
            r#"{"dependencies": {"express": "^4.18.0"}}"#,
        )
        .unwrap();

        let mut builder = SbomBuilder::new().with_npm(true);
        let result = builder.build_from_path(temp_dir.path());

        assert!(result.is_ok());
        assert!(!builder.components().is_empty());
    }

    #[test]
    fn test_sbom_builder_build_from_path_with_cargo() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(
            temp_dir.path().join("Cargo.toml"),
            r#"[dependencies]
serde = "1.0"
"#,
        )
        .unwrap();

        let mut builder = SbomBuilder::new().with_cargo(true);
        let result = builder.build_from_path(temp_dir.path());

        assert!(result.is_ok());
        assert!(!builder.components().is_empty());
    }

    #[test]
    fn test_component_serialization() {
        let comp = Component::new("test", ComponentType::Library)
            .with_version("1.0.0")
            .with_purl("pkg:npm/test@1.0.0");

        let json = serde_json::to_string(&comp).unwrap();
        assert!(json.contains("test"));
        assert!(json.contains("1.0.0"));
        assert!(json.contains("pkg:npm/test@1.0.0"));
    }

    #[test]
    fn test_component_deserialization() {
        let json = r#"{"name":"test","type":"library","version":"1.0.0"}"#;
        let comp: Component = serde_json::from_str(json).unwrap();

        assert_eq!(comp.name, "test");
        assert_eq!(comp.version, Some("1.0.0".to_string()));
        assert_eq!(comp.component_type, ComponentType::Library);
    }
}
