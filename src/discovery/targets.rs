//! Scan target definitions.

use std::path::PathBuf;

/// The kind of scan target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetKind {
    /// SKILL.md or CLAUDE.md file
    Skill,
    /// Command definition file (.claude/commands/*.md)
    Command,
    /// MCP configuration file (mcp.json, .mcp.json)
    Mcp,
    /// Hook configuration file (settings.json)
    Hook,
    /// Dependency manifest file (package.json, Cargo.toml, etc.)
    Dependency,
    /// Docker-related file (Dockerfile, docker-compose.yml)
    Docker,
    /// Plugin manifest file (plugin.json, marketplace.json)
    Plugin,
    /// Subagent definition file (.claude/agents/*.md)
    Subagent,
    /// Rules directory file (.claude/rules/*.md)
    RulesDir,
    /// Generic text file
    TextFile,
    /// Unknown file type
    Unknown,
}

impl TargetKind {
    /// Get the target kind from a file path.
    pub fn from_path(path: &std::path::Path) -> Self {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();

        // Check specific file names first
        match file_name {
            "SKILL.md" | "CLAUDE.md" => return Self::Skill,
            "mcp.json" | ".mcp.json" => return Self::Mcp,
            "settings.json" => return Self::Hook,
            "plugin.json" | "marketplace.json" => return Self::Plugin,
            "Dockerfile" | "dockerfile" => return Self::Docker,
            "package.json" | "Cargo.toml" | "requirements.txt" | "Pipfile" | "pyproject.toml"
            | "go.mod" | "Gemfile" | "composer.json" | "pom.xml" => return Self::Dependency,
            _ => {}
        }

        // Check by path components
        let path_str = path.to_string_lossy();

        if (path_str.contains(".claude/commands/")
            || path_str.contains("/commands/")
            || path_str.starts_with("commands/"))
            && file_name.ends_with(".md")
        {
            return Self::Command;
        }

        if path_str.contains(".claude/agents/") || path_str.starts_with(".claude/agents/") {
            return Self::Subagent;
        }

        if path_str.contains(".claude/rules/")
            || path_str.contains("/rules/")
            || path_str.starts_with("rules/")
            || path_str.starts_with(".claude/rules/")
        {
            return Self::RulesDir;
        }

        // Check by extension
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            match ext {
                "md" => {
                    if path_str.contains("scripts/") || path_str.contains(".claude/") {
                        return Self::Skill;
                    }
                    return Self::TextFile;
                }
                "json" => return Self::Unknown,
                "yml" | "yaml" => {
                    if file_name.contains("docker-compose") || file_name.contains("compose") {
                        return Self::Docker;
                    }
                    return Self::Unknown;
                }
                _ => return Self::Unknown,
            }
        }

        Self::Unknown
    }
}

/// A scan target representing a file or directory to be scanned.
#[derive(Debug, Clone)]
pub struct ScanTarget {
    /// The path to the target.
    pub path: PathBuf,
    /// The kind of target.
    pub kind: TargetKind,
    /// The discovery source (how this target was found).
    pub source: DiscoverySource,
}

/// How a scan target was discovered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoverySource {
    /// Explicitly specified by user (CLI argument).
    UserSpecified,
    /// Discovered via file system traversal.
    FileSystem,
    /// Discovered via client auto-detection (Claude, Cursor, etc.).
    ClientDetection,
    /// Discovered via remote URL.
    Remote,
}

impl ScanTarget {
    /// Create a new scan target.
    pub fn new(path: PathBuf, kind: TargetKind, source: DiscoverySource) -> Self {
        Self { path, kind, source }
    }

    /// Create a scan target from a path, auto-detecting the kind.
    pub fn from_path(path: PathBuf, source: DiscoverySource) -> Self {
        let kind = TargetKind::from_path(&path);
        Self { path, kind, source }
    }

    /// Create a user-specified scan target.
    pub fn user_specified(path: PathBuf) -> Self {
        Self::from_path(path, DiscoverySource::UserSpecified)
    }

    /// Create a file system discovered scan target.
    pub fn discovered(path: PathBuf) -> Self {
        Self::from_path(path, DiscoverySource::FileSystem)
    }

    /// Create a client-detected scan target.
    pub fn from_client(path: PathBuf) -> Self {
        Self::from_path(path, DiscoverySource::ClientDetection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_target_kind_skill() {
        assert_eq!(
            TargetKind::from_path(Path::new("SKILL.md")),
            TargetKind::Skill
        );
        assert_eq!(
            TargetKind::from_path(Path::new("CLAUDE.md")),
            TargetKind::Skill
        );
        assert_eq!(
            TargetKind::from_path(Path::new(".claude/CLAUDE.md")),
            TargetKind::Skill
        );
    }

    #[test]
    fn test_target_kind_command() {
        assert_eq!(
            TargetKind::from_path(Path::new(".claude/commands/test.md")),
            TargetKind::Command
        );
        assert_eq!(
            TargetKind::from_path(Path::new("commands/deploy.md")),
            TargetKind::Command
        );
    }

    #[test]
    fn test_target_kind_mcp() {
        assert_eq!(
            TargetKind::from_path(Path::new("mcp.json")),
            TargetKind::Mcp
        );
        assert_eq!(
            TargetKind::from_path(Path::new(".mcp.json")),
            TargetKind::Mcp
        );
    }

    #[test]
    fn test_target_kind_dependency() {
        assert_eq!(
            TargetKind::from_path(Path::new("package.json")),
            TargetKind::Dependency
        );
        assert_eq!(
            TargetKind::from_path(Path::new("Cargo.toml")),
            TargetKind::Dependency
        );
        assert_eq!(
            TargetKind::from_path(Path::new("requirements.txt")),
            TargetKind::Dependency
        );
    }

    #[test]
    fn test_target_kind_docker() {
        assert_eq!(
            TargetKind::from_path(Path::new("Dockerfile")),
            TargetKind::Docker
        );
        assert_eq!(
            TargetKind::from_path(Path::new("docker-compose.yml")),
            TargetKind::Docker
        );
    }

    #[test]
    fn test_target_kind_plugin() {
        assert_eq!(
            TargetKind::from_path(Path::new("plugin.json")),
            TargetKind::Plugin
        );
        assert_eq!(
            TargetKind::from_path(Path::new("marketplace.json")),
            TargetKind::Plugin
        );
    }

    #[test]
    fn test_target_kind_subagent() {
        assert_eq!(
            TargetKind::from_path(Path::new(".claude/agents/helper.md")),
            TargetKind::Subagent
        );
    }

    #[test]
    fn test_target_kind_rules_dir() {
        assert_eq!(
            TargetKind::from_path(Path::new(".claude/rules/custom.md")),
            TargetKind::RulesDir
        );
        assert_eq!(
            TargetKind::from_path(Path::new("rules/security.md")),
            TargetKind::RulesDir
        );
    }

    #[test]
    fn test_scan_target_creation() {
        let target = ScanTarget::user_specified(PathBuf::from("SKILL.md"));
        assert_eq!(target.kind, TargetKind::Skill);
        assert_eq!(target.source, DiscoverySource::UserSpecified);

        let target = ScanTarget::discovered(PathBuf::from("package.json"));
        assert_eq!(target.kind, TargetKind::Dependency);
        assert_eq!(target.source, DiscoverySource::FileSystem);

        let target = ScanTarget::from_client(PathBuf::from(".claude/CLAUDE.md"));
        assert_eq!(target.kind, TargetKind::Skill);
        assert_eq!(target.source, DiscoverySource::ClientDetection);
    }
}
