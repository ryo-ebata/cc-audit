//! File patterns for scan target discovery.

use std::path::Path;

/// A file pattern specification for matching scan targets.
#[derive(Debug, Clone)]
pub struct FilePattern {
    /// Root directories to search in.
    pub root_dirs: &'static [&'static str],
    /// File extensions to match.
    pub extensions: &'static [&'static str],
    /// Specific file names to match.
    pub file_names: &'static [&'static str],
}

impl FilePattern {
    /// Check if a path matches this pattern.
    pub fn matches(&self, path: &Path) -> bool {
        // Check specific file names first
        if let Some(file_name) = path.file_name().and_then(|n| n.to_str())
            && self.file_names.contains(&file_name)
        {
            return true;
        }

        // Check extensions
        if !self.extensions.is_empty() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                return self.extensions.contains(&ext);
            }
            return false;
        }

        true
    }

    /// Check if a path is within one of the root directories.
    pub fn is_in_root_dir(&self, path: &Path, base: &Path) -> bool {
        if self.root_dirs.is_empty() {
            return true;
        }

        for root in self.root_dirs {
            let root_path = base.join(root);
            if path.starts_with(&root_path) {
                return true;
            }
        }

        false
    }
}

/// Patterns for SKILL.md and CLAUDE.md files.
pub static SKILL_PATTERNS: FilePattern = FilePattern {
    root_dirs: &[".claude", "scripts"],
    extensions: &["md"],
    file_names: &["SKILL.md", "CLAUDE.md"],
};

/// Patterns for command definition files.
pub static COMMAND_PATTERNS: FilePattern = FilePattern {
    root_dirs: &[".claude/commands", "commands"],
    extensions: &["md"],
    file_names: &[],
};

/// Patterns for MCP configuration files.
pub static MCP_PATTERNS: FilePattern = FilePattern {
    root_dirs: &[".claude"],
    extensions: &["json"],
    file_names: &["mcp.json", ".mcp.json"],
};

/// Patterns for dependency manifest files.
pub static DEPENDENCY_PATTERNS: FilePattern = FilePattern {
    root_dirs: &[],
    extensions: &["json", "toml", "txt", "lock"],
    file_names: &[
        "package.json",
        "package-lock.json",
        "Cargo.toml",
        "Cargo.lock",
        "requirements.txt",
        "Pipfile",
        "Pipfile.lock",
        "pyproject.toml",
        "poetry.lock",
        "go.mod",
        "go.sum",
        "Gemfile",
        "Gemfile.lock",
        "composer.json",
        "composer.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
    ],
};

/// Patterns for Docker-related files.
pub static DOCKER_PATTERNS: FilePattern = FilePattern {
    root_dirs: &[],
    extensions: &["yml", "yaml"],
    file_names: &[
        "Dockerfile",
        "dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yml",
        "compose.yaml",
    ],
};

/// Patterns for hook configuration files.
pub static HOOK_PATTERNS: FilePattern = FilePattern {
    root_dirs: &[".claude"],
    extensions: &["json"],
    file_names: &["settings.json"],
};

/// Patterns for subagent definition files.
pub static SUBAGENT_PATTERNS: FilePattern = FilePattern {
    root_dirs: &[".claude/agents"],
    extensions: &["md", "yaml", "yml"],
    file_names: &[],
};

/// Patterns for rules directory files.
pub static RULES_DIR_PATTERNS: FilePattern = FilePattern {
    root_dirs: &[".claude/rules", "rules"],
    extensions: &["md", "yaml", "yml"],
    file_names: &[],
};

/// Patterns for plugin manifest files.
pub static PLUGIN_PATTERNS: FilePattern = FilePattern {
    root_dirs: &[],
    extensions: &["json"],
    file_names: &["plugin.json", "marketplace.json"],
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skill_patterns_matches_skill_md() {
        assert!(SKILL_PATTERNS.matches(Path::new("SKILL.md")));
        assert!(SKILL_PATTERNS.matches(Path::new("path/to/SKILL.md")));
    }

    #[test]
    fn test_skill_patterns_matches_claude_md() {
        assert!(SKILL_PATTERNS.matches(Path::new("CLAUDE.md")));
        assert!(SKILL_PATTERNS.matches(Path::new(".claude/CLAUDE.md")));
    }

    #[test]
    fn test_skill_patterns_matches_md_extension() {
        assert!(SKILL_PATTERNS.matches(Path::new("readme.md")));
        assert!(!SKILL_PATTERNS.matches(Path::new("file.txt")));
    }

    #[test]
    fn test_command_patterns() {
        assert!(COMMAND_PATTERNS.matches(Path::new("test.md")));
        assert!(!COMMAND_PATTERNS.matches(Path::new("test.txt")));
    }

    #[test]
    fn test_mcp_patterns() {
        assert!(MCP_PATTERNS.matches(Path::new("mcp.json")));
        assert!(MCP_PATTERNS.matches(Path::new(".mcp.json")));
        assert!(!MCP_PATTERNS.matches(Path::new("config.yaml")));
    }

    #[test]
    fn test_dependency_patterns() {
        assert!(DEPENDENCY_PATTERNS.matches(Path::new("package.json")));
        assert!(DEPENDENCY_PATTERNS.matches(Path::new("Cargo.toml")));
        assert!(DEPENDENCY_PATTERNS.matches(Path::new("requirements.txt")));
        assert!(!DEPENDENCY_PATTERNS.matches(Path::new("README.md")));
    }

    #[test]
    fn test_docker_patterns() {
        assert!(DOCKER_PATTERNS.matches(Path::new("Dockerfile")));
        assert!(DOCKER_PATTERNS.matches(Path::new("docker-compose.yml")));
        assert!(DOCKER_PATTERNS.matches(Path::new("compose.yaml")));
    }

    #[test]
    fn test_is_in_root_dir() {
        let base = Path::new("/project");

        assert!(SKILL_PATTERNS.is_in_root_dir(Path::new("/project/.claude/CLAUDE.md"), base));
        assert!(SKILL_PATTERNS.is_in_root_dir(Path::new("/project/scripts/helper.md"), base));
        assert!(!SKILL_PATTERNS.is_in_root_dir(Path::new("/project/other/file.md"), base));
    }
}
