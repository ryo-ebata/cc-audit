//! Directory walking abstraction for consistent file discovery.

use crate::ignore::IgnoreFilter;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Configuration for directory walking.
#[derive(Debug, Clone, Default)]
pub struct WalkConfig {
    /// Root patterns to search (e.g., [".claude/commands", "commands"]).
    pub root_patterns: Vec<PathBuf>,
    /// File extensions to include (e.g., ["md", "yaml", "json"]).
    pub file_extensions: Vec<&'static str>,
    /// Maximum depth to traverse. None means unlimited.
    pub max_depth: Option<usize>,
    /// Whether to follow symbolic links.
    pub follow_symlinks: bool,
}

impl WalkConfig {
    /// Create a new WalkConfig with specified patterns.
    pub fn new(patterns: impl IntoIterator<Item = impl Into<PathBuf>>) -> Self {
        Self {
            root_patterns: patterns.into_iter().map(Into::into).collect(),
            ..Default::default()
        }
    }

    /// Set file extensions to include.
    pub fn with_extensions(mut self, extensions: &[&'static str]) -> Self {
        self.file_extensions = extensions.to_vec();
        self
    }

    /// Set maximum depth.
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = Some(depth);
        self
    }

    /// Set whether to follow symlinks.
    pub fn with_follow_symlinks(mut self, follow: bool) -> Self {
        self.follow_symlinks = follow;
        self
    }
}

/// Directory walker with optional ignore filter.
pub struct DirectoryWalker {
    config: WalkConfig,
    ignore_filter: Option<IgnoreFilter>,
}

impl DirectoryWalker {
    /// Create a new DirectoryWalker with the given configuration.
    pub fn new(config: WalkConfig) -> Self {
        Self {
            config,
            ignore_filter: None,
        }
    }

    /// Set an ignore filter.
    pub fn with_ignore_filter(mut self, filter: IgnoreFilter) -> Self {
        self.ignore_filter = Some(filter);
        self
    }

    /// Check if a path should be ignored.
    fn is_ignored(&self, path: &Path) -> bool {
        self.ignore_filter
            .as_ref()
            .is_some_and(|f| f.is_ignored(path))
    }

    /// Check if a path matches the configured extensions.
    fn matches_extension(&self, path: &Path) -> bool {
        if self.config.file_extensions.is_empty() {
            return true;
        }

        path.extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| self.config.file_extensions.contains(&ext))
    }

    /// Walk the directory and yield matching file paths.
    pub fn walk<'a>(&'a self, base_dir: &'a Path) -> impl Iterator<Item = PathBuf> + 'a {
        self.config.root_patterns.iter().flat_map(move |pattern| {
            let target = base_dir.join(pattern);
            if !target.exists() {
                return Vec::new();
            }

            let mut walker = WalkDir::new(&target).follow_links(self.config.follow_symlinks);

            if let Some(depth) = self.config.max_depth {
                walker = walker.max_depth(depth);
            }

            walker
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .filter(|e| self.matches_extension(e.path()))
                .filter(|e| !self.is_ignored(e.path()))
                .map(|e| e.path().to_path_buf())
                .collect::<Vec<_>>()
        })
    }

    /// Walk a single directory (not using patterns).
    pub fn walk_single(&self, dir: &Path) -> impl Iterator<Item = PathBuf> + '_ {
        let mut walker = WalkDir::new(dir).follow_links(self.config.follow_symlinks);

        if let Some(depth) = self.config.max_depth {
            walker = walker.max_depth(depth);
        }

        walker
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| self.matches_extension(e.path()))
            .filter(|e| !self.is_ignored(e.path()))
            .map(|e| e.path().to_path_buf())
            .collect::<Vec<_>>()
            .into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_dir() -> TempDir {
        let dir = TempDir::new().unwrap();

        // Create test structure
        let commands = dir.path().join(".claude").join("commands");
        fs::create_dir_all(&commands).unwrap();
        fs::write(commands.join("test.md"), "test content").unwrap();
        fs::write(commands.join("other.txt"), "other content").unwrap();

        let scripts = dir.path().join("scripts");
        fs::create_dir_all(&scripts).unwrap();
        fs::write(scripts.join("script.sh"), "#!/bin/bash").unwrap();

        dir
    }

    #[test]
    fn test_walk_with_pattern() {
        let dir = create_test_dir();
        let config = WalkConfig::new([".claude/commands"]).with_extensions(&["md"]);

        let walker = DirectoryWalker::new(config);
        let files: Vec<_> = walker.walk(dir.path()).collect();

        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("test.md"));
    }

    #[test]
    fn test_walk_without_extension_filter() {
        let dir = create_test_dir();
        let config = WalkConfig::new([".claude/commands"]);

        let walker = DirectoryWalker::new(config);
        let files: Vec<_> = walker.walk(dir.path()).collect();

        assert_eq!(files.len(), 2);
    }

    #[test]
    fn test_walk_single() {
        let dir = create_test_dir();
        let config = WalkConfig::default().with_extensions(&["sh"]);

        let walker = DirectoryWalker::new(config);
        let scripts_dir = dir.path().join("scripts");
        let files: Vec<_> = walker.walk_single(&scripts_dir).collect();

        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("script.sh"));
    }

    #[test]
    fn test_walk_nonexistent_pattern() {
        let dir = create_test_dir();
        let config = WalkConfig::new(["nonexistent"]);

        let walker = DirectoryWalker::new(config);
        let files: Vec<_> = walker.walk(dir.path()).collect();

        assert!(files.is_empty());
    }

    #[test]
    fn test_walk_with_max_depth() {
        let dir = create_test_dir();

        // Create nested structure
        let nested = dir.path().join("deep").join("nested").join("dir");
        fs::create_dir_all(&nested).unwrap();
        fs::write(nested.join("file.md"), "content").unwrap();

        let config = WalkConfig::new(["deep"]).with_max_depth(1);

        let walker = DirectoryWalker::new(config);
        let files: Vec<_> = walker.walk(dir.path()).collect();

        // Should not find the deeply nested file
        assert!(files.is_empty());
    }
}
