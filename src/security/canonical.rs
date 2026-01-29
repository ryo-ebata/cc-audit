//! Canonical path handling for safe deduplication.
//!
//! Provides secure canonicalization that fails safely rather than falling back
//! to potentially unsafe non-canonical paths.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors that can occur during canonical path operations
#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("Failed to canonicalize {path}: {source}")]
    CanonicalizeFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// A set that stores only canonical paths, preventing duplicates caused by
/// symlinks or relative path variations.
///
/// This type ensures all paths are canonicalized before insertion, preventing
/// security issues that could arise from using non-canonical fallbacks.
#[derive(Debug, Clone, Default)]
pub struct CanonicalPathSet {
    paths: HashSet<PathBuf>,
}

impl CanonicalPathSet {
    /// Creates a new empty set.
    pub fn new() -> Self {
        Self {
            paths: HashSet::new(),
        }
    }

    /// Inserts a path into the set after canonicalizing it.
    ///
    /// # Errors
    ///
    /// Returns an error if the path cannot be canonicalized (e.g., doesn't exist,
    /// permission denied). This is fail-secure: we never fall back to non-canonical paths.
    ///
    /// # Security
    ///
    /// This method intentionally fails rather than using the original path as a fallback.
    /// Using non-canonical paths could allow an attacker to bypass deduplication by
    /// creating multiple symlinks to the same file.
    pub fn insert(&mut self, path: impl AsRef<Path>) -> Result<bool, CanonicalError> {
        let path = path.as_ref();
        let canonical = path
            .canonicalize()
            .map_err(|e| CanonicalError::CanonicalizeFailed {
                path: path.to_path_buf(),
                source: e,
            })?;

        Ok(self.paths.insert(canonical))
    }

    /// Checks if the set contains the given path (after canonicalizing it).
    ///
    /// # Errors
    ///
    /// Returns an error if the path cannot be canonicalized.
    pub fn contains(&self, path: impl AsRef<Path>) -> Result<bool, CanonicalError> {
        let path = path.as_ref();
        let canonical = path
            .canonicalize()
            .map_err(|e| CanonicalError::CanonicalizeFailed {
                path: path.to_path_buf(),
                source: e,
            })?;

        Ok(self.paths.contains(&canonical))
    }

    /// Returns the number of paths in the set.
    pub fn len(&self) -> usize {
        self.paths.len()
    }

    /// Returns true if the set contains no paths.
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_canonical_path_set_new() {
        let set = CanonicalPathSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_canonical_path_set_default() {
        let set = CanonicalPathSet::default();
        assert!(set.is_empty());
    }

    #[test]
    fn test_insert_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "content").unwrap();

        let mut set = CanonicalPathSet::new();
        let inserted = set.insert(&file_path).unwrap();

        assert!(inserted, "Should insert new path");
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_insert_duplicate_same_path() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "content").unwrap();

        let mut set = CanonicalPathSet::new();
        let first = set.insert(&file_path).unwrap();
        let second = set.insert(&file_path).unwrap();

        assert!(first, "First insert should return true");
        assert!(!second, "Second insert should return false (duplicate)");
        assert_eq!(set.len(), 1, "Should only contain one entry");
    }

    #[test]
    fn test_insert_nonexistent_file_fails() {
        let mut set = CanonicalPathSet::new();
        let nonexistent = PathBuf::from("/nonexistent/file.txt");

        let result = set.insert(&nonexistent);
        assert!(result.is_err(), "Should fail for nonexistent file");
        assert_eq!(set.len(), 0, "Should not insert on error");
    }

    #[cfg(unix)]
    #[test]
    fn test_insert_symlink_deduplicates() {
        use std::os::unix::fs::symlink;

        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("target.txt");
        let link1 = temp_dir.path().join("link1.txt");
        let link2 = temp_dir.path().join("link2.txt");

        fs::write(&target, "content").unwrap();
        symlink(&target, &link1).unwrap();
        symlink(&target, &link2).unwrap();

        let mut set = CanonicalPathSet::new();
        set.insert(&target).unwrap();
        let result1 = set.insert(&link1).unwrap();
        let result2 = set.insert(&link2).unwrap();

        assert!(!result1, "link1 should be recognized as duplicate");
        assert!(!result2, "link2 should be recognized as duplicate");
        assert_eq!(
            set.len(),
            1,
            "All paths should resolve to same canonical path"
        );
    }

    #[test]
    fn test_insert_relative_path_deduplicates() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "content").unwrap();

        // Create a relative path to the same file
        std::env::set_current_dir(temp_dir.path()).unwrap();
        let relative = PathBuf::from("test.txt");

        let mut set = CanonicalPathSet::new();
        set.insert(&file_path).unwrap();
        let result = set.insert(&relative).unwrap();

        assert!(!result, "Relative path should be recognized as duplicate");
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn test_contains_existing_path() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "content").unwrap();

        let mut set = CanonicalPathSet::new();
        set.insert(&file_path).unwrap();

        let contains = set.contains(&file_path).unwrap();
        assert!(contains, "Should contain the inserted path");
    }

    #[test]
    fn test_contains_nonexistent_path_fails() {
        let set = CanonicalPathSet::new();
        let nonexistent = PathBuf::from("/nonexistent/file.txt");

        let result = set.contains(&nonexistent);
        assert!(result.is_err(), "Should fail for nonexistent file");
    }

    #[cfg(unix)]
    #[test]
    fn test_contains_symlink() {
        use std::os::unix::fs::symlink;

        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("target.txt");
        let link = temp_dir.path().join("link.txt");

        fs::write(&target, "content").unwrap();
        symlink(&target, &link).unwrap();

        let mut set = CanonicalPathSet::new();
        set.insert(&target).unwrap();

        let contains = set.contains(&link).unwrap();
        assert!(
            contains,
            "Symlink should be recognized as same canonical path"
        );
    }

    #[test]
    fn test_multiple_different_files() {
        let temp_dir = TempDir::new().unwrap();
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");
        let file3 = temp_dir.path().join("file3.txt");

        fs::write(&file1, "content1").unwrap();
        fs::write(&file2, "content2").unwrap();
        fs::write(&file3, "content3").unwrap();

        let mut set = CanonicalPathSet::new();
        set.insert(&file1).unwrap();
        set.insert(&file2).unwrap();
        set.insert(&file3).unwrap();

        assert_eq!(set.len(), 3);
        assert!(set.contains(&file1).unwrap());
        assert!(set.contains(&file2).unwrap());
        assert!(set.contains(&file3).unwrap());
    }

    #[test]
    fn test_canonical_error_display() {
        let error = CanonicalError::CanonicalizeFailed {
            path: PathBuf::from("/test/path"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
        };

        let error_msg = format!("{}", error);
        assert!(error_msg.contains("/test/path"));
        assert!(error_msg.contains("Failed to canonicalize"));
    }

    #[test]
    fn test_clone() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "content").unwrap();

        let mut set1 = CanonicalPathSet::new();
        set1.insert(&file_path).unwrap();

        let set2 = set1.clone();
        assert_eq!(set1.len(), set2.len());
        assert!(set2.contains(&file_path).unwrap());
    }
}
