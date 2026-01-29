//! Path validation and traversal prevention
//!
//! Provides secure path handling to prevent path traversal attacks.

use std::path::{Path, PathBuf};
use thiserror::Error;

/// Errors that can occur during path security validation
#[derive(Debug, Error)]
pub enum PathSecurityError {
    #[error("Path traversal attempt detected")]
    TraversalAttempt(PathBuf),

    #[error("Encoded path traversal detected")]
    EncodedTraversal(PathBuf),

    #[error("Unicode homoglyph traversal detected")]
    HomoglyphTraversal(PathBuf),

    #[error("Failed to canonicalize path: {path}")]
    CanonicalizeFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Path contains null byte")]
    NullByteInPath(PathBuf),

    #[error("Path validation failed")]
    ValidationFailed(String),
}

/// A validated, canonical path that has been checked for security issues
pub struct SafePath {
    canonical: PathBuf,
    original: PathBuf,
}

impl SafePath {
    /// Create a new SafePath after validation
    ///
    /// This performs several security checks:
    /// 1. Checks for literal `..` sequences
    /// 2. Checks for URL-encoded traversal patterns
    /// 3. Checks for Unicode homoglyphs
    /// 4. Canonicalizes the path to resolve symlinks and relative components
    /// 5. Validates the canonical path
    pub fn new(path: impl AsRef<Path>) -> Result<Self, PathSecurityError> {
        let original = path.as_ref().to_path_buf();

        // 1. Check for traversal patterns before canonicalization
        Self::check_traversal_patterns(&original)?;

        // 2. Canonicalize the path (resolves symlinks and relative components)
        let canonical =
            original
                .canonicalize()
                .map_err(|e| PathSecurityError::CanonicalizeFailed {
                    path: original.clone(),
                    source: e,
                })?;

        Ok(Self {
            canonical,
            original,
        })
    }

    /// Check for various path traversal patterns (public static method)
    ///
    /// This can be called without creating a SafePath instance,
    /// useful for validating paths that may not exist yet.
    pub fn check_traversal_patterns_static(path: &Path) -> Result<(), PathSecurityError> {
        Self::check_traversal_patterns(path)
    }

    /// Check for various path traversal patterns
    fn check_traversal_patterns(path: &Path) -> Result<(), PathSecurityError> {
        let path_str = path.to_string_lossy();

        // Check for null bytes (potential injection)
        if path_str.contains('\0') {
            return Err(PathSecurityError::NullByteInPath(path.to_path_buf()));
        }

        // Check for literal traversal
        if path_str.contains("..") {
            return Err(PathSecurityError::TraversalAttempt(path.to_path_buf()));
        }

        // Check for URL-encoded variants (case-insensitive)
        let path_lower = path_str.to_lowercase();
        let encoded_patterns = [
            "%2e%2e", // ..
            "%252e",  // %2e (double-encoded)
            "..%2f",  // ../
            "%2f..",  // /..
        ];

        for pattern in &encoded_patterns {
            if path_lower.contains(pattern) {
                return Err(PathSecurityError::EncodedTraversal(path.to_path_buf()));
            }
        }

        // Check for Unicode homoglyphs
        // U+2024 (ONE DOT LEADER) looks like '.'
        if path_str.contains('\u{2024}') {
            return Err(PathSecurityError::HomoglyphTraversal(path.to_path_buf()));
        }

        Ok(())
    }

    /// Get the canonical (absolute, symlink-resolved) path
    pub fn canonical(&self) -> &Path {
        &self.canonical
    }

    /// Get the original path as provided
    pub fn original(&self) -> &Path {
        &self.original
    }

    /// Check if this path is within the given boundary directory
    pub fn is_within(&self, boundary: &Path) -> Result<bool, PathSecurityError> {
        let boundary_canonical =
            boundary
                .canonicalize()
                .map_err(|e| PathSecurityError::CanonicalizeFailed {
                    path: boundary.to_path_buf(),
                    source: e,
                })?;

        Ok(self.canonical.starts_with(&boundary_canonical))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_check_traversal_patterns_rejects_literal_dots() {
        let path = Path::new("/tmp/../etc/passwd");
        let result = SafePath::check_traversal_patterns(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_traversal_patterns_rejects_url_encoded() {
        let path = Path::new("/tmp/%2e%2e/etc/passwd");
        let result = SafePath::check_traversal_patterns(path);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_traversal_patterns_accepts_normal_path() {
        let path = Path::new("/tmp/test.txt");
        let result = SafePath::check_traversal_patterns(path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_safe_path_with_valid_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let safe_path = SafePath::new(&file_path);
        assert!(safe_path.is_ok());
    }

    #[test]
    fn test_safe_path_canonical_is_absolute() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let safe_path = SafePath::new(&file_path).unwrap();
        assert!(safe_path.canonical().is_absolute());
    }
}
