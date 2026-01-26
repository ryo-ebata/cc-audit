//! Path-related NewType wrappers with validation.

use std::path::{Path, PathBuf};
use thiserror::Error;

/// Error type for path validation failures.
#[derive(Error, Debug, Clone)]
pub enum PathValidationError {
    #[error("Path not found: {0}")]
    NotFound(PathBuf),

    #[error("Path is not a file: {0}")]
    NotAFile(PathBuf),

    #[error("Path is not a directory: {0}")]
    NotADirectory(PathBuf),

    #[error("Path is not readable: {0}")]
    NotReadable(PathBuf),
}

/// A validated scan target path.
///
/// Ensures the path exists at construction time.
#[derive(Debug, Clone)]
pub struct ScanTarget {
    path: PathBuf,
}

impl ScanTarget {
    /// Create a new ScanTarget after validating the path exists.
    pub fn new(path: impl AsRef<Path>) -> Result<Self, PathValidationError> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(PathValidationError::NotFound(path));
        }
        Ok(Self { path })
    }

    /// Create a ScanTarget for a file, validating it's actually a file.
    pub fn file(path: impl AsRef<Path>) -> Result<Self, PathValidationError> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(PathValidationError::NotFound(path));
        }
        if !path.is_file() {
            return Err(PathValidationError::NotAFile(path));
        }
        Ok(Self { path })
    }

    /// Create a ScanTarget for a directory, validating it's actually a directory.
    pub fn directory(path: impl AsRef<Path>) -> Result<Self, PathValidationError> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(PathValidationError::NotFound(path));
        }
        if !path.is_dir() {
            return Err(PathValidationError::NotADirectory(path));
        }
        Ok(Self { path })
    }

    /// Create a ScanTarget without validation (for testing or trusted paths).
    ///
    /// # Safety
    /// The caller must ensure the path is valid for the intended use.
    pub fn unchecked(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Get the underlying path reference.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the path as a PathBuf.
    pub fn to_path_buf(&self) -> PathBuf {
        self.path.clone()
    }

    /// Consume self and return the inner PathBuf.
    pub fn into_path_buf(self) -> PathBuf {
        self.path
    }

    /// Check if the target is a file.
    pub fn is_file(&self) -> bool {
        self.path.is_file()
    }

    /// Check if the target is a directory.
    pub fn is_dir(&self) -> bool {
        self.path.is_dir()
    }

    /// Get the file name component if present.
    pub fn file_name(&self) -> Option<&std::ffi::OsStr> {
        self.path.file_name()
    }

    /// Get the parent directory if present.
    pub fn parent(&self) -> Option<&Path> {
        self.path.parent()
    }
}

impl AsRef<Path> for ScanTarget {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl From<ScanTarget> for PathBuf {
    fn from(target: ScanTarget) -> Self {
        target.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_scan_target_valid_path() {
        let dir = tempdir().unwrap();
        let target = ScanTarget::new(dir.path());
        assert!(target.is_ok());
        assert!(target.unwrap().is_dir());
    }

    #[test]
    fn test_scan_target_invalid_path() {
        let result = ScanTarget::new("/nonexistent/path/12345");
        assert!(result.is_err());
        assert!(matches!(result, Err(PathValidationError::NotFound(_))));
    }

    #[test]
    fn test_scan_target_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let target = ScanTarget::file(&file_path);
        assert!(target.is_ok());
        assert!(target.unwrap().is_file());
    }

    #[test]
    fn test_scan_target_file_on_directory() {
        let dir = tempdir().unwrap();
        let result = ScanTarget::file(dir.path());
        assert!(result.is_err());
        assert!(matches!(result, Err(PathValidationError::NotAFile(_))));
    }

    #[test]
    fn test_scan_target_directory() {
        let dir = tempdir().unwrap();
        let target = ScanTarget::directory(dir.path());
        assert!(target.is_ok());
        assert!(target.unwrap().is_dir());
    }

    #[test]
    fn test_scan_target_directory_on_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let result = ScanTarget::directory(&file_path);
        assert!(result.is_err());
        assert!(matches!(result, Err(PathValidationError::NotADirectory(_))));
    }

    #[test]
    fn test_scan_target_unchecked() {
        let target = ScanTarget::unchecked("/any/path");
        assert_eq!(target.path(), Path::new("/any/path"));
    }

    #[test]
    fn test_scan_target_into_path_buf() {
        let dir = tempdir().unwrap();
        let target = ScanTarget::new(dir.path()).unwrap();
        let path_buf: PathBuf = target.into();
        assert_eq!(path_buf, dir.path());
    }

    #[test]
    fn test_scan_target_to_path_buf() {
        let dir = tempdir().unwrap();
        let target = ScanTarget::new(dir.path()).unwrap();
        let path_buf = target.to_path_buf();
        assert_eq!(path_buf, dir.path());
    }

    #[test]
    fn test_scan_target_into_path_buf_method() {
        let dir = tempdir().unwrap();
        let target = ScanTarget::new(dir.path()).unwrap();
        let path_buf = target.into_path_buf();
        assert_eq!(path_buf, dir.path());
    }

    #[test]
    fn test_scan_target_file_name() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let target = ScanTarget::file(&file_path).unwrap();
        assert_eq!(target.file_name().unwrap(), "test.txt");
    }

    #[test]
    fn test_scan_target_parent() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        fs::write(&file_path, "test").unwrap();

        let target = ScanTarget::file(&file_path).unwrap();
        assert_eq!(target.parent().unwrap(), dir.path());
    }

    #[test]
    fn test_scan_target_as_ref() {
        let dir = tempdir().unwrap();
        let target = ScanTarget::new(dir.path()).unwrap();
        let path: &Path = target.as_ref();
        assert_eq!(path, dir.path());
    }

    #[test]
    fn test_scan_target_debug() {
        let dir = tempdir().unwrap();
        let target = ScanTarget::new(dir.path()).unwrap();
        let debug_str = format!("{:?}", target);
        assert!(debug_str.contains("ScanTarget"));
    }

    #[test]
    fn test_scan_target_clone() {
        let dir = tempdir().unwrap();
        let target = ScanTarget::new(dir.path()).unwrap();
        let cloned = target.clone();
        assert_eq!(target.path(), cloned.path());
    }

    #[test]
    fn test_path_validation_error_display() {
        let err = PathValidationError::NotFound(PathBuf::from("/test"));
        assert!(err.to_string().contains("/test"));

        let err = PathValidationError::NotAFile(PathBuf::from("/test"));
        assert!(err.to_string().contains("/test"));

        let err = PathValidationError::NotADirectory(PathBuf::from("/test"));
        assert!(err.to_string().contains("/test"));

        let err = PathValidationError::NotReadable(PathBuf::from("/test"));
        assert!(err.to_string().contains("/test"));
    }

    #[test]
    fn test_path_validation_error_debug() {
        let err = PathValidationError::NotFound(PathBuf::from("/test"));
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("NotFound"));
    }

    #[test]
    fn test_path_validation_error_clone() {
        let err = PathValidationError::NotFound(PathBuf::from("/test"));
        let cloned = err.clone();
        assert!(matches!(cloned, PathValidationError::NotFound(_)));
    }

    #[test]
    fn test_scan_target_file_not_found() {
        let result = ScanTarget::file("/nonexistent/file.txt");
        assert!(result.is_err());
        assert!(matches!(result, Err(PathValidationError::NotFound(_))));
    }

    #[test]
    fn test_scan_target_directory_not_found() {
        let result = ScanTarget::directory("/nonexistent/dir");
        assert!(result.is_err());
        assert!(matches!(result, Err(PathValidationError::NotFound(_))));
    }
}
