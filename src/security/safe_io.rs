//! Safe file I/O operations
//!
//! Provides secure file reading that prevents:
//! - Symlink attacks
//! - TOCTOU (Time-of-Check Time-of-Use) vulnerabilities
//! - Path traversal through symlinks

use std::fs::OpenOptions;
use std::io::{BufReader, Read};
use std::path::Path;
use thiserror::Error;

/// Errors that can occur during safe file I/O operations
#[derive(Debug, Error)]
pub enum SafeIoError {
    #[error("Failed to get metadata for {path}: {source}")]
    MetadataFailed {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Symlink rejected: {0}")]
    SymlinkRejected(std::path::PathBuf),

    #[error("Failed to open file {path}: {source}")]
    OpenFailed {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("Inode mismatch detected (possible TOCTOU attack): expected {expected}, got {actual}")]
    InodeMismatch {
        path: std::path::PathBuf,
        expected: u64,
        actual: u64,
    },

    #[error("Failed to read file {path}: {source}")]
    ReadFailed {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Safe file reader that prevents symlink attacks and TOCTOU vulnerabilities
pub struct SafeFileReader;

impl SafeFileReader {
    /// Safely read a file to a string without following symlinks
    ///
    /// On Unix systems, this uses O_NOFOLLOW to prevent symlink following
    /// and verifies the inode hasn't changed to mitigate TOCTOU attacks.
    ///
    /// # Security Features
    ///
    /// 1. Symlink Detection: Rejects symlinks immediately
    /// 2. O_NOFOLLOW: Uses O_NOFOLLOW flag on Unix systems
    /// 3. Inode Verification: Checks inode hasn't changed (TOCTOU mitigation)
    /// 4. Fail-Secure: Any error results in read failure
    pub fn read_to_string(path: &Path) -> Result<String, SafeIoError> {
        // 1. Get metadata without following symlinks
        let metadata =
            std::fs::symlink_metadata(path).map_err(|e| SafeIoError::MetadataFailed {
                path: path.to_path_buf(),
                source: e,
            })?;

        // 2. Reject symlinks immediately (fail-secure)
        if metadata.file_type().is_symlink() {
            return Err(SafeIoError::SymlinkRejected(path.to_path_buf()));
        }

        // 3. Open file with O_NOFOLLOW on Unix
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::MetadataExt;

            let mut opts = OpenOptions::new();
            opts.read(true);

            // O_NOFOLLOW: Don't follow symlinks
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.custom_flags(libc::O_NOFOLLOW);
            }

            #[cfg(target_os = "macos")]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.custom_flags(libc::O_NOFOLLOW);
            }

            let file = opts.open(path).map_err(|e| SafeIoError::OpenFailed {
                path: path.to_path_buf(),
                source: e,
            })?;

            // 4. Verify inode hasn't changed (TOCTOU mitigation)
            let file_metadata = file.metadata().map_err(|e| SafeIoError::MetadataFailed {
                path: path.to_path_buf(),
                source: e,
            })?;

            let original_inode = metadata.ino();
            let current_inode = file_metadata.ino();

            if original_inode != current_inode {
                return Err(SafeIoError::InodeMismatch {
                    path: path.to_path_buf(),
                    expected: original_inode,
                    actual: current_inode,
                });
            }

            file
        };

        // Non-Unix platforms (Windows, etc.)
        #[cfg(not(unix))]
        let file = File::open(path).map_err(|e| SafeIoError::OpenFailed {
            path: path.to_path_buf(),
            source: e,
        })?;

        // 5. Read content
        let mut content = String::new();
        let mut buf_reader = BufReader::new(file);
        buf_reader
            .read_to_string(&mut content)
            .map_err(|e| SafeIoError::ReadFailed {
                path: path.to_path_buf(),
                source: e,
            })?;

        Ok(content)
    }

    /// Read file to bytes (binary-safe version)
    pub fn read_to_bytes(path: &Path) -> Result<Vec<u8>, SafeIoError> {
        // 1. Get metadata without following symlinks
        let metadata =
            std::fs::symlink_metadata(path).map_err(|e| SafeIoError::MetadataFailed {
                path: path.to_path_buf(),
                source: e,
            })?;

        // 2. Reject symlinks immediately
        if metadata.file_type().is_symlink() {
            return Err(SafeIoError::SymlinkRejected(path.to_path_buf()));
        }

        // 3. Open file with O_NOFOLLOW on Unix
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::MetadataExt;

            let mut opts = OpenOptions::new();
            opts.read(true);

            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.custom_flags(libc::O_NOFOLLOW);
            }

            let file = opts.open(path).map_err(|e| SafeIoError::OpenFailed {
                path: path.to_path_buf(),
                source: e,
            })?;

            // Verify inode
            let file_metadata = file.metadata().map_err(|e| SafeIoError::MetadataFailed {
                path: path.to_path_buf(),
                source: e,
            })?;

            if metadata.ino() != file_metadata.ino() {
                return Err(SafeIoError::InodeMismatch {
                    path: path.to_path_buf(),
                    expected: metadata.ino(),
                    actual: file_metadata.ino(),
                });
            }

            file
        };

        #[cfg(not(unix))]
        let file = File::open(path).map_err(|e| SafeIoError::OpenFailed {
            path: path.to_path_buf(),
            source: e,
        })?;

        // Read bytes
        let mut bytes = Vec::new();
        let mut buf_reader = BufReader::new(file);
        buf_reader
            .read_to_end(&mut bytes)
            .map_err(|e| SafeIoError::ReadFailed {
                path: path.to_path_buf(),
                source: e,
            })?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_read_normal_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test content").unwrap();

        let result = SafeFileReader::read_to_string(&file_path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "test content");
    }

    #[cfg(unix)]
    #[test]
    fn test_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("target.txt");
        let link = temp_dir.path().join("link.txt");

        fs::write(&target, "content").unwrap();
        symlink(&target, &link).unwrap();

        let result = SafeFileReader::read_to_string(&link);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_to_bytes() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.bin");
        let data = vec![0u8, 1, 2, 3, 255];
        fs::write(&file_path, &data).unwrap();

        let result = SafeFileReader::read_to_bytes(&file_path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), data);
    }

    #[test]
    fn test_error_on_nonexistent_file() {
        let path = Path::new("/nonexistent/file.txt");
        let result = SafeFileReader::read_to_string(path);
        assert!(result.is_err());
    }
}
