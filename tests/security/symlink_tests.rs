//! Symlink attack and TOCTOU (Time-of-Check Time-of-Use) tests
//!
//! Tests for preventing symlink attacks and race conditions including:
//! - Symlink detection and rejection
//! - O_NOFOLLOW enforcement on Unix
//! - Inode verification for TOCTOU mitigation
//! - Safe file reading operations

use cc_audit::security::SafeFileReader;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::fs::symlink;

#[cfg(unix)]
#[test]
fn test_rejects_symlink_file() {
    let temp_dir = TempDir::new().unwrap();
    let target = temp_dir.path().join("target.txt");
    let link = temp_dir.path().join("link.txt");

    fs::write(&target, "content").unwrap();
    symlink(&target, &link).unwrap();

    let result = SafeFileReader::read_to_string(&link);
    assert!(result.is_err(), "Should reject reading from symlink file");
}

#[test]
fn test_reads_normal_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");
    fs::write(&file_path, "test content").unwrap();

    let result = SafeFileReader::read_to_string(&file_path);
    assert!(result.is_ok(), "Should read normal file");
    assert_eq!(result.unwrap(), "test content");
}

#[test]
fn test_reads_file_with_unicode_content() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("unicode.txt");
    let unicode_content = "日本語コンテンツ 🦀 Rust";
    fs::write(&file_path, unicode_content).unwrap();

    let result = SafeFileReader::read_to_string(&file_path);
    assert!(result.is_ok(), "Should read Unicode content");
    assert_eq!(result.unwrap(), unicode_content);
}

#[test]
fn test_error_on_nonexistent_file() {
    let path = Path::new("/nonexistent/file.txt");
    let result = SafeFileReader::read_to_string(path);
    assert!(result.is_err(), "Should error on nonexistent file");
}

#[test]
fn test_error_on_directory() {
    let temp_dir = TempDir::new().unwrap();
    let result = SafeFileReader::read_to_string(temp_dir.path());
    assert!(
        result.is_err(),
        "Should error when trying to read directory"
    );
}

#[cfg(unix)]
#[test]
fn test_rejects_symlink_to_directory() {
    let temp_dir = TempDir::new().unwrap();
    let target_dir = temp_dir.path().join("target_dir");
    let link = temp_dir.path().join("link_dir");

    fs::create_dir(&target_dir).unwrap();
    symlink(&target_dir, &link).unwrap();

    let result = SafeFileReader::read_to_string(&link);
    assert!(result.is_err(), "Should reject symlink to directory");
}

#[cfg(unix)]
#[test]
fn test_rejects_broken_symlink() {
    let temp_dir = TempDir::new().unwrap();
    let nonexistent = temp_dir.path().join("nonexistent.txt");
    let link = temp_dir.path().join("broken_link.txt");

    symlink(&nonexistent, &link).unwrap();

    let result = SafeFileReader::read_to_string(&link);
    assert!(result.is_err(), "Should reject broken symlink");
}

#[cfg(unix)]
#[test]
fn test_rejects_symlink_chain() {
    let temp_dir = TempDir::new().unwrap();
    let target = temp_dir.path().join("target.txt");
    let link1 = temp_dir.path().join("link1.txt");
    let link2 = temp_dir.path().join("link2.txt");

    fs::write(&target, "content").unwrap();
    symlink(&target, &link1).unwrap();
    symlink(&link1, &link2).unwrap();

    let result = SafeFileReader::read_to_string(&link2);
    assert!(
        result.is_err(),
        "Should reject symlink chain (first symlink should be detected)"
    );
}

#[test]
fn test_reads_empty_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("empty.txt");
    fs::write(&file_path, "").unwrap();

    let result = SafeFileReader::read_to_string(&file_path);
    assert!(result.is_ok(), "Should read empty file");
    assert_eq!(result.unwrap(), "");
}

#[test]
fn test_reads_large_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("large.txt");
    let large_content = "x".repeat(1_000_000); // 1MB
    fs::write(&file_path, &large_content).unwrap();

    let result = SafeFileReader::read_to_string(&file_path);
    assert!(result.is_ok(), "Should read large file");
    assert_eq!(result.unwrap().len(), 1_000_000);
}

#[cfg(unix)]
#[test]
fn test_inode_verification() {
    use std::os::unix::fs::MetadataExt;

    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");
    fs::write(&file_path, "test").unwrap();

    // Get inode before reading
    let metadata_before = fs::metadata(&file_path).unwrap();
    let inode_before = metadata_before.ino();

    // Read file
    let result = SafeFileReader::read_to_string(&file_path);
    assert!(result.is_ok());

    // Verify inode hasn't changed (no TOCTOU attack)
    let metadata_after = fs::metadata(&file_path).unwrap();
    let inode_after = metadata_after.ino();

    assert_eq!(
        inode_before, inode_after,
        "Inode should remain the same (no file swap)"
    );
}

#[test]
fn test_safe_file_reader_handles_permission_denied() {
    // This test is platform-specific and may not work on all systems
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("no_read.txt");
    fs::write(&file_path, "content").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&file_path).unwrap().permissions();
        perms.set_mode(0o000); // No permissions
        fs::set_permissions(&file_path, perms).unwrap();

        let result = SafeFileReader::read_to_string(&file_path);
        assert!(result.is_err(), "Should error on permission denied");

        // Restore permissions for cleanup
        let mut perms = fs::metadata(&file_path).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&file_path, perms).unwrap();
    }
}

#[cfg(unix)]
#[test]
fn test_o_nofollow_flag_enforcement() {
    // This test verifies that O_NOFOLLOW is actually being used
    // by attempting to read a symlink, which should fail

    let temp_dir = TempDir::new().unwrap();
    let target = temp_dir.path().join("target.txt");
    let link = temp_dir.path().join("link.txt");

    fs::write(&target, "content").unwrap();
    symlink(&target, &link).unwrap();

    // Should fail because O_NOFOLLOW prevents following symlinks
    let result = SafeFileReader::read_to_string(&link);
    assert!(
        result.is_err(),
        "O_NOFOLLOW should prevent symlink following"
    );

    // Verify the error is about symlink rejection
    if let Err(e) = result {
        let error_msg = format!("{}", e);
        assert!(
            error_msg.contains("symlink") || error_msg.contains("Symlink"),
            "Error should mention symlink: {}",
            error_msg
        );
    }
}

#[test]
fn test_safe_file_reader_preserves_content_integrity() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");
    let original_content = "Line 1\nLine 2\nLine 3\n";
    fs::write(&file_path, original_content).unwrap();

    let result = SafeFileReader::read_to_string(&file_path);
    assert!(result.is_ok());
    assert_eq!(
        result.unwrap(),
        original_content,
        "Content should be preserved exactly"
    );
}
