//! Path traversal security tests
//!
//! Tests for detecting and preventing path traversal attacks including:
//! - Literal `..` sequences
//! - URL-encoded variants
//! - Unicode homoglyphs
//! - Complex nested paths

use cc_audit::security::SafePath;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_rejects_literal_parent_reference() {
    let path = Path::new("/tmp/../etc/passwd");
    let result = SafePath::new(path);
    assert!(result.is_err(), "Should reject literal '..' sequence");
}

#[test]
fn test_rejects_url_encoded_traversal_lowercase() {
    let path = Path::new("/tmp/%2e%2e/etc/passwd");
    let result = SafePath::new(path);
    assert!(
        result.is_err(),
        "Should reject URL-encoded traversal (%2e%2e)"
    );
}

#[test]
fn test_rejects_url_encoded_traversal_mixed_case() {
    let path = Path::new("/tmp/%2E%2E/etc/passwd");
    let result = SafePath::new(path);
    assert!(
        result.is_err(),
        "Should reject URL-encoded traversal (mixed case)"
    );
}

#[test]
fn test_rejects_double_encoded_traversal() {
    let path = Path::new("/tmp/%252e%252e/etc/passwd");
    let result = SafePath::new(path);
    assert!(
        result.is_err(),
        "Should reject double URL-encoded traversal"
    );
}

#[test]
fn test_rejects_traversal_with_encoded_slash() {
    let path = Path::new("/tmp/..%2fetc/passwd");
    let result = SafePath::new(path);
    assert!(
        result.is_err(),
        "Should reject traversal with encoded slash"
    );
}

#[test]
fn test_rejects_traversal_with_backslash() {
    let path = Path::new("/tmp/..\\etc\\passwd");
    let result = SafePath::new(path);
    assert!(
        result.is_err(),
        "Should reject traversal with backslash (Windows-style)"
    );
}

#[test]
fn test_rejects_unicode_homoglyph_traversal() {
    // U+2024 (ONE DOT LEADER) looks like '.'
    let path_with_homoglyph = "/tmp/\u{2024}\u{2024}/etc/passwd";
    let path = Path::new(path_with_homoglyph);
    let result = SafePath::new(path);
    assert!(result.is_err(), "Should reject Unicode homoglyph traversal");
}

#[test]
fn test_rejects_complex_nested_traversal() {
    let path = Path::new("./../../etc/passwd");
    let result = SafePath::new(path);
    assert!(result.is_err(), "Should reject complex nested traversal");
}

#[test]
fn test_rejects_multiple_traversal_sequences() {
    let path = Path::new("/tmp/../../../etc/passwd");
    let result = SafePath::new(path);
    assert!(
        result.is_err(),
        "Should reject multiple traversal sequences"
    );
}

#[test]
fn test_accepts_normal_absolute_path() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");
    std::fs::write(&file_path, "test").unwrap();

    let result = SafePath::new(&file_path);
    assert!(result.is_ok(), "Should accept normal absolute path");
}

#[test]
fn test_accepts_normal_relative_path() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("subdir").join("test.txt");
    std::fs::create_dir_all(file_path.parent().unwrap()).unwrap();
    std::fs::write(&file_path, "test").unwrap();

    let result = SafePath::new(&file_path);
    assert!(result.is_ok(), "Should accept normal relative path");
}

#[test]
fn test_accepts_path_with_dots_in_filename() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("my.config.yaml");
    std::fs::write(&file_path, "test").unwrap();

    let result = SafePath::new(&file_path);
    assert!(result.is_ok(), "Should accept path with dots in filename");
}

#[test]
fn test_accepts_path_with_hidden_file() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join(".hidden");
    std::fs::write(&file_path, "test").unwrap();

    let result = SafePath::new(&file_path);
    assert!(result.is_ok(), "Should accept hidden file path");
}

#[test]
fn test_rejects_nonexistent_path_with_traversal() {
    let path = Path::new("/nonexistent/../etc/passwd");
    let result = SafePath::new(path);
    assert!(
        result.is_err(),
        "Should reject nonexistent path with traversal"
    );
}

#[test]
fn test_safe_path_provides_canonical_path() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");
    std::fs::write(&file_path, "test").unwrap();

    let safe_path = SafePath::new(&file_path).unwrap();
    let canonical = safe_path.canonical();

    assert!(canonical.is_absolute(), "Canonical path should be absolute");
    assert!(
        !canonical.to_string_lossy().contains(".."),
        "Canonical path should not contain '..'"
    );
}

#[test]
fn test_safe_path_preserves_original_path() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");
    std::fs::write(&file_path, "test").unwrap();

    let safe_path = SafePath::new(&file_path).unwrap();
    let original = safe_path.original();

    assert_eq!(original, &file_path, "Should preserve original path");
}

#[test]
fn test_safe_path_within_boundary_check() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.txt");
    std::fs::write(&file_path, "test").unwrap();

    let safe_path = SafePath::new(&file_path).unwrap();
    let is_within = safe_path.is_within(temp_dir.path()).unwrap();

    assert!(is_within, "Path should be within temp directory");
}

#[test]
fn test_safe_path_outside_boundary_check() {
    let temp_dir = TempDir::new().unwrap();
    let other_dir = TempDir::new().unwrap();
    let file_path = other_dir.path().join("test.txt");
    std::fs::write(&file_path, "test").unwrap();

    let safe_path = SafePath::new(&file_path).unwrap();
    let is_within = safe_path.is_within(temp_dir.path()).unwrap();

    assert!(!is_within, "Path should not be within different directory");
}

#[test]
fn test_rejects_path_with_null_byte() {
    let path_with_null = "/tmp/test\0hidden";
    let path = Path::new(path_with_null);
    let result = SafePath::new(path);
    assert!(
        result.is_err(),
        "Should reject path with null byte (potential injection)"
    );
}

#[test]
fn test_safe_path_display_does_not_leak_sensitive_info() {
    let path = Path::new("/sensitive/../etc/passwd");
    let result = SafePath::new(path);

    if let Err(e) = result {
        let error_msg = format!("{}", e);
        // Error message should not contain the full path
        assert!(
            !error_msg.contains("/sensitive"),
            "Error message should not leak sensitive path info"
        );
    }
}
