//! Text file detection utilities.
//!
//! Provides functions to detect whether a file should be scanned based on
//! its extension, name, or other characteristics.

use std::path::Path;

/// Check if a file is a cc-audit configuration file.
pub fn is_config_file(path: &Path) -> bool {
    const CONFIG_FILES: &[&str] = &[
        ".cc-audit.yaml",
        ".cc-audit.yml",
        ".cc-audit.json",
        ".cc-audit.toml",
        ".cc-auditignore",
    ];

    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| CONFIG_FILES.contains(&name))
}

/// Check if a file is a text file using the default configuration.
pub fn is_text_file(path: &Path) -> bool {
    static DEFAULT_CONFIG: std::sync::LazyLock<crate::config::TextFilesConfig> =
        std::sync::LazyLock::new(crate::config::TextFilesConfig::default);

    is_text_file_with_config(path, &DEFAULT_CONFIG)
}

/// Check if a file is a text file using the provided configuration.
pub fn is_text_file_with_config(path: &Path, config: &crate::config::TextFilesConfig) -> bool {
    // First try the config-based check
    if config.is_text_file(path) {
        return true;
    }

    // Additional checks for common patterns not easily captured in config
    if let Some(name) = path.file_name() {
        let name_str = name.to_string_lossy();
        let name_lower = name_str.to_lowercase();

        // Dotfiles are often text configuration files
        if name_str.starts_with('.') {
            return true;
        }

        // Files ending with "rc" are often configuration files
        if name_lower.ends_with("rc") {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_text_file_by_extension() {
        assert!(is_text_file(Path::new("test.md")));
        assert!(is_text_file(Path::new("test.txt")));
        assert!(is_text_file(Path::new("test.sh")));
        assert!(is_text_file(Path::new("test.py")));
        assert!(is_text_file(Path::new("test.js")));
        assert!(is_text_file(Path::new("test.rs")));
        assert!(is_text_file(Path::new("test.json")));
        assert!(is_text_file(Path::new("test.yaml")));
        assert!(is_text_file(Path::new("test.yml")));
        assert!(is_text_file(Path::new("test.toml")));
        assert!(is_text_file(Path::new("test.xml")));
        assert!(is_text_file(Path::new("test.html")));
        assert!(is_text_file(Path::new("test.css")));
        assert!(is_text_file(Path::new("test.go")));
        assert!(is_text_file(Path::new("test.rb")));
        assert!(is_text_file(Path::new("test.pl")));
        assert!(is_text_file(Path::new("test.php")));
        assert!(is_text_file(Path::new("test.java")));
        assert!(is_text_file(Path::new("test.c")));
        assert!(is_text_file(Path::new("test.cpp")));
        assert!(is_text_file(Path::new("test.h")));
        assert!(is_text_file(Path::new("test.hpp")));
        assert!(is_text_file(Path::new("test.cs")));
        assert!(is_text_file(Path::new("test.env")));
        assert!(is_text_file(Path::new("test.conf")));
        assert!(is_text_file(Path::new("test.cfg")));
        assert!(is_text_file(Path::new("test.ini")));
        assert!(is_text_file(Path::new("test.bash")));
        assert!(is_text_file(Path::new("test.zsh")));
        assert!(is_text_file(Path::new("test.ts")));
    }

    #[test]
    fn test_is_text_file_case_insensitive() {
        assert!(is_text_file(Path::new("test.MD")));
        assert!(is_text_file(Path::new("test.TXT")));
        assert!(is_text_file(Path::new("test.JSON")));
        assert!(is_text_file(Path::new("test.YAML")));
    }

    #[test]
    fn test_is_text_file_by_filename() {
        assert!(is_text_file(Path::new("Dockerfile")));
        assert!(is_text_file(Path::new("dockerfile")));
        assert!(is_text_file(Path::new("Makefile")));
        assert!(is_text_file(Path::new("makefile")));
        assert!(is_text_file(Path::new(".gitignore")));
        assert!(is_text_file(Path::new(".bashrc")));
        assert!(is_text_file(Path::new(".zshrc")));
        assert!(is_text_file(Path::new(".vimrc")));
    }

    #[test]
    fn test_is_text_file_returns_false_for_binary() {
        assert!(!is_text_file(Path::new("image.png")));
        assert!(!is_text_file(Path::new("binary.exe")));
        assert!(!is_text_file(Path::new("archive.zip")));
        assert!(!is_text_file(Path::new("document.pdf")));
        assert!(!is_text_file(Path::new("audio.mp3")));
        assert!(!is_text_file(Path::new("video.mp4")));
    }

    #[test]
    fn test_is_text_file_common_text_files() {
        assert!(is_text_file(Path::new("README")));
        assert!(is_text_file(Path::new("LICENSE")));
    }

    #[test]
    fn test_is_text_file_unknown_no_extension() {
        assert!(!is_text_file(Path::new("unknownfile123")));
    }

    #[test]
    fn test_is_config_file() {
        assert!(is_config_file(Path::new(".cc-audit.yaml")));
        assert!(is_config_file(Path::new(".cc-audit.yml")));
        assert!(is_config_file(Path::new(".cc-audit.json")));
        assert!(is_config_file(Path::new(".cc-audit.toml")));
        assert!(is_config_file(Path::new(".cc-auditignore")));
        assert!(!is_config_file(Path::new("other.yaml")));
        assert!(!is_config_file(Path::new("config.yaml")));
    }
}
