use std::path::Path;
use std::sync::LazyLock;

use crate::config::TextFilesConfig;

/// File extensions that should be scanned in skill directories
const SCANNABLE_EXTENSIONS: &[&str] = &[
    "md", "sh", "bash", "zsh", "py", "rb", "js", "mjs", "cjs", "jsx", "ts", "tsx", "json", "yaml",
    "yml", "toml", "ps1", "bat", "cmd", "pl", "php", "lua", "fish",
];

/// Configuration file names that should be excluded from scanning
const CONFIG_FILES: &[&str] = &[
    ".cc-audit.yaml",
    ".cc-audit.yml",
    ".cc-audit.json",
    ".cc-audit.toml",
    ".cc-auditignore",
];

static DEFAULT_TEXT_FILES_CONFIG: LazyLock<TextFilesConfig> =
    LazyLock::new(TextFilesConfig::default);

/// Determines which files should be scanned within a skill directory
pub struct SkillFileFilter;

impl SkillFileFilter {
    /// Check if a file should be scanned based on its extension
    pub fn should_scan(path: &Path) -> bool {
        // Exclude cc-audit config files
        if Self::is_config_file(path) {
            return false;
        }

        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| SCANNABLE_EXTENSIONS.contains(&ext.to_lowercase().as_str()))
        {
            return true;
        }

        // Extension-less executable scripts (e.g. `scripts/hook` with a `#!/bin/bash`)
        // must also be scanned; fall back to shebang detection so they are not
        // silently skipped.
        crate::run::has_known_shebang(path)
    }

    /// Check if a file should be scanned using configured text-file names.
    pub fn should_scan_with_config(path: &Path, text_files: &TextFilesConfig) -> bool {
        // Exclude cc-audit config files
        if Self::is_config_file(path) {
            return false;
        }

        // Preserve the historical default classifier and only add entries that
        // are explicitly configured beyond its built-in set.
        if text_files.is_text_file(path) && !DEFAULT_TEXT_FILES_CONFIG.is_text_file(path) {
            return true;
        }

        Self::should_scan(path)
    }

    /// Check if a file is a cc-audit configuration file
    pub fn is_config_file(path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| CONFIG_FILES.contains(&name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_markdown_files() {
        assert!(SkillFileFilter::should_scan(Path::new("test.md")));
        assert!(SkillFileFilter::should_scan(Path::new("SKILL.md")));
        assert!(SkillFileFilter::should_scan(Path::new("README.md")));
    }

    #[test]
    fn test_shell_files() {
        assert!(SkillFileFilter::should_scan(Path::new("test.sh")));
        assert!(SkillFileFilter::should_scan(Path::new("test.bash")));
        assert!(SkillFileFilter::should_scan(Path::new("test.zsh")));
    }

    #[test]
    fn test_script_files() {
        assert!(SkillFileFilter::should_scan(Path::new("test.py")));
        assert!(SkillFileFilter::should_scan(Path::new("test.rb")));
        assert!(SkillFileFilter::should_scan(Path::new("test.js")));
        assert!(SkillFileFilter::should_scan(Path::new("test.ts")));
    }

    #[test]
    fn test_extended_script_files() {
        for extension in [
            "mjs", "cjs", "jsx", "tsx", "ps1", "bat", "cmd", "pl", "php", "lua", "fish",
        ] {
            assert!(
                SkillFileFilter::should_scan(Path::new(&format!("test.{extension}"))),
                "{extension} files must be scannable"
            );
        }
    }

    #[test]
    fn test_config_files() {
        assert!(SkillFileFilter::should_scan(Path::new("test.json")));
        assert!(SkillFileFilter::should_scan(Path::new("test.yaml")));
        assert!(SkillFileFilter::should_scan(Path::new("test.yml")));
        assert!(SkillFileFilter::should_scan(Path::new("test.toml")));
    }

    #[test]
    fn test_case_insensitive() {
        assert!(SkillFileFilter::should_scan(Path::new("TEST.MD")));
        assert!(SkillFileFilter::should_scan(Path::new("test.SH")));
        assert!(SkillFileFilter::should_scan(Path::new("Test.Py")));
    }

    #[test]
    fn test_non_scannable_files() {
        assert!(!SkillFileFilter::should_scan(Path::new("test.exe")));
        assert!(!SkillFileFilter::should_scan(Path::new("test.bin")));
        assert!(!SkillFileFilter::should_scan(Path::new("test.dll")));
        assert!(!SkillFileFilter::should_scan(Path::new("test.so")));
        assert!(!SkillFileFilter::should_scan(Path::new("test.png")));
        assert!(!SkillFileFilter::should_scan(Path::new("test.jpg")));
    }

    #[test]
    fn test_no_extension() {
        assert!(!SkillFileFilter::should_scan(Path::new("no_extension")));
        assert!(!SkillFileFilter::should_scan(Path::new("Makefile")));
    }

    #[test]
    fn test_shebang_script_no_extension_is_scannable() {
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let script = dir.path().join("hook"); // no extension
        let mut f = std::fs::File::create(&script).unwrap();
        writeln!(f, "#!/bin/bash").unwrap();
        writeln!(f, "echo hi").unwrap();
        assert!(
            SkillFileFilter::should_scan(&script),
            "no-extension shebang scripts must be scannable in skill directories"
        );
    }

    #[test]
    fn test_no_extension_non_script_not_scannable() {
        let dir = tempfile::TempDir::new().unwrap();
        let f = dir.path().join("data");
        std::fs::write(&f, b"plain text, no shebang").unwrap();
        assert!(!SkillFileFilter::should_scan(&f));
    }

    #[test]
    fn test_config_files_excluded() {
        // cc-audit config files should be excluded from scanning
        assert!(!SkillFileFilter::should_scan(Path::new(".cc-audit.yaml")));
        assert!(!SkillFileFilter::should_scan(Path::new(".cc-audit.yml")));
        assert!(!SkillFileFilter::should_scan(Path::new(".cc-audit.json")));
        assert!(!SkillFileFilter::should_scan(Path::new(".cc-audit.toml")));
        assert!(!SkillFileFilter::should_scan(Path::new(".cc-auditignore")));
        // But regular yaml files should still be scanned
        assert!(SkillFileFilter::should_scan(Path::new("config.yaml")));
        assert!(SkillFileFilter::should_scan(Path::new("settings.yml")));
    }

    #[test]
    fn test_is_config_file() {
        assert!(SkillFileFilter::is_config_file(Path::new(".cc-audit.yaml")));
        assert!(SkillFileFilter::is_config_file(Path::new(
            "/some/path/.cc-audit.yaml"
        )));
        assert!(!SkillFileFilter::is_config_file(Path::new("config.yaml")));
        assert!(!SkillFileFilter::is_config_file(Path::new(".gitignore")));
    }
}
