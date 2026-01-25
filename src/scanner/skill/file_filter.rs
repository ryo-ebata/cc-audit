use std::path::Path;

/// File extensions that should be scanned in skill directories
const SCANNABLE_EXTENSIONS: &[&str] = &[
    "md", "sh", "bash", "zsh", "py", "rb", "js", "ts", "json", "yaml", "yml", "toml",
];

/// Configuration file names that should be excluded from scanning
const CONFIG_FILES: &[&str] = &[
    ".cc-audit.yaml",
    ".cc-audit.yml",
    ".cc-audit.json",
    ".cc-audit.toml",
    ".cc-auditignore",
];

/// Determines which files should be scanned within a skill directory
pub struct SkillFileFilter;

impl SkillFileFilter {
    /// Check if a file should be scanned based on its extension
    pub fn should_scan(path: &Path) -> bool {
        // Exclude cc-audit config files
        if Self::is_config_file(path) {
            return false;
        }

        path.extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| SCANNABLE_EXTENSIONS.contains(&ext.to_lowercase().as_str()))
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
