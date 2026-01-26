use crate::engine::scanner::{Scanner, ScannerConfig};
use crate::error::Result;
use crate::ignore::IgnoreFilter;
use crate::rules::Finding;
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

impl Scanner for DockerScanner {
    fn scan_file(&self, path: &Path) -> Result<Vec<Finding>> {
        let content = self.config.read_file(path)?;
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
            if docker_file.exists()
                && !self.config.is_ignored(&docker_file)
                && let Ok(file_findings) = self.scan_file(&docker_file)
            {
                findings.extend(file_findings);
            }
        }

        // Scan for any .dockerfile files in the directory
        for entry in WalkDir::new(dir)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() && Self::is_dockerfile(path) && !self.config.is_ignored(path) {
                // Avoid scanning the same file twice
                let is_common_name = dockerfile_names.iter().any(|n| {
                    path.file_name()
                        .and_then(|f| f.to_str())
                        .is_some_and(|f| f == *n)
                });

                if (!is_common_name || path.parent() != Some(dir))
                    && let Ok(file_findings) = self.scan_file(path)
                {
                    findings.extend(file_findings);
                }
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
        assert!(!DockerScanner::is_dockerfile(Path::new("README.md")));
        assert!(!DockerScanner::is_dockerfile(Path::new("script.sh")));
    }

    #[test]
    fn test_scan_file_read_error() {
        let dir = TempDir::new().unwrap();
        let scanner = DockerScanner::new();
        let result = scanner.scan_file(dir.path());
        assert!(result.is_err());
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
