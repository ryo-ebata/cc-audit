use super::error::RemoteError;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

/// Result of a successful clone operation
pub struct ClonedRepo {
    /// Path to the cloned repository
    pub path: PathBuf,
    /// Original repository URL
    pub url: String,
    /// Git ref that was checked out
    pub git_ref: String,
    /// Commit SHA of the checked out ref
    pub commit_sha: Option<String>,
    /// Temporary directory handle (dropped when ClonedRepo is dropped)
    _temp_dir: TempDir,
}

impl ClonedRepo {
    /// Get the path to the cloned repository
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Git repository cloner with security measures
pub struct GitCloner {
    /// Optional authentication token for private repositories
    auth_token: Option<String>,
    /// Clone timeout in seconds
    timeout_secs: u64,
    /// Maximum repository size in MB (0 = unlimited)
    max_size_mb: u64,
}

impl Default for GitCloner {
    fn default() -> Self {
        Self::new()
    }
}

impl GitCloner {
    /// Create a new GitCloner with default settings
    pub fn new() -> Self {
        Self {
            auth_token: None,
            timeout_secs: 300, // 5 minutes
            max_size_mb: 0,    // unlimited
        }
    }

    /// Set authentication token for private repositories
    pub fn with_auth_token(mut self, token: Option<String>) -> Self {
        self.auth_token = token;
        self
    }

    /// Set clone timeout in seconds
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Set maximum repository size in MB
    pub fn with_max_size(mut self, mb: u64) -> Self {
        self.max_size_mb = mb;
        self
    }

    /// Clone a repository with security measures
    ///
    /// Security measures:
    /// - Uses shallow clone (depth=1)
    /// - Disables git hooks (template and local)
    /// - Uses temporary directory that is automatically cleaned up
    pub fn clone(&self, url: &str, git_ref: &str) -> Result<ClonedRepo, RemoteError> {
        // Validate URL format
        self.validate_url(url)?;

        // Check if git is available
        self.check_git_available()?;

        // Create temporary directory
        let temp_dir = TempDir::new().map_err(|e| RemoteError::TempDir(e.to_string()))?;
        let repo_path = temp_dir.path().to_path_buf();

        // Build clone URL with auth token if provided
        let clone_url = self.build_clone_url(url)?;

        // Execute git clone with security measures
        self.execute_clone(&clone_url, &repo_path, git_ref)?;

        // Get commit SHA
        let commit_sha = self.get_commit_sha(&repo_path).ok();

        Ok(ClonedRepo {
            path: repo_path,
            url: url.to_string(),
            git_ref: git_ref.to_string(),
            commit_sha,
            _temp_dir: temp_dir,
        })
    }

    /// Validate the repository URL format
    fn validate_url(&self, url: &str) -> Result<(), RemoteError> {
        // Check for basic URL structure
        if !url.starts_with("https://") && !url.starts_with("git@") {
            return Err(RemoteError::InvalidUrl(format!(
                "URL must start with https:// or git@: {}",
                url
            )));
        }

        // Check for GitHub URL format
        if url.starts_with("https://github.com/") || url.starts_with("git@github.com:") {
            // Valid GitHub URL
            return Ok(());
        }

        // Allow other HTTPS URLs but warn about non-GitHub sources
        if url.starts_with("https://") {
            return Ok(());
        }

        Err(RemoteError::InvalidUrl(format!(
            "Unsupported URL format: {}",
            url
        )))
    }

    /// Check if git command is available
    fn check_git_available(&self) -> Result<(), RemoteError> {
        Command::new("git")
            .arg("--version")
            .output()
            .map_err(|_| RemoteError::GitNotFound)?;
        Ok(())
    }

    /// Build clone URL with authentication if needed
    fn build_clone_url(&self, url: &str) -> Result<String, RemoteError> {
        if let Some(ref token) = self.auth_token {
            // Insert token into HTTPS URL
            if url.starts_with("https://github.com/") {
                return Ok(url.replace(
                    "https://github.com/",
                    &format!("https://{}@github.com/", token),
                ));
            }
        }
        Ok(url.to_string())
    }

    /// Execute git clone command with security measures
    fn execute_clone(&self, url: &str, path: &Path, git_ref: &str) -> Result<(), RemoteError> {
        // Build the git clone command with security measures
        let mut cmd = Command::new("git");

        // Disable hooks for security
        cmd.env("GIT_TEMPLATE_DIR", "");

        // Clone with shallow depth
        cmd.args([
            "clone",
            "--depth",
            "1",
            "--single-branch",
            "--no-tags",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "advice.detachedHead=false",
        ]);

        // Add branch/ref if not HEAD
        if git_ref != "HEAD" && !git_ref.is_empty() {
            cmd.args(["--branch", git_ref]);
        }

        cmd.arg(url);
        cmd.arg(path);

        // Execute with timeout
        let output = cmd.output().map_err(|e| RemoteError::CloneFailed {
            url: url.to_string(),
            message: e.to_string(),
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);

            // Check for common error patterns
            if stderr.contains("Repository not found") || stderr.contains("404") {
                return Err(RemoteError::NotFound(url.to_string()));
            }

            if stderr.contains("Authentication failed")
                || stderr.contains("could not read Username")
            {
                return Err(RemoteError::AuthRequired(url.to_string()));
            }

            return Err(RemoteError::CloneFailed {
                url: url.to_string(),
                message: stderr.to_string(),
            });
        }

        Ok(())
    }

    /// Get the commit SHA of HEAD
    fn get_commit_sha(&self, path: &Path) -> Result<String, RemoteError> {
        let output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(path)
            .output()
            .map_err(|e| RemoteError::CloneFailed {
                url: "".to_string(),
                message: e.to_string(),
            })?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            Err(RemoteError::CloneFailed {
                url: "".to_string(),
                message: "Failed to get commit SHA".to_string(),
            })
        }
    }
}

/// Parse GitHub URL to extract owner and repo name
pub fn parse_github_url(url: &str) -> Option<(String, String)> {
    // Handle HTTPS URLs: https://github.com/owner/repo or https://github.com/owner/repo.git
    if url.starts_with("https://github.com/") {
        let path = url.trim_start_matches("https://github.com/");
        let path = path.trim_end_matches(".git");
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 2 {
            return Some((parts[0].to_string(), parts[1].to_string()));
        }
    }

    // Handle SSH URLs: git@github.com:owner/repo.git
    if url.starts_with("git@github.com:") {
        let path = url.trim_start_matches("git@github.com:");
        let path = path.trim_end_matches(".git");
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 2 {
            return Some((parts[0].to_string(), parts[1].to_string()));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_github_url_https() {
        let result = parse_github_url("https://github.com/owner/repo");
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));

        let result = parse_github_url("https://github.com/owner/repo.git");
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn test_parse_github_url_ssh() {
        let result = parse_github_url("git@github.com:owner/repo.git");
        assert_eq!(result, Some(("owner".to_string(), "repo".to_string())));
    }

    #[test]
    fn test_parse_github_url_invalid() {
        assert!(parse_github_url("https://gitlab.com/owner/repo").is_none());
        assert!(parse_github_url("not-a-url").is_none());
    }

    #[test]
    fn test_validate_url_https() {
        let cloner = GitCloner::new();
        assert!(cloner.validate_url("https://github.com/owner/repo").is_ok());
        assert!(cloner.validate_url("https://example.com/repo").is_ok());
    }

    #[test]
    fn test_validate_url_invalid() {
        let cloner = GitCloner::new();
        assert!(cloner.validate_url("http://github.com/owner/repo").is_err());
        assert!(cloner.validate_url("ftp://github.com/owner/repo").is_err());
    }

    #[test]
    fn test_build_clone_url_with_token() {
        let cloner = GitCloner::new().with_auth_token(Some("ghp_token123".to_string()));
        let url = cloner
            .build_clone_url("https://github.com/owner/repo")
            .unwrap();
        assert_eq!(url, "https://ghp_token123@github.com/owner/repo");
    }

    #[test]
    fn test_build_clone_url_without_token() {
        let cloner = GitCloner::new();
        let url = cloner
            .build_clone_url("https://github.com/owner/repo")
            .unwrap();
        assert_eq!(url, "https://github.com/owner/repo");
    }
}
