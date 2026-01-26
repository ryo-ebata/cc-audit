use super::error::RemoteError;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};

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
    /// - Token is passed via GIT_ASKPASS (not embedded in URL)
    /// - Clone has configurable timeout
    pub fn clone(&self, url: &str, git_ref: &str) -> Result<ClonedRepo, RemoteError> {
        // Validate URL format
        self.validate_url(url)?;

        // Check if git is available
        self.check_git_available()?;

        // Create temporary directory
        let temp_dir = TempDir::new().map_err(|e| RemoteError::TempDir(e.to_string()))?;
        let repo_path = temp_dir.path().to_path_buf();

        // Execute git clone with security measures (token via env, not URL)
        self.execute_clone(url, &repo_path, git_ref)?;

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

    /// Create a temporary GIT_ASKPASS script that returns the token.
    /// This is more secure than embedding the token in the URL because:
    /// - Token is not visible in process list (ps aux)
    /// - Token is not logged in git error messages
    /// - Script is automatically cleaned up
    fn create_askpass_script(&self) -> Result<Option<NamedTempFile>, RemoteError> {
        let Some(ref token) = self.auth_token else {
            return Ok(None);
        };

        let mut script = NamedTempFile::new().map_err(|e| RemoteError::TempDir(e.to_string()))?;

        // Write a shell script that outputs the token
        // The script receives the prompt as an argument but we ignore it
        writeln!(script, "#!/bin/sh").map_err(|e| RemoteError::TempDir(e.to_string()))?;
        writeln!(script, "echo '{}'", token.replace('\'', "'\"'\"'"))
            .map_err(|e| RemoteError::TempDir(e.to_string()))?;

        // Make the script executable (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = script.path();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| RemoteError::TempDir(e.to_string()))?;
        }

        Ok(Some(script))
    }

    /// Sanitize error messages to remove any potential token leakage.
    fn sanitize_error_message(&self, message: &str) -> String {
        let mut sanitized = message.to_string();

        // Remove any token-like patterns from error messages
        if let Some(ref token) = self.auth_token {
            sanitized = sanitized.replace(token, "[REDACTED]");
        }

        // Remove patterns that look like tokens embedded in URLs
        // Pattern: https://TOKEN@github.com or similar
        let token_pattern = regex::Regex::new(r"https://[^@\s]+@")
            .unwrap_or_else(|_| regex::Regex::new("^$").unwrap());
        sanitized = token_pattern
            .replace_all(&sanitized, "https://[REDACTED]@")
            .to_string();

        // Also redact Bearer tokens
        let bearer_pattern =
            regex::Regex::new(r"Bearer\s+\S+").unwrap_or_else(|_| regex::Regex::new("^$").unwrap());
        sanitized = bearer_pattern
            .replace_all(&sanitized, "Bearer [REDACTED]")
            .to_string();

        sanitized
    }

    /// Execute git clone command with security measures and timeout.
    fn execute_clone(&self, url: &str, path: &Path, git_ref: &str) -> Result<(), RemoteError> {
        // Create askpass script for secure token handling
        let askpass_script = self.create_askpass_script()?;

        // Build the git clone command with security measures
        let mut cmd = Command::new("git");

        // Disable hooks for security
        cmd.env("GIT_TEMPLATE_DIR", "");

        // Set up authentication via GIT_ASKPASS if we have a token
        if let Some(ref script) = askpass_script {
            cmd.env("GIT_ASKPASS", script.path());
            // Disable terminal prompts to force use of ASKPASS
            cmd.env("GIT_TERMINAL_PROMPT", "0");
        }

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

        // Execute with timeout using a child process
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().map_err(|e| RemoteError::CloneFailed {
            url: url.to_string(),
            message: self.sanitize_error_message(&e.to_string()),
        })?;

        // Wait with timeout
        let timeout = Duration::from_secs(self.timeout_secs);
        let start = std::time::Instant::now();

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Process finished
                    let output =
                        child
                            .wait_with_output()
                            .map_err(|e| RemoteError::CloneFailed {
                                url: url.to_string(),
                                message: self.sanitize_error_message(&e.to_string()),
                            })?;

                    if !status.success() {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        let sanitized_stderr = self.sanitize_error_message(&stderr);

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
                            message: sanitized_stderr,
                        });
                    }

                    return Ok(());
                }
                Ok(None) => {
                    // Process still running, check timeout
                    if start.elapsed() > timeout {
                        // Kill the process
                        let _ = child.kill();
                        return Err(RemoteError::CloneFailed {
                            url: url.to_string(),
                            message: format!("Clone timed out after {} seconds", self.timeout_secs),
                        });
                    }
                    // Sleep briefly before checking again
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    return Err(RemoteError::CloneFailed {
                        url: url.to_string(),
                        message: self.sanitize_error_message(&e.to_string()),
                    });
                }
            }
        }
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
    fn test_sanitize_error_message() {
        let cloner = GitCloner::new().with_auth_token(Some("ghp_secret123".to_string()));

        // Test direct token replacement
        let msg = "failed with ghp_secret123 in message";
        assert_eq!(
            cloner.sanitize_error_message(msg),
            "failed with [REDACTED] in message"
        );

        // Test URL token pattern
        let msg = "failed: https://token123@github.com/repo";
        assert!(cloner.sanitize_error_message(msg).contains("[REDACTED]"));
        assert!(!cloner.sanitize_error_message(msg).contains("token123"));
    }

    #[test]
    fn test_sanitize_error_message_no_token() {
        let cloner = GitCloner::new();

        // Without token, message should still sanitize URL patterns
        let msg = "failed: https://sometoken@github.com/repo";
        let sanitized = cloner.sanitize_error_message(msg);
        assert!(sanitized.contains("[REDACTED]"));
    }

    #[test]
    fn test_sanitize_bearer_token() {
        let cloner = GitCloner::new();

        let msg = "Authorization: Bearer ghp_secret123456";
        let sanitized = cloner.sanitize_error_message(msg);
        assert!(!sanitized.contains("ghp_secret123456"));
        assert!(sanitized.contains("[REDACTED]"));
    }

    #[cfg(unix)]
    #[test]
    fn test_create_askpass_script() {
        let cloner = GitCloner::new().with_auth_token(Some("test_token".to_string()));
        let script = cloner.create_askpass_script().unwrap();

        assert!(script.is_some());
        let script = script.unwrap();

        // Verify script exists and is executable
        let path = script.path();
        assert!(path.exists());

        let metadata = std::fs::metadata(path).unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(metadata.permissions().mode() & 0o700, 0o700);
    }

    #[test]
    fn test_create_askpass_script_no_token() {
        let cloner = GitCloner::new();
        let script = cloner.create_askpass_script().unwrap();
        assert!(script.is_none());
    }

    #[test]
    fn test_cloner_with_timeout() {
        let cloner = GitCloner::new().with_timeout(60);
        assert_eq!(cloner.timeout_secs, 60);
    }

    #[test]
    fn test_cloner_with_max_size() {
        let cloner = GitCloner::new().with_max_size(100);
        assert_eq!(cloner.max_size_mb, 100);
    }
}
