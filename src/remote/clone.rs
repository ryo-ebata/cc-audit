use super::error::RemoteError;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::time::Duration;
use tempfile::{NamedTempFile, TempDir};

const REPOSITORY_GIT_ENV: &[&str] = &[
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_DIR",
    "GIT_GRAFT_FILE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
];

fn command_without_repository_git_env(program: &str) -> Command {
    let mut command = Command::new(program);
    for (key, _) in std::env::vars_os() {
        let is_repository_git_env = key.to_str().is_some_and(|key| {
            let normalized = if cfg!(windows) {
                key.to_ascii_uppercase()
            } else {
                key.to_string()
            };
            REPOSITORY_GIT_ENV.contains(&normalized.as_str())
                || normalized.starts_with("GIT_CONFIG_KEY_")
                || normalized.starts_with("GIT_CONFIG_VALUE_")
        });
        if is_repository_git_env {
            command.env_remove(key);
        }
    }
    command
}

static TOKEN_URL_PATTERN: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"https://[^@\s]+@").expect("TOKEN_URL_PATTERN is a valid regex literal")
});

static BEARER_PATTERN: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"Bearer\s+\S+").expect("BEARER_PATTERN is a valid regex literal")
});

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
        sanitized = TOKEN_URL_PATTERN
            .replace_all(&sanitized, "https://[REDACTED]@")
            .to_string();

        // Also redact Bearer tokens
        sanitized = BEARER_PATTERN
            .replace_all(&sanitized, "Bearer [REDACTED]")
            .to_string();

        sanitized
    }

    /// Return the total size of a checkout, including its `.git` directory.
    fn repository_size_bytes(path: &Path) -> Result<u64, std::io::Error> {
        let mut size: u64 = 0;
        for entry in walkdir::WalkDir::new(path) {
            let entry = entry.map_err(|e| {
                let message = e.to_string();
                e.into_io_error()
                    .unwrap_or_else(|| std::io::Error::other(message))
            })?;
            if entry.file_type().is_file() {
                size = size.saturating_add(entry.metadata()?.len());
            }
        }
        Ok(size)
    }

    /// Enforce the configured repository size limit. A zero limit is unlimited.
    fn check_repository_size(&self, url: &str, path: &Path) -> Result<(), RemoteError> {
        if self.max_size_mb == 0 || !path.exists() {
            return Ok(());
        }

        let size_bytes =
            Self::repository_size_bytes(path).map_err(|e| RemoteError::CloneFailed {
                url: url.to_string(),
                message: self.sanitize_error_message(&e.to_string()),
            })?;
        let limit_bytes = self.max_size_mb.saturating_mul(1024 * 1024);
        if size_bytes > limit_bytes {
            let size_mb = size_bytes / (1024 * 1024) + u64::from(size_bytes % (1024 * 1024) != 0);
            return Err(RemoteError::RepositoryTooLarge {
                url: url.to_string(),
                size_mb,
                limit_mb: self.max_size_mb,
            });
        }

        Ok(())
    }

    /// Execute git clone command with security measures and timeout.
    fn execute_clone(&self, url: &str, path: &Path, git_ref: &str) -> Result<(), RemoteError> {
        // Create askpass script for secure token handling
        let askpass_script = self.create_askpass_script()?;

        // Build the git clone command with security measures
        let mut cmd = command_without_repository_git_env("git");

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
            if let Err(error) = self.check_repository_size(url, path) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }

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

                    self.check_repository_size(url, path)?;
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
        let output = command_without_repository_git_env("git")
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

    fn run_git(args: &[&str], current_dir: &Path) -> std::process::Output {
        let mut command = Command::new("git");
        command
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("GIT_CONFIG_NOSYSTEM", "1");
        for variable in ["SYSTEMROOT", "TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(variable) {
                command.env(variable, value);
            }
        }
        command
            .args(args)
            .current_dir(current_dir)
            .output()
            .unwrap()
    }

    fn assert_git_success(output: &std::process::Output, operation: &str) {
        assert!(
            output.status.success(),
            "{operation} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_stdout(args: &[&str], current_dir: &Path, operation: &str) -> String {
        let output = run_git(args, current_dir);
        assert_git_success(&output, operation);
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

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
    fn test_clone_isolates_repository_git_environment() {
        if std::env::var_os("CC_AUDIT_REMOTE_CLONE_CHILD").is_some() {
            let bare_repo = std::env::var_os("CC_AUDIT_REMOTE_BARE_REPO").unwrap();
            let clone_path = PathBuf::from(std::env::var_os("CC_AUDIT_REMOTE_CLONE_PATH").unwrap());
            let expected_sha = std::env::var("CC_AUDIT_REMOTE_EXPECTED_SHA").unwrap();
            let config_mode = std::env::var("CC_AUDIT_REMOTE_CONFIG_MODE").unwrap();

            let cloner = GitCloner::new();
            cloner
                .execute_clone(
                    &format!("file://{}", PathBuf::from(bare_repo).display()),
                    &clone_path,
                    "main",
                )
                .unwrap();
            assert_eq!(cloner.get_commit_sha(&clone_path).unwrap(), expected_sha);
            let global = command_without_repository_git_env("git")
                .args(["config", "--global", "--get", "cc-audit.test-global"])
                .current_dir(&clone_path)
                .output()
                .unwrap();
            assert_git_success(&global, "global config lookup");
            assert_eq!(
                String::from_utf8_lossy(&global.stdout).trim(),
                "global-value"
            );
            let system = command_without_repository_git_env("git")
                .args(["config", "--get", "cc-audit.test-system"])
                .current_dir(&clone_path)
                .output()
                .unwrap();
            if config_mode == "nosystem" {
                assert!(
                    !system.status.success(),
                    "GIT_CONFIG_NOSYSTEM was not preserved"
                );
            } else {
                assert_git_success(&system, "system config lookup");
                assert_eq!(
                    String::from_utf8_lossy(&system.stdout).trim(),
                    "system-value"
                );
            }
            return;
        }

        let source = tempfile::tempdir().unwrap();
        let bare = tempfile::tempdir().unwrap();
        let clone = tempfile::tempdir().unwrap();
        let clone_without_system = tempfile::tempdir().unwrap();
        let config = tempfile::tempdir().unwrap();
        let global_config = config.path().join("global");
        let system_config = config.path().join("system");
        std::fs::write(&global_config, "[cc-audit]\n\ttest-global = global-value\n").unwrap();
        std::fs::write(&system_config, "[cc-audit]\n\ttest-system = system-value\n").unwrap();

        assert_git_success(&run_git(&["init", "--quiet"], source.path()), "source init");
        std::fs::write(source.path().join("README.md"), "first commit\n").unwrap();
        assert_git_success(&run_git(&["add", "README.md"], source.path()), "source add");
        assert_git_success(
            &run_git(
                &[
                    "-c",
                    "user.name=cc-audit-test",
                    "-c",
                    "user.email=cc-audit-test@example.invalid",
                    "-c",
                    "commit.gpgSign=false",
                    "commit",
                    "--quiet",
                    "-m",
                    "fixture",
                ],
                source.path(),
            ),
            "source commit",
        );
        let expected_sha = git_stdout(&["rev-parse", "HEAD"], source.path(), "source rev-parse");
        assert_git_success(
            &run_git(&["init", "--bare", "--quiet"], bare.path()),
            "bare init",
        );
        assert_git_success(
            &run_git(
                &["push", bare.path().to_str().unwrap(), "HEAD:main"],
                source.path(),
            ),
            "source push",
        );

        std::fs::write(source.path().join("second.md"), "second commit\n").unwrap();
        assert_git_success(
            &run_git(&["add", "second.md"], source.path()),
            "source add second",
        );
        assert_git_success(
            &run_git(
                &[
                    "-c",
                    "user.name=cc-audit-test",
                    "-c",
                    "user.email=cc-audit-test@example.invalid",
                    "-c",
                    "commit.gpgSign=false",
                    "commit",
                    "--quiet",
                    "-m",
                    "second fixture",
                ],
                source.path(),
            ),
            "source commit second",
        );
        let source_current_sha = git_stdout(
            &["rev-parse", "HEAD"],
            source.path(),
            "source current rev-parse",
        );
        assert_ne!(source_current_sha, expected_sha);

        let snapshot = |path: &Path| match std::fs::read(path) {
            Ok(contents) => Some(contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("failed to snapshot {}: {error}", path.display()),
        };
        let source_config = snapshot(&source.path().join(".git/config"));
        let source_head = snapshot(&source.path().join(".git/HEAD"));
        let source_index = snapshot(&source.path().join(".git/index"));
        let test_binary = std::env::current_exe().unwrap();

        let run_child = |clone_path: &Path, mode: &str, nosystem: bool| {
            let mut child = std::process::Command::new(&test_binary);
            child
                .args([
                    "--exact",
                    "remote::clone::tests::test_clone_isolates_repository_git_environment",
                    "--nocapture",
                ])
                .env("CC_AUDIT_REMOTE_CLONE_CHILD", "1")
                .env("CC_AUDIT_REMOTE_CONFIG_MODE", mode)
                .env("CC_AUDIT_REMOTE_BARE_REPO", bare.path())
                .env("CC_AUDIT_REMOTE_CLONE_PATH", clone_path)
                .env("CC_AUDIT_REMOTE_EXPECTED_SHA", &expected_sha)
                .env("GIT_DIR", source.path().join(".git"))
                .env("GIT_WORK_TREE", clone_path)
                .env("GIT_COMMON_DIR", source.path().join(".git"))
                .env("GIT_CONFIG", source.path().join(".git/config"))
                .env("GIT_CONFIG_COUNT", "1")
                .env("GIT_CONFIG_KEY_0", "core.bare")
                .env("GIT_CONFIG_VALUE_0", "true")
                .env("GIT_CONFIG_GLOBAL", &global_config)
                .env("GIT_CONFIG_SYSTEM", &system_config)
                .env("GIT_INDEX_FILE", source.path().join(".git/index"));
            if nosystem {
                child.env("GIT_CONFIG_NOSYSTEM", "1");
            }
            if cfg!(windows) {
                child
                    .env("Git_Dir", source.path().join(".git"))
                    .env("Git_Work_Tree", clone_path)
                    .env("Git_Common_Dir", source.path().join(".git"))
                    .env("Git_Config", source.path().join(".git/config"))
                    .env("Git_Config_Global", &global_config)
                    .env("Git_Config_Count", "1")
                    .env("Git_Config_Key_0", "core.bare")
                    .env("Git_Config_Value_0", "true")
                    .env("Git_Config_System", &system_config)
                    .env("Git_Index_File", source.path().join(".git/index"));
                if nosystem {
                    child.env("Git_Config_NoSystem", "1");
                }
            }
            let status = child.status().unwrap();
            assert!(status.success(), "isolated clone child test failed");
        };
        run_child(clone.path(), "config", false);
        run_child(clone_without_system.path(), "nosystem", true);

        assert_eq!(snapshot(&source.path().join(".git/config")), source_config);
        assert_eq!(snapshot(&source.path().join(".git/HEAD")), source_head);
        assert_eq!(snapshot(&source.path().join(".git/index")), source_index);
        assert!(clone.path().join(".git").is_dir());
        assert!(clone_without_system.path().join(".git").is_dir());
        assert_eq!(
            git_stdout(&["rev-parse", "HEAD"], clone.path(), "clone rev-parse"),
            expected_sha
        );
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

    #[test]
    fn test_repository_size_limit_allows_below_limit() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::write(temp_dir.path().join("small.txt"), b"small").unwrap();

        let cloner = GitCloner::new().with_max_size(1);
        assert!(
            cloner
                .check_repository_size("https://github.com/owner/repo", temp_dir.path())
                .is_ok()
        );
    }

    #[test]
    fn test_repository_size_limit_detects_above_limit() {
        let temp_dir = tempfile::tempdir().unwrap();
        let large_file = vec![0_u8; 1024 * 1024 + 1];
        std::fs::write(temp_dir.path().join("large.bin"), large_file).unwrap();

        let cloner = GitCloner::new().with_max_size(1);
        let error = cloner
            .check_repository_size("https://github.com/owner/repo", temp_dir.path())
            .unwrap_err();
        assert!(matches!(
            error,
            RemoteError::RepositoryTooLarge { limit_mb: 1, .. }
        ));
    }

    #[test]
    fn test_repository_size_limit_zero_is_unlimited() {
        let temp_dir = tempfile::tempdir().unwrap();
        let large_file = vec![0_u8; 1024 * 1024 + 1];
        std::fs::write(temp_dir.path().join("large.bin"), large_file).unwrap();

        let cloner = GitCloner::new();
        assert!(
            cloner
                .check_repository_size("https://github.com/owner/repo", temp_dir.path())
                .is_ok()
        );
    }
}
