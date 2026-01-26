use thiserror::Error;

/// Errors related to remote repository scanning
#[derive(Debug, Error)]
pub enum RemoteError {
    /// Git clone operation failed
    #[error("Git clone failed for {url}: {message}")]
    CloneFailed { url: String, message: String },

    /// Invalid repository URL format
    #[error("Invalid repository URL: {0}")]
    InvalidUrl(String),

    /// Repository not found (404)
    #[error("Repository not found: {0}")]
    NotFound(String),

    /// Authentication required for private repository
    #[error("Authentication required for private repository: {0}")]
    AuthRequired(String),

    /// GitHub API rate limit exceeded
    #[error("GitHub rate limit exceeded, retry after {reset_at}")]
    RateLimitExceeded { reset_at: String },

    /// Network/IO error
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    /// HTTP request error
    #[error("HTTP error {status}: {message}")]
    Http { status: u16, message: String },

    /// Failed to parse awesome-claude-code README
    #[error("Failed to parse awesome-claude-code: {0}")]
    ParseError(String),

    /// Temporary directory creation failed
    #[error("Temporary directory error: {0}")]
    TempDir(String),

    /// Git command not found
    #[error("Git command not found. Please install git.")]
    GitNotFound,

    /// Clone timeout exceeded
    #[error("Clone timeout exceeded for {url} (timeout: {timeout_secs}s)")]
    CloneTimeout { url: String, timeout_secs: u64 },

    /// Repository too large
    #[error("Repository too large: {url} (size: {size_mb}MB, limit: {limit_mb}MB)")]
    RepositoryTooLarge {
        url: String,
        size_mb: u64,
        limit_mb: u64,
    },
}

impl RemoteError {
    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            RemoteError::RateLimitExceeded { .. }
                | RemoteError::Network(_)
                | RemoteError::CloneTimeout { .. }
        )
    }

    /// Check if error is due to authentication issues
    pub fn is_auth_error(&self) -> bool {
        matches!(self, RemoteError::AuthRequired(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clone_failed_error() {
        let err = RemoteError::CloneFailed {
            url: "https://github.com/user/repo".to_string(),
            message: "Connection refused".to_string(),
        };
        assert!(err.to_string().contains("github.com/user/repo"));
        assert!(err.to_string().contains("Connection refused"));
    }

    #[test]
    fn test_is_retryable() {
        assert!(
            RemoteError::RateLimitExceeded {
                reset_at: "2026-01-25T12:00:00Z".to_string()
            }
            .is_retryable()
        );

        assert!(
            RemoteError::CloneTimeout {
                url: "https://github.com/user/repo".to_string(),
                timeout_secs: 60
            }
            .is_retryable()
        );

        assert!(!RemoteError::InvalidUrl("bad".to_string()).is_retryable());
        assert!(!RemoteError::NotFound("repo".to_string()).is_retryable());
    }

    #[test]
    fn test_is_auth_error() {
        assert!(
            RemoteError::AuthRequired("https://github.com/private/repo".to_string())
                .is_auth_error()
        );
        assert!(!RemoteError::NotFound("repo".to_string()).is_auth_error());
    }
}
