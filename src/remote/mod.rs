//! Remote repository scanning module
//!
//! This module provides functionality to scan remote Git repositories
//! for security vulnerabilities in Claude Code configurations.
//!
//! # Features
//!
//! - Clone remote repositories with security measures (shallow clone, hooks disabled)
//! - Support for GitHub authentication (token-based)
//! - Parse awesome-claude-code repository list
//! - Batch scanning with parallel clones
//!
//! # Security Measures
//!
//! - All clones are shallow (depth=1) to minimize attack surface
//! - Git hooks are disabled during clone to prevent code execution
//! - Temporary directories are automatically cleaned up
//! - Authentication tokens are not logged or exposed

pub mod clone;
pub mod error;

pub use clone::{ClonedRepo, GitCloner, parse_github_url};
pub use error::RemoteError;

/// Default clone timeout in seconds
pub const DEFAULT_CLONE_TIMEOUT_SECS: u64 = 300;

/// Default maximum parallel clones
pub const DEFAULT_PARALLEL_CLONES: usize = 4;

/// Default rate limit retry max attempts
pub const DEFAULT_RATE_LIMIT_RETRIES: u32 = 5;

/// awesome-claude-code repository URL
pub const AWESOME_CLAUDE_CODE_URL: &str = "https://github.com/anthropics/awesome-claude-code";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_CLONE_TIMEOUT_SECS, 300);
        assert_eq!(DEFAULT_PARALLEL_CLONES, 4);
        assert!(AWESOME_CLAUDE_CODE_URL.contains("github.com"));
    }
}
