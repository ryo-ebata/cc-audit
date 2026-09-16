# Remote Module

Remote repository scanning functionality.

## Overview

This module provides functionality to scan remote Git repositories for security vulnerabilities in Claude Code configurations.

## Features

- Clone remote repositories with security measures
- Support for GitHub authentication (token-based)
- Parse awesome-claude-code repository list
- Batch scanning with parallel clones

## Security Measures

- **Shallow clones** (depth=1) to minimize attack surface
- **Git hooks disabled** during clone to prevent code execution
- **Temporary directories** automatically cleaned up
- **Authentication tokens** not logged or exposed

## Files

| File | Description |
|------|-------------|
| `mod.rs` | Module exports, constants |
| `clone.rs` | `GitCloner`, `ClonedRepo`, URL parsing |
| `error.rs` | `RemoteError` definitions |

## Constants

```rust
pub const DEFAULT_CLONE_TIMEOUT_SECS: u64 = 300;
pub const DEFAULT_PARALLEL_CLONES: usize = 4;
pub const DEFAULT_RATE_LIMIT_RETRIES: u32 = 5;
pub const AWESOME_CLAUDE_CODE_URL: &str = "https://github.com/anthropics/awesome-claude-code";
```

## Key Types

### GitCloner

```rust
pub struct GitCloner {
    // Configuration fields are private; use the builder methods below.
}

impl GitCloner {
    pub fn new() -> Self;
    pub fn with_auth_token(self, token: Option<String>) -> Self;
    pub fn with_timeout(self, secs: u64) -> Self;
    pub fn with_max_size(self, mb: u64) -> Self;
    pub fn clone(&self, url: &str, git_ref: &str) -> Result<ClonedRepo, RemoteError>;
}
```

### ClonedRepo

```rust
pub struct ClonedRepo {
    pub path: PathBuf,
    pub url: String,
    pub git_ref: String,
    pub commit_sha: Option<String>,
    // The temporary directory handle is private and cleans up on drop.
}

impl ClonedRepo {
    pub fn path(&self) -> &Path;
}
```

### RemoteError

```rust
pub enum RemoteError {
    CloneFailed { url: String, message: String },
    InvalidUrl(String),
    NotFound(String),
    AuthRequired(String),
    RateLimitExceeded { reset_at: String },
    Network(std::io::Error),
    Http { status: u16, message: String },
    ParseError(String),
    TempDir(String),
    GitNotFound,
    CloneTimeout { url: String, timeout_secs: u64 },
    RepositoryTooLarge { url: String, size_mb: u64, limit_mb: u64 },
}
```

### URL Parsing

```rust
pub fn parse_github_url(url: &str) -> Option<(String, String)>;
// Returns (owner, repo) tuple
```

## Usage Example

```rust
use cc_audit::remote::{ClonedRepo, GitCloner, RemoteError};

fn example() -> Result<(), RemoteError> {
// Basic clone
let cloner = GitCloner::new();
let repo: ClonedRepo = cloner.clone("https://github.com/user/repo", "HEAD")?;
let _path = repo.path();

// With authentication
let cloner = GitCloner::new().with_auth_token(Some("ghp_xxx".to_string()));
let repo = cloner.clone("https://github.com/org/private-repo", "HEAD")?;

// Clone specific ref
let repo = cloner.clone("https://github.com/user/repo", "v1.0.0")?;
Ok(())
}
```

## CLI Usage

```bash
# Scan remote repository
cc-audit --remote https://github.com/user/repo

# With specific branch
cc-audit --remote https://github.com/user/repo --git-ref feature-branch

# With authentication
cc-audit --remote https://github.com/org/private-repo --remote-auth $GITHUB_TOKEN

# Parallel scanning
cc-audit --remote-list repos.txt --parallel-clones 8
```

## Batch Scanning

```bash
# Scan list of repositories
cc-audit --remote-list repositories.txt

# Scan awesome-claude-code repositories
cc-audit --awesome-claude-code
```

## Security Considerations

1. **Token Security**: Auth tokens are never logged
2. **Shallow Clones**: Only fetch minimal history
3. **Hook Prevention**: `--config core.hooksPath=/dev/null`
4. **Timeout**: Prevent hanging on slow/malicious repos
5. **Cleanup**: Temp directories removed after scan
