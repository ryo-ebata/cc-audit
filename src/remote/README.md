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
    auth_token: Option<AuthToken>,
    timeout: Duration,
}

impl GitCloner {
    pub fn new() -> Self;
    pub fn with_token(token: AuthToken) -> Self;
    pub fn clone(&self, url: &str) -> Result<ClonedRepo, RemoteError>;
    pub fn clone_with_ref(&self, url: &str, git_ref: &GitRef) -> Result<ClonedRepo, RemoteError>;
}
```

### ClonedRepo

```rust
pub struct ClonedRepo {
    path: PathBuf,
    temp_dir: TempDir,  // Auto-cleanup on drop
}

impl ClonedRepo {
    pub fn path(&self) -> &Path;
}
```

### RemoteError

```rust
pub enum RemoteError {
    CloneFailed { url: String, message: String },
    Timeout { url: String },
    AuthenticationFailed { url: String },
    RateLimited { url: String, retry_after: Option<Duration> },
    InvalidUrl(String),
    IoError(std::io::Error),
}
```

### URL Parsing

```rust
pub fn parse_github_url(url: &str) -> Option<(String, String)>;
// Returns (owner, repo) tuple
```

## Usage Example

```rust
use cc_audit::remote::{GitCloner, ClonedRepo, RemoteError};

// Basic clone
let cloner = GitCloner::new();
let repo = cloner.clone("https://github.com/user/repo")?;
let result = scan(repo.path());

// With authentication
let cloner = GitCloner::with_token(AuthToken::new("ghp_xxx"));
let repo = cloner.clone("https://github.com/org/private-repo")?;

// Clone specific ref
let repo = cloner.clone_with_ref(
    "https://github.com/user/repo",
    &GitRef::tag("v1.0.0")
)?;
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
