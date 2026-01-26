# Types Module

Type-safe wrapper types for improved compile-time guarantees.

## Overview

This module provides NewType pattern implementations to prevent primitive type misuse and improve API clarity.

## Files

| File | Description |
|------|-------------|
| `mod.rs` | Module exports |
| `newtypes.rs` | NewType wrapper implementations |
| `paths.rs` | Path-related types and validation |

## NewType Pattern

The NewType pattern wraps primitive types to:
- Prevent accidental misuse (mixing up strings)
- Add type-level documentation
- Enable type-specific validation
- Improve API clarity

## Key Types

### newtypes.rs

#### RuleId

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleId(String);

impl RuleId {
    pub fn new(id: impl Into<String>) -> Self;
    pub fn as_str(&self) -> &str;
}
```

#### ServerName

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerName(String);
```

#### GitRef

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRef(String);

impl GitRef {
    pub fn branch(name: &str) -> Self;
    pub fn tag(name: &str) -> Self;
    pub fn commit(sha: &str) -> Self;
}
```

#### AuthToken

```rust
#[derive(Clone)]
pub struct AuthToken(String);

// Debug intentionally hides the value
impl Debug for AuthToken {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("AuthToken(***)")
    }
}
```

#### CommandArgs

```rust
#[derive(Debug, Clone)]
pub struct CommandArgs(Vec<String>);
```

#### FileHash

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHash(String);

impl FileHash {
    pub fn sha256(content: &[u8]) -> Self;
}
```

#### CompiledPattern

```rust
#[derive(Clone)]
pub struct CompiledPattern(Regex);

impl CompiledPattern {
    pub fn new(pattern: &str) -> Result<Self, regex::Error>;
    pub fn is_match(&self, text: &str) -> bool;
}
```

### paths.rs

#### ScanTarget

```rust
pub struct ScanTarget {
    path: PathBuf,
    validated: bool,
}

impl ScanTarget {
    pub fn new(path: PathBuf) -> Result<Self, PathValidationError>;
    pub fn path(&self) -> &Path;
}
```

#### PathValidationError

```rust
pub enum PathValidationError {
    NotFound(PathBuf),
    NotAFile(PathBuf),
    NotADirectory(PathBuf),
    PermissionDenied(PathBuf),
}
```

## Usage Example

```rust
use cc_audit::types::{RuleId, ServerName, AuthToken, GitRef};

// Rule IDs
let rule_id = RuleId::new("EX-001");
assert_eq!(rule_id.as_str(), "EX-001");

// Server names
let server = ServerName::new("mcp-server");

// Git references
let branch = GitRef::branch("main");
let tag = GitRef::tag("v1.0.0");
let commit = GitRef::commit("abc123");

// Auth tokens (value hidden in debug output)
let token = AuthToken::new("ghp_xxx");
println!("{:?}", token); // AuthToken(***)
```

## Benefits

### Before (primitive types)
```rust
fn scan(path: &str, rule: &str, token: &str) -> Result<()> {
    // Easy to mix up parameters!
}
```

### After (NewTypes)
```rust
fn scan(path: &ScanTarget, rule: &RuleId, token: &AuthToken) -> Result<()> {
    // Compiler prevents parameter mixup
}
```
