# Error Module

Unified error handling system for cc-audit.

## Overview

This module provides a comprehensive error handling system with:
- `CcAuditError`: New unified error type with full context preservation
- `AuditError`: Legacy error type for backwards compatibility
- Context types for better error messages

## Files

| File | Description |
|------|-------------|
| `mod.rs` | Module exports, `AuditError` definition |
| `audit.rs` | `CcAuditError` - New unified error type |
| `context.rs` | Context types (`IoOperation`, `ParseFormat`) |

## Key Types

### CcAuditError (Recommended)

New error type with full context:

```rust
pub enum CcAuditError {
    Io { path: PathBuf, operation: IoOperation, source: std::io::Error },
    Parse { path: PathBuf, format: ParseFormat, source: Box<dyn Error> },
    FileNotFound(PathBuf),
    NotADirectory(PathBuf),
    NotAFile(PathBuf),
    InvalidFormat { path: PathBuf, message: String },
    Regex(regex::Error),
    Hook(HookError),
    MalwareDb(MalwareDbError),
    Watch(notify::Error),
    Config(String),
    // ...
}
```

### AuditError (Legacy)

Backwards-compatible error type:

```rust
pub enum AuditError {
    FileNotFound(String),
    ReadError { path: String, source: std::io::Error },
    YamlParseError { path: String, source: serde_yaml::Error },
    InvalidSkillFormat(String),
    RegexError(regex::Error),
    NotADirectory(String),
    JsonError(serde_json::Error),
    ParseError { path: String, message: String },
    Hook(HookError),
    MalwareDb(MalwareDbError),
    Watch(notify::Error),
    Config(String),
}
```

### Context Types

```rust
pub enum IoOperation {
    Read,
    Write,
    Create,
    Delete,
    Open,
}

pub enum ParseFormat {
    Yaml,
    Json,
    Toml,
    Markdown,
}
```

## Result Type Aliases

```rust
// Legacy result type
pub type Result<T> = std::result::Result<T, AuditError>;

// New result type
pub type CcResult<T> = std::result::Result<T, CcAuditError>;
```

## Migration Guide

For new code, prefer `CcAuditError`:

```rust
// Old style
fn old_function() -> Result<Data> {
    Err(AuditError::FileNotFound(path.to_string()))
}

// New style (recommended)
fn new_function() -> CcResult<Data> {
    Err(CcAuditError::FileNotFound(path.to_path_buf()))
}
```

## Error Conversion

`CcAuditError` can be converted to `AuditError` for backwards compatibility:

```rust
let cc_err: CcAuditError = ...;
let audit_err: AuditError = cc_err.into();
```
