---
name: rust-best-practices
description: Rust coding best practices for cc-audit development. Use when writing new Rust code, reviewing code, or refactoring. Covers error handling, safety, performance, and idiomatic patterns.
---

# Rust Best Practices for cc-audit

## Error Handling

### Prefer `?` Over `unwrap()`

```rust
// BAD: Panics on error
let content = fs::read_to_string(path).unwrap();

// GOOD: Propagates error
let content = fs::read_to_string(path)?;

// GOOD: With context
let content = fs::read_to_string(path)
    .map_err(|e| ScanError::IoError { path: path.into(), source: e })?;
```

### Use `thiserror` for Custom Errors

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("failed to read file: {path}")]
    IoError {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid pattern: {0}")]
    InvalidPattern(String),
}
```

### When `unwrap()` is Acceptable

- In tests
- After validation guarantees success
- With `unreachable!()` comment explaining why

```rust
// OK: We just checked is_some()
if value.is_some() {
    let v = value.unwrap(); // Known safe
}

// BETTER: Use if-let or match
if let Some(v) = value {
    // use v
}
```

## Option and Result Patterns

### Prefer Combinators

```rust
// BAD: Verbose match
let result = match opt {
    Some(v) => Some(v.to_uppercase()),
    None => None,
};

// GOOD: Use map
let result = opt.map(|v| v.to_uppercase());

// GOOD: Chain combinators
let result = opt
    .filter(|s| !s.is_empty())
    .map(|s| s.trim())
    .unwrap_or_default();
```

### `ok_or` vs `ok_or_else`

```rust
// Use ok_or for cheap errors
let value = opt.ok_or(MyError::NotFound)?;

// Use ok_or_else for expensive error construction
let value = opt.ok_or_else(|| MyError::detailed(context))?;
```

## Ownership and Borrowing

### Prefer Borrowing Over Cloning

```rust
// BAD: Unnecessary clone
fn process(data: String) { /* ... */ }
process(my_string.clone());

// GOOD: Borrow if not consuming
fn process(data: &str) { /* ... */ }
process(&my_string);
```

### Use `Cow` for Flexible Ownership

```rust
use std::borrow::Cow;

fn normalize_path(path: &str) -> Cow<'_, str> {
    if path.contains('\\') {
        Cow::Owned(path.replace('\\', "/"))
    } else {
        Cow::Borrowed(path)
    }
}
```

## String Handling

### `&str` vs `String`

```rust
// Parameters: prefer &str
fn scan_content(content: &str) -> Result<Findings, Error>

// Return owned: use String or impl Into<String>
fn get_message(&self) -> String

// Accept both: use impl AsRef<str>
fn log_message(msg: impl AsRef<str>)
```

### Efficient String Building

```rust
// BAD: Multiple allocations
let s = "prefix".to_string() + &middle + "suffix";

// GOOD: Use format! or String::with_capacity
let s = format!("prefix{}suffix", middle);

// GOOD: For complex building
let mut s = String::with_capacity(estimated_len);
s.push_str("prefix");
s.push_str(&middle);
s.push_str("suffix");
```

## Collections

### Prefer Iterators Over Loops

```rust
// BAD: Manual loop
let mut results = Vec::new();
for item in items {
    if item.is_valid() {
        results.push(item.transform());
    }
}

// GOOD: Iterator chain
let results: Vec<_> = items
    .iter()
    .filter(|item| item.is_valid())
    .map(|item| item.transform())
    .collect();
```

### Pre-allocate When Size is Known

```rust
// BAD: Multiple reallocations
let mut vec = Vec::new();
for i in 0..1000 {
    vec.push(i);
}

// GOOD: Pre-allocate
let mut vec = Vec::with_capacity(1000);
for i in 0..1000 {
    vec.push(i);
}

// BEST: Use collect
let vec: Vec<_> = (0..1000).collect();
```

## Structs and Enums

### Use Builder Pattern for Complex Structs

```rust
pub struct ScanConfig {
    path: PathBuf,
    recursive: bool,
    max_depth: Option<usize>,
}

impl ScanConfig {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            recursive: true,
            max_depth: None,
        }
    }

    pub fn recursive(mut self, value: bool) -> Self {
        self.recursive = value;
        self
    }

    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = Some(depth);
        self
    }
}

// Usage
let config = ScanConfig::new("./src")
    .recursive(true)
    .max_depth(5);
```

### Derive Common Traits

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleId(String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}
```

## Traits

### Use Trait Objects Sparingly

```rust
// Prefer generics for performance
fn scan<S: Scanner>(scanner: &S, content: &str) -> Result<Findings>

// Use trait objects for heterogeneous collections
fn scan_all(scanners: &[Box<dyn Scanner>], content: &str) -> Result<Findings>
```

### Implement Standard Traits

```rust
// Display for user-facing output
impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.rule_id, self.message)
    }
}

// Default for sensible defaults
impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            recursive: true,
            max_depth: None,
            // ...
        }
    }
}
```

## Performance

### Avoid Unnecessary Allocations

```rust
// BAD: Allocates on every call
fn get_prefix() -> String {
    "PREFIX_".to_string()
}

// GOOD: Return static reference
fn get_prefix() -> &'static str {
    "PREFIX_"
}
```

### Use `once_cell` for Lazy Static

```rust
use once_cell::sync::Lazy;
use regex::Regex;

static PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"malicious_pattern").expect("valid regex")
});
```

## Security (Critical for cc-audit)

### Validate All External Input

```rust
pub fn scan_path(path: &Path) -> Result<(), ScanError> {
    // Validate path exists
    if !path.exists() {
        return Err(ScanError::PathNotFound(path.into()));
    }

    // Prevent path traversal
    let canonical = path.canonicalize()?;
    if !canonical.starts_with(&allowed_root) {
        return Err(ScanError::PathTraversal(path.into()));
    }

    // Continue with scan...
    Ok(())
}
```

### Avoid Unsafe Unless Absolutely Necessary

```rust
// NEVER do this without extremely good reason
unsafe {
    // dangerous code
}

// If unavoidable, document extensively
/// # Safety
/// - `ptr` must be valid and aligned
/// - `ptr` must point to initialized memory
unsafe fn read_raw(ptr: *const u8) -> u8 {
    *ptr
}
```

## Documentation

### Doc Comments for Public Items

```rust
/// Scans content for security vulnerabilities.
///
/// # Arguments
///
/// * `content` - The file content to scan
/// * `path` - The file path (for error reporting)
///
/// # Returns
///
/// A `ScanResult` containing any findings, or an error.
///
/// # Examples
///
/// ```
/// let result = scanner.scan("content", Path::new("test.js"))?;
/// assert!(result.findings.is_empty());
/// ```
pub fn scan(&self, content: &str, path: &Path) -> Result<ScanResult, ScanError>
```

## Quick Reference

| Pattern | Bad | Good |
|---------|-----|------|
| Error handling | `.unwrap()` | `?` with context |
| String params | `String` | `&str` or `impl AsRef<str>` |
| Collections | Manual loops | Iterator chains |
| Optionals | Nested `if let` | Combinators (`map`, `and_then`) |
| Allocation | Repeated small allocs | Pre-allocate or `Cow` |
| Cloning | Clone everything | Borrow when possible |
