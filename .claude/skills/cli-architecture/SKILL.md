---
name: cli-architecture
description: CLI tool design and architecture best practices inspired by Biome, OxcLint, and other modern Rust tools. Use when designing new features, refactoring architecture, or reviewing structural decisions.
---

# CLI Architecture Best Practices

Reference tools: **Biome**, **OxcLint**, **ripgrep**, **fd**

## Core Design Principles

### 1. Zero-Config by Default

```
User experience priority:
1. Works out of the box with sensible defaults
2. Configuration is optional enhancement
3. Explicit overrides when needed
```

```rust
// BAD: Requires configuration to work
let config = Config::load("config.yaml")?; // Fails if missing

// GOOD: Sensible defaults, optional config
let config = Config::load_or_default("config.yaml");
```

### 2. Modular Composability (Oxc Pattern)

Each component works independently or together:

```
┌─────────────────────────────────────────────┐
│                    CLI                       │
├─────────────────────────────────────────────┤
│  ┌─────────┐ ┌─────────┐ ┌─────────────┐   │
│  │ Scanner │ │ Reporter│ │ Config      │   │
│  └────┬────┘ └────┬────┘ └──────┬──────┘   │
│       │           │             │           │
├───────┴───────────┴─────────────┴───────────┤
│              Core Engine                     │
├─────────────────────────────────────────────┤
│  ┌────────┐ ┌────────┐ ┌────────┐          │
│  │ Parser │ │ Rules  │ │ Types  │          │
│  └────────┘ └────────┘ └────────┘          │
└─────────────────────────────────────────────┘
```

### 3. Performance First

- **Parallel by default**: Use `rayon` for file processing
- **Streaming output**: Don't buffer entire results
- **Lazy evaluation**: Load resources on demand
- **Memory efficiency**: Process files without loading all into memory

## Crate Organization (Workspace Pattern)

### Recommended Structure

```
my-tool/
├── Cargo.toml              # Workspace root
├── crates/
│   ├── my_tool/            # Main library (pub API)
│   ├── my_tool_cli/        # CLI binary (thin wrapper)
│   ├── my_tool_parser/     # Parser implementation
│   ├── my_tool_rules/      # Rule definitions
│   ├── my_tool_config/     # Configuration handling
│   └── my_tool_reporter/   # Output formatters
├── xtask/                  # Development tasks
└── tests/                  # Integration tests
```

### Workspace Cargo.toml

```toml
[workspace]
resolver = "2"
members = ["crates/*", "xtask"]

[workspace.package]
version = "1.0.0"
edition = "2024"
rust-version = "1.85"
license = "MIT"
repository = "https://github.com/org/my-tool"

[workspace.dependencies]
# Share versions across crates
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
thiserror = "2"
rayon = "1"
```

### Crate Dependencies (Layered)

```
cli → lib → [parser, rules, config, reporter]
              ↓
           core types
```

```toml
# crates/my_tool_cli/Cargo.toml
[dependencies]
my_tool = { workspace = true }
clap = { workspace = true }

# crates/my_tool/Cargo.toml (main lib)
[dependencies]
my_tool_parser = { workspace = true }
my_tool_rules = { workspace = true }
my_tool_config = { workspace = true }
my_tool_reporter = { workspace = true }
```

## CLI Design (clap)

### Subcommand Pattern

```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "my-tool")]
#[command(version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Files or directories to process
    #[arg(default_value = ".")]
    pub paths: Vec<PathBuf>,

    /// Output format
    #[arg(long, short, default_value = "text")]
    pub format: OutputFormat,

    /// Configuration file
    #[arg(long, short)]
    pub config: Option<PathBuf>,

    /// Verbose output
    #[arg(long, short, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Check files (default)
    Check(CheckArgs),
    /// Initialize configuration
    Init(InitArgs),
    /// Explain a rule
    Explain { rule: String },
}
```

### Exit Codes (Consistent Convention)

```rust
pub enum ExitCode {
    Success = 0,
    LintError = 1,      // Findings detected
    ConfigError = 2,    // Invalid configuration
    IoError = 3,        // File system error
    InternalError = 101, // Bug in tool
}

fn main() -> ExitCode {
    match run() {
        Ok(result) if result.has_errors() => ExitCode::LintError,
        Ok(_) => ExitCode::Success,
        Err(e) => e.into(),
    }
}
```

## Configuration System (Biome Pattern)

### Layered Configuration

```
Priority (highest to lowest):
1. CLI arguments
2. Environment variables
3. Project config (.my-tool.yaml)
4. User config (~/.config/my-tool/config.yaml)
5. Default values
```

```rust
pub struct Config {
    // Merged from all sources
}

impl Config {
    pub fn load(cli: &Cli) -> Result<Self, ConfigError> {
        let mut config = Self::default();

        // Layer 5: Defaults (already set)

        // Layer 4: User config
        if let Some(user_config) = Self::load_user_config()? {
            config.merge(user_config);
        }

        // Layer 3: Project config
        if let Some(project_config) = Self::find_project_config()? {
            config.merge(project_config);
        }

        // Layer 2: Environment variables
        config.apply_env();

        // Layer 1: CLI arguments (highest priority)
        config.apply_cli(cli);

        Ok(config)
    }
}
```

### Config File Format

```yaml
# .my-tool.yaml
# Supports YAML, JSON, TOML

# Rule configuration
rules:
  enabled:
    - "EX-*"      # Enable all exfiltration rules
    - "PE-001"    # Enable specific rule
  disabled:
    - "OB-001"    # Disable specific rule
  severity:
    warn: ["PI-001", "PI-002"]

# Ignore patterns
ignore:
  patterns:
    - "tests/fixtures/**"
    - "*.generated.*"

# Output configuration
output:
  format: "text"  # text, json, sarif
  color: "auto"   # auto, always, never
```

## Output Formatting (Reporter Pattern)

### Trait-based Reporters

```rust
pub trait Reporter: Send + Sync {
    fn report_finding(&mut self, finding: &Finding) -> io::Result<()>;
    fn report_summary(&mut self, summary: &Summary) -> io::Result<()>;
    fn finish(self: Box<Self>) -> io::Result<()>;
}

pub struct TextReporter { /* ... */ }
pub struct JsonReporter { /* ... */ }
pub struct SarifReporter { /* ... */ }

impl Reporter for TextReporter {
    fn report_finding(&mut self, finding: &Finding) -> io::Result<()> {
        writeln!(
            self.writer,
            "{}:{}:{} {} {}",
            finding.path.display(),
            finding.line,
            finding.column,
            finding.severity,
            finding.message
        )
    }
}
```

### Streaming vs Buffered

```rust
// GOOD: Stream findings as they're found
for file in files {
    let findings = scanner.scan(&file)?;
    for finding in findings {
        reporter.report_finding(&finding)?;
    }
}
reporter.report_summary(&summary)?;

// AVOID: Buffer everything (memory issues on large codebases)
let all_findings: Vec<_> = files
    .iter()
    .flat_map(|f| scanner.scan(f))
    .collect();
reporter.report_all(&all_findings)?;
```

## Parallel Processing

### File Discovery and Processing

```rust
use rayon::prelude::*;
use ignore::WalkBuilder;

pub fn scan_directory(path: &Path, config: &Config) -> Result<Vec<Finding>> {
    let walker = WalkBuilder::new(path)
        .hidden(!config.include_hidden)
        .git_ignore(true)
        .build();

    let files: Vec<_> = walker
        .filter_map(Result::ok)
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .collect();

    // Parallel scan
    let findings: Vec<Finding> = files
        .par_iter()
        .filter_map(|entry| {
            scan_file(entry.path(), config).ok()
        })
        .flatten()
        .collect();

    Ok(findings)
}
```

## Error Handling Strategy

### User-Facing vs Internal Errors

```rust
#[derive(Error, Debug)]
pub enum CliError {
    // User-facing (recoverable, helpful message)
    #[error("Configuration file not found: {path}")]
    ConfigNotFound { path: PathBuf },

    #[error("Invalid rule ID: {id}. Did you mean {suggestion}?")]
    InvalidRule { id: String, suggestion: String },

    // Internal (should not happen, report bug)
    #[error("Internal error: {0}. Please report this bug.")]
    Internal(String),
}

impl CliError {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::ConfigNotFound { .. } => ExitCode::ConfigError,
            Self::InvalidRule { .. } => ExitCode::ConfigError,
            Self::Internal(_) => ExitCode::InternalError,
        }
    }
}
```

### Helpful Error Messages

```rust
// BAD: Cryptic error
Error: regex parse error

// GOOD: Actionable error (miette style)
error[EX-001]: Invalid regex pattern in rule
  ┌─ rules/custom.yaml:15:12
  │
15│   pattern: "[unclosed"
  │            ^^^^^^^^^^^ missing closing bracket
  │
  = help: Add ']' to close the character class
```

## Testing Strategy

### Unit Tests (Per Crate)

```rust
// crates/my_tool_parser/src/lib.rs
#[cfg(test)]
mod tests {
    #[test]
    fn parse_valid_input() { /* ... */ }
}
```

### Integration Tests (CLI Behavior)

```rust
// tests/integration.rs
use assert_cmd::Command;

#[test]
fn test_check_finds_issues() {
    Command::cargo_bin("my-tool")
        .unwrap()
        .arg("check")
        .arg("tests/fixtures/malicious")
        .assert()
        .failure()
        .code(1);
}

#[test]
fn test_json_output_format() {
    let output = Command::cargo_bin("my-tool")
        .unwrap()
        .args(["--format", "json", "tests/fixtures/sample"])
        .output()
        .unwrap();

    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(json.is_array());
}
```

### Snapshot Tests (Output Stability)

```rust
use insta::assert_snapshot;

#[test]
fn test_output_format() {
    let output = run_scan("fixtures/sample.js");
    assert_snapshot!(output);
}
```

## Quick Reference

| Principle | Implementation |
|-----------|----------------|
| Zero-config | `Config::load_or_default()` |
| Modularity | Workspace with focused crates |
| Performance | `rayon` parallel, streaming output |
| Layered config | CLI > env > project > user > default |
| Exit codes | 0=success, 1=findings, 2=config, 3=io |
| Error UX | Actionable messages with suggestions |
| Testing | Unit + integration + snapshot |

## Reference Projects

- **Biome**: Unified toolchain, LSP-first design
- **OxcLint**: Modular composability, extreme performance
- **ripgrep**: Parallel search, ignore handling
- **fd**: User-friendly defaults, smart output
- **cargo-deny**: Security-focused, config-driven
