# Scanners Module

Scanner implementations for the detection engine (L5).

## Overview

This module contains specialized scanners that analyze different file types for security issues.

## Files

| File | Scanner | Description |
|------|---------|-------------|
| `skill/` | `SkillScanner` | SKILL.md and CLAUDE.md analysis |
| `command.rs` | `CommandScanner` | Slash command file analysis |
| `mcp.rs` | `McpScanner` | MCP server configuration |
| `hook.rs` | `HookScanner` | Git hook configuration |
| `plugin.rs` | `PluginScanner` | Plugin configuration |
| `dockerfile.rs` | `DockerScanner` | Dockerfile security |
| `dependency.rs` | `DependencyScanner` | Dependency manifests |
| `subagent.rs` | `SubagentScanner` | Subagent configuration |
| `manifest.rs` | `ManifestScanner` | Manifest directory scanning |
| `rules_dir.rs` | `RulesDirScanner` | Custom rules validation |
| `walker.rs` | `DirectoryWalker` | Directory traversal |
| `macros.rs` | - | Helper macros for scanner creation |
| `error.rs` | `ScanError` | Error types |

## Skill Scanner Submodule

```
skill/
├── mod.rs           # Module exports
├── file_filter.rs   # SkillFileFilter - File detection
└── frontmatter.rs   # FrontmatterParser - YAML parsing
```

## Scanner Interface

All scanners implement the common interface:

```rust
pub trait Scanner {
    fn name(&self) -> &'static str;
    fn scan(&self, path: &Path) -> ScanResult<Vec<Finding>>;
}
```

## Usage

```rust
use cc_audit::engine::scanners::{SkillScanner, McpScanner, CommandScanner};

// Scan a SKILL.md file
let skill_scanner = SkillScanner::new(config.clone());
let findings = skill_scanner.scan(Path::new("SKILL.md"))?;

// Scan MCP configuration
let mcp_scanner = McpScanner::new(config.clone());
let findings = mcp_scanner.scan(Path::new(".claude/mcp.json"))?;
```

## Scanner Macros

The `macros.rs` file provides helper macros for creating rules:

```rust
// Example macro usage (internal)
create_rule!(
    id: "EX-001",
    name: "Data Exfiltration",
    severity: Critical,
    // ...
);
```
