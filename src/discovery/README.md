# Discovery Module (L3)

The discovery layer handles scan target enumeration through directory traversal and file filtering.

## Architecture Layer

**Layer 3 (Discovery)** - Receives configuration from L2 and provides scan targets to L4 (Parser).

## Responsibilities

- Directory traversal and file discovery
- Ignore filtering (`.gitignore`, `.cc-auditignore`)
- File pattern matching for different scan types
- Scan target definition and resolution

## Files

| File | Description |
|------|-------------|
| `mod.rs` | Module exports and re-exports |
| `walker.rs` | `DirectoryWalker` - Traverses directories |
| `filter.rs` | `IgnoreFilter` - Handles ignore patterns |
| `patterns.rs` | File patterns for different scan types |
| `targets.rs` | `ScanTarget` and `TargetKind` definitions |

## Key Types

### DirectoryWalker

Traverses directories respecting ignore rules:

```rust
pub struct DirectoryWalker {
    config: WalkConfig,
    ignore_filter: IgnoreFilter,
}
```

### IgnoreFilter

Handles ignore patterns from multiple sources:

```rust
pub struct IgnoreFilter {
    gitignore_patterns: Vec<Pattern>,
    auditignore_patterns: Vec<Pattern>,
    config_patterns: Vec<Pattern>,
}
```

### ScanTarget

Represents a discovered scan target:

```rust
pub struct ScanTarget {
    pub path: PathBuf,
    pub kind: TargetKind,
}

pub enum TargetKind {
    SkillFile,
    CommandFile,
    McpConfig,
    HookConfig,
    // ...
}
```

## File Patterns

Pre-defined patterns for discovering files:

| Pattern Set | Description |
|-------------|-------------|
| `SKILL_PATTERNS` | SKILL.md, CLAUDE.md files |
| `COMMAND_PATTERNS` | .claude/commands/*.md |
| `MCP_PATTERNS` | mcp.json, claude_desktop_config.json |
| `DEPENDENCY_PATTERNS` | package.json, Cargo.toml, etc. |

## Ignore Sources

Files are ignored based on:

1. `.gitignore` patterns
2. `.cc-auditignore` patterns
3. Config file `ignore` section
4. Built-in defaults (node_modules, .git, etc.)

## Usage Example

```rust
use cc_audit::discovery::{DirectoryWalker, WalkConfig, IgnoreFilter};

let config = WalkConfig::default();
let walker = DirectoryWalker::new(config);

for target in walker.walk(Path::new("."))? {
    println!("Found: {:?} - {:?}", target.path, target.kind);
}
```

## Data Flow

```
┌─────────────────┐
│   Config (L2)   │
│  ignore rules   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Discovery     │
│  (This Module)  │
│   - Walker      │
│   - Filter      │
│   - Patterns    │
└────────┬────────┘
         │ ScanTargets
         ▼
┌─────────────────┐
│   Parser (L4)   │
└─────────────────┘
```
