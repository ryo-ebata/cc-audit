# Engine Module (L5)

The detection engine layer provides core security analysis functionality.

## Architecture Layer

**Layer 5 (Detection Engine)** - Receives parsed content from L4 and produces findings for L6 (Aggregator).

## Responsibilities

- File and directory scanning
- Rule pattern matching
- Suppression handling
- Malware signature detection
- CVE vulnerability checking
- Content deobfuscation
- Context detection

## Directory Structure

```
engine/
├── mod.rs          # Module exports
├── scanner.rs      # Scanner traits and config
├── traits.rs       # Trait definitions
└── scanners/       # Scanner implementations
    ├── mod.rs
    ├── skill/      # SKILL.md scanner
    ├── command.rs  # Command scanner
    ├── mcp.rs      # MCP config scanner
    ├── hook.rs     # Git hook scanner
    ├── plugin.rs   # Plugin scanner
    ├── dockerfile.rs
    ├── dependency.rs
    ├── subagent.rs
    ├── manifest.rs
    ├── rules_dir.rs
    ├── walker.rs
    ├── macros.rs
    └── error.rs
```

## Key Types

### Scanner Trait

```rust
pub trait Scanner {
    fn name(&self) -> &'static str;
    fn scan(&self, path: &Path) -> ScanResult<Vec<Finding>>;
}

pub trait ContentScanner {
    fn scan_content(&self, content: &str, path: &Path) -> Vec<Finding>;
}
```

### ScannerConfig

```rust
pub struct ScannerConfig {
    pub skip_comments: bool,
    pub min_confidence: Confidence,
    pub disabled_rules: HashSet<String>,
}
```

## Available Scanners

| Scanner | Target Files | Description |
|---------|--------------|-------------|
| `SkillScanner` | SKILL.md, CLAUDE.md | Skill file security |
| `CommandScanner` | .claude/commands/*.md | Slash command analysis |
| `McpScanner` | mcp.json | MCP server config |
| `HookScanner` | hooks.json | Git hook config |
| `PluginScanner` | plugins.json | Plugin config |
| `DockerScanner` | Dockerfile | Docker security |
| `DependencyScanner` | package.json, Cargo.toml | Dependency analysis |
| `SubagentScanner` | subagent configs | Subagent security |
| `RulesDirScanner` | Custom rules | Rules validation |

## Re-exported Types

```rust
// From crate::context
pub use ContentContext, ContextDetector;

// From crate::cve_db
pub use CveDatabase, CveDbError, CveEntry;

// From crate::deobfuscation
pub use DecodedContent, Deobfuscator;

// From crate::malware_db
pub use MalwareDatabase, MalwareDbError;

// From crate::rules
pub use Confidence, Finding, RuleEngine, Severity;

// From crate::suppression
pub use SuppressionManager, SuppressionType;
```

## Usage Example

```rust
use cc_audit::engine::{SkillScanner, Scanner, ScannerConfig};

let config = ScannerConfig::default();
let scanner = SkillScanner::new(config);

let findings = scanner.scan(Path::new("SKILL.md"))?;
for finding in findings {
    println!("{}: {}", finding.id, finding.message);
}
```

## Data Flow

```
┌─────────────────┐
│   Parser (L4)   │
│  ParsedContent  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Detection Engine│
│  (This Module)  │
│   - Scanners    │
│   - Rules       │
│   - Malware DB  │
│   - CVE DB      │
└────────┬────────┘
         │ Findings
         ▼
┌─────────────────┐
│ Aggregator (L6) │
└─────────────────┘
```
