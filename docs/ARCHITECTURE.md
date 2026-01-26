# cc-audit Architecture Design v1.0

This document describes the 7-layer architecture of cc-audit.

## Design Decisions

| Item | Decision | Rationale |
|------|----------|-----------|
| L4 (Content Parser) granularity | Separate by file format | High reusability, easier implementation of F-202 (context awareness) |
| scanner/ migration strategy | Full migration | No parallel operation, avoid technical debt |
| runtime/ early implementation | Create skeleton in v1.x | Show future direction to contributors |

---

## Architecture: 7 Layers + Cross-cutting Concerns

### Data Flow

```
[Input] → L1 → L2 → L3 → L4 → L5 → L6 → L7 → [Output]
            ↓         ↓    ↓
         [Config] [external/] [runtime/]
```

### Layer Responsibilities

| Layer | Module | Input | Output | Responsibility |
|-------|--------|-------|--------|----------------|
| L1 | `input/` | CLI args, stdin, config path | `InputContext` | Input source abstraction. CLI/Hook/Proxy mode detection |
| L2 | `config/` | `InputContext` | `ScanPlan` | Config merging, profile application, scan plan determination |
| L3 | `discovery/` | `ScanPlan` | `Vec<Target>` | Scan target enumeration. Client auto-detection, ignore processing |
| L4 | `parser/` | `Target` | `ParsedContent` | File format parsing. Structural context extraction |
| L5 | `engine/` | `ParsedContent`, `Rules` | `Vec<RawFinding>` | Parallel rule evaluation. Pattern matching execution |
| L6 | `aggregator/` | `Vec<RawFinding>` | `ScanResult` | Deduplication, scoring, baseline comparison |
| L7 | `output/` | `ScanResult` | stdout/file | Format selection, output generation |

---

## Directory Structure

```
src/
├── lib.rs
├── main.rs
│
├── input/                    # L1: Input Layer
│   ├── mod.rs
│   ├── cli.rs               # CLI argument parsing
│   ├── source.rs            # Input source resolution
│   └── client.rs            # Client detection (Claude, Cursor, etc.)
│
├── config/                   # L2: Configuration Layer
│   ├── mod.rs
│   ├── types.rs             # Configuration type definitions
│   ├── loading.rs           # File loading logic
│   ├── effective.rs         # CLI + config + profile merging
│   ├── profile.rs           # Profile management
│   └── severity.rs          # Severity configuration
│
├── discovery/                # L3: Discovery Layer
│   ├── mod.rs
│   ├── walker.rs            # Directory traversal
│   ├── filter.rs            # Ignore filter
│   ├── patterns.rs          # File patterns
│   └── targets.rs           # ScanTarget definitions
│
├── parser/                   # L4: Parser Layer
│   ├── mod.rs
│   ├── traits.rs            # ContentParser trait
│   ├── markdown.rs          # Markdown/SKILL.md/CLAUDE.md
│   ├── json.rs              # JSON files
│   ├── yaml.rs              # YAML files
│   ├── toml.rs              # TOML files
│   ├── dockerfile.rs        # Dockerfile
│   └── frontmatter.rs       # Frontmatter extraction
│
├── engine/                   # L5: Detection Engine Layer
│   ├── mod.rs
│   ├── rule_engine.rs       # Rule evaluation
│   ├── matcher.rs           # Pattern matching
│   ├── suppression.rs       # Inline suppression
│   ├── context.rs           # Context detection (F-202)
│   ├── malware.rs           # Malware signature DB
│   ├── cve.rs               # CVE database
│   └── deobfuscation.rs     # Deobfuscation
│
├── aggregator/               # L6: Aggregation Layer
│   ├── mod.rs
│   ├── collector.rs         # Finding collection
│   ├── scorer.rs            # Risk scoring
│   ├── summary.rs           # Summary generation
│   └── baseline.rs          # Baseline comparison
│
├── output/                   # L7: Output Layer
│   ├── mod.rs
│   ├── reporter.rs          # Reporter trait
│   ├── terminal.rs          # Terminal output
│   ├── json.rs              # JSON output
│   ├── sarif.rs             # SARIF output
│   ├── html.rs              # HTML report
│   ├── markdown.rs          # Markdown report
│   └── formatter.rs         # Output formatting
│
├── rules/                    # Cross-cutting: Rule Definitions
│   ├── mod.rs
│   ├── types.rs             # Finding, Rule, Severity, Category
│   ├── custom.rs            # Custom rule loading
│   ├── builtin/             # Built-in rules
│   └── snapshot_test.rs
│
├── external/                 # Cross-cutting: External Integration
│   ├── mod.rs
│   ├── remote.rs            # Git clone, remote scanning
│   ├── hooks.rs             # Git hook management
│   ├── mcp_server.rs        # MCP server
│   ├── watch.rs             # File watching
│   ├── fix.rs               # Auto-fix
│   ├── pinning.rs           # Tool pinning
│   └── trusted_domains.rs   # Trusted domain management
│
├── runtime/                  # Cross-cutting: Execution Control (skeleton only in v1.x)
│   ├── mod.rs
│   ├── context.rs           # Runtime context
│   ├── pipeline.rs          # Scan pipeline (stub)
│   ├── executor.rs          # Pipeline executor (stub)
│   └── hook.rs              # Hook mode (F-207)
│
├── handlers/                 # Request Handlers (simplified)
│   ├── mod.rs
│   ├── scan.rs
│   ├── baseline.rs
│   ├── compare.rs
│   ├── config.rs
│   ├── fix.rs
│   ├── hook.rs
│   ├── mcp.rs
│   ├── pin.rs
│   └── remote.rs
│
├── types/                    # Common Types
│   ├── mod.rs
│   ├── newtypes.rs
│   └── paths.rs
│
└── error/                    # Error Types
    ├── mod.rs
    ├── audit.rs
    └── context.rs
```

---

## Key Traits and Types

### L4: ContentParser

```rust
pub trait ContentParser: Send + Sync {
    fn parse(&self, content: &str, path: &str) -> Result<ParsedContent>;
    fn supported_extensions(&self) -> &[&str];
    fn can_parse(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|e| e.to_str())
            .map(|e| self.supported_extensions().contains(&e))
            .unwrap_or(false)
    }
}

pub struct ParsedContent {
    pub content_type: ContentType,
    pub raw_content: String,
    pub structured_data: Option<serde_json::Value>,
    pub frontmatter: Option<String>,
    pub source_path: String,
}

pub enum ContentType {
    Markdown,
    Json,
    Yaml,
    Toml,
    Dockerfile,
    Shell,
    Unknown,
}
```

### L5: DetectionEngine

```rust
pub trait DetectionEngine: Send + Sync {
    fn analyze(&self, content: &ParsedContent, config: &EngineConfig) -> Vec<Finding>;
    fn supports_content_type(&self, content_type: ContentType) -> bool;
}
```

### L6: ResultCollector

```rust
pub trait ResultCollector {
    fn collect(&mut self, findings: Vec<Finding>);
    fn finalize(self) -> ScanResult;
}
```

### L7: Reporter (existing, extended)

```rust
pub trait Reporter {
    fn report(&self, result: &ScanResult) -> String;
    fn format(&self) -> OutputFormat;
}
```

---

## Layer Dependencies

```
L1 (input)
    ↓
L2 (config)
    ↓
L3 (discovery)
    ↓
L4 (parser)
    ↓
L5 (engine) ← rules (cross-cutting)
    ↓
L6 (aggregator)
    ↓
L7 (output)

external, runtime, types, error → accessible from all layers
```

---

## runtime/ Skeleton Specification

In v1.x, only the following will be implemented:

### context.rs
- `RuntimeContext` type definition
- Configuration and CLI state holding

### pipeline.rs
- `ScanPipeline` type definition
- Pipeline stage definitions (stub)

### executor.rs
- `PipelineExecutor` type definition
- Execution orchestration (stub)

### hook.rs (from hook_mode/)
- `HookInput` / `HookOutput` type definitions
- stdin/stdout serialization spec (Claude Code Hooks compliant)
- Actual processing logic marked as `unimplemented!()`

**Purpose**: Allow contributors to understand "implementation will go here in the future"

---

## Deprecated Modules

| Current | Migration Target | Notes |
|---------|------------------|-------|
| `scanner/mod.rs` | Deleted | Distributed to each layer |
| `scanner/skill.rs` | `discovery/` + `parser/` + `engine/` | Split into 3 layers |
| `scanner/hook.rs` | `parser/json.rs` + `engine/` | Same |
| `scanner/mcp.rs` | `parser/json.rs` + `engine/` | Same |
| `scanner/command.rs` | `parser/markdown.rs` + `engine/` | Same |
| `scanner/dockerfile.rs` | `parser/dockerfile.rs` + `engine/` | Same |
| `scanner/dependency.rs` | `parser/` (multiple) + `engine/` | Same |
| `scanner/common.rs` | `engine/matcher.rs` | Common matching logic |
| `handlers.rs` | `input/cli.rs` + `output/` | Responsibility separation |
| `run.rs` | `aggregator/` + orchestration | Split |

---

## Version History

- v1.0 (2025-01-26): Initial architecture design
