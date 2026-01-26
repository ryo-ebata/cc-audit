# Input Module (L1)

The input layer handles input source abstraction and CLI argument parsing.

## Architecture Layer

**Layer 1 (Input)** - Entry point that provides input to L2 (Configuration).

## Responsibilities

- CLI argument parsing
- Input source resolution (local paths, remote URLs, clients)
- Client detection (Claude Code, Cursor, etc.)

## Files

| File | Description |
|------|-------------|
| `mod.rs` | Module exports and re-exports |
| `source.rs` | `InputSource` and `SourceResolver` |

## Key Types

### InputSource

Represents different input sources:

```rust
pub enum InputSource {
    LocalPath(PathBuf),
    RemoteUrl(String),
    Client(ClientType),
    Stdin,
}
```

### SourceResolver

Resolves input arguments to concrete sources:

```rust
pub struct SourceResolver;

impl SourceResolver {
    pub fn resolve(args: &[String]) -> Vec<InputSource>;
}
```

## Re-exported Types

```rust
// From crate::cli
pub use Cli, OutputFormat, ScanType, BadgeFormat;

// From crate::client
pub use ClientType, DetectedClient;
pub use detect_client, detect_installed_clients, list_installed_clients;
```

### ClientType

```rust
pub enum ClientType {
    ClaudeCode,
    Cursor,
    Windsurf,
    Cline,
    Custom(String),
}
```

### OutputFormat

```rust
pub enum OutputFormat {
    Terminal,
    Json,
    Sarif,
    Html,
    Markdown,
}
```

### ScanType

```rust
pub enum ScanType {
    All,
    Skill,
    Mcp,
    Command,
    Docker,
    Dependency,
    Subagent,
    Plugin,
    Hook,
}
```

## Data Flow

```
┌─────────────────┐
│  CLI Arguments  │
│  Remote URLs    │
│  Client Paths   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     Input       │
│  (This Module)  │
│   - Parse CLI   │
│   - Resolve     │
└────────┬────────┘
         │ InputSource
         ▼
┌─────────────────┐
│   Config (L2)   │
└─────────────────┘
```

## Usage Example

```rust
use cc_audit::input::{InputSource, SourceResolver, Cli};
use clap::Parser;

let cli = Cli::parse();
let sources = SourceResolver::resolve(&cli.paths);

for source in sources {
    match source {
        InputSource::LocalPath(path) => { /* scan local */ }
        InputSource::RemoteUrl(url) => { /* clone and scan */ }
        InputSource::Client(client) => { /* scan client config */ }
        InputSource::Stdin => { /* read from stdin */ }
    }
}
```
