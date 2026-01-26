# External Module (Cross-cutting)

External integrations and cross-cutting concerns.

## Architecture Layer

**Cross-cutting (横断層)** - Integrations that span multiple layers and interact with external systems.

## Overview

This module provides external integrations:
- Remote repository operations
- Git hooks installation
- MCP server for IDE integration
- File watching for continuous scanning
- Auto-fix capabilities
- Tool pinning verification
- Trusted domain management

## Re-exported Types

All types are re-exported from their respective modules:

### Auto-Fix

```rust
// From crate::fix
pub use AutoFixer;   // Applies automatic fixes
pub use Fix;         // Fix definition
pub use FixResult;   // Result of fix application
```

### Git Hooks

```rust
// From crate::hooks
pub use HookInstaller;  // Installs/removes git hooks
pub use HookError;      // Hook operation errors
```

### MCP Server

```rust
// From crate::mcp_server
pub use McpServer;      // MCP server implementation
```

### Tool Pinning

```rust
// From crate::pinning
pub use ToolPins;       // Tool version pins
pub use PinnedTool;     // Individual pinned tool
pub use PinVerifyResult; // Verification result
pub use PinMismatch;    // Version mismatch info
```

### Remote Operations

```rust
// From crate::remote
pub use GitCloner;      // Clones remote repositories
pub use ClonedRepo;     // Cloned repository handle
pub use RemoteError;    // Remote operation errors
pub use parse_github_url; // URL parsing utility
```

### Trusted Domains

```rust
// From crate::trusted_domains
pub use TrustedDomainMatcher;  // Domain matching
pub use TrustedDomain;         // Domain definition
```

### File Watching

```rust
// From crate::watch
pub use FileWatcher;    // Watches files for changes
```

## Integration Diagram

```
┌─────────────────────────────────────────────────────────┐
│                   External Module                        │
├─────────────────┬─────────────────┬────────────────────┤
│                 │                 │                      │
│  Remote Ops     │   Local Ops     │    IDE Integration  │
│  - GitCloner    │   - HookInstaller│   - McpServer      │
│  - ClonedRepo   │   - FileWatcher │                      │
│                 │   - AutoFixer   │                      │
│                 │   - ToolPins    │                      │
│                 │                 │                      │
└────────┬────────┴────────┬────────┴─────────┬──────────┘
         │                 │                   │
         ▼                 ▼                   ▼
    [Remote Repos]    [Local Files]      [IDEs/Editors]
```

## Usage Examples

### Git Hooks

```rust
use cc_audit::external::{HookInstaller, HookError};

let installer = HookInstaller::new(Path::new("."));

// Install pre-commit hook
installer.install()?;

// Remove hook
installer.remove()?;
```

### Remote Repository

```rust
use cc_audit::external::{GitCloner, ClonedRepo};

let cloner = GitCloner::new();
let repo: ClonedRepo = cloner.clone("https://github.com/user/repo")?;

// Scan the cloned repo
let result = scan(repo.path());

// Repo is automatically cleaned up when dropped
```

### Tool Pinning

```rust
use cc_audit::external::{ToolPins, PinVerifyResult};

let pins = ToolPins::load(".tool-versions")?;
let result = pins.verify();

match result {
    PinVerifyResult::Ok => println!("All tools match pinned versions"),
    PinVerifyResult::Mismatch(mismatches) => {
        for m in mismatches {
            println!("{}: expected {}, got {}", m.tool, m.expected, m.actual);
        }
    }
}
```

### File Watching

```rust
use cc_audit::external::FileWatcher;

let watcher = FileWatcher::new(Path::new("."))?;

// Watch for changes
for event in watcher.events() {
    match event {
        FileEvent::Modified(path) => rescan(path),
        FileEvent::Created(path) => scan(path),
        // ...
    }
}
```

### MCP Server

```rust
use cc_audit::external::McpServer;

// Start MCP server for IDE integration
let server = McpServer::new();
server.run()?;
```
