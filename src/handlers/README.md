# Handlers Module

CLI command handlers for cc-audit operations.

## Overview

This module contains all handler functions for CLI commands, separated from `main.rs` to enable unit testing.

## Files

| File | Handler | Description |
|------|---------|-------------|
| `mod.rs` | `HandlerResult` | Module exports, result type |
| `scan.rs` | `run_normal_mode`, `run_watch_mode` | Main scan operations |
| `baseline.rs` | `handle_baseline`, `handle_check_drift`, `handle_save_baseline` | Baseline management |
| `compare.rs` | `handle_compare` | Directory comparison |
| `config.rs` | `handle_init_config`, `handle_save_profile`, `handle_show_profile` | Config operations |
| `fix.rs` | `handle_fix` | Auto-fix operations |
| `hook.rs` | `handle_init_hook`, `handle_remove_hook` | Git hook management |
| `hook_mode.rs` | `handle_hook_mode` | Real-time hook mode |
| `mcp.rs` | `handle_mcp_server` | MCP server mode |
| `pin.rs` | `handle_pin`, `handle_pin_verify` | Tool pinning |
| `remote.rs` | `handle_remote_scan`, `handle_remote_list_scan`, `handle_awesome_claude_code_scan` | Remote scanning |

## HandlerResult

All handlers return a testable result type:

```rust
pub enum HandlerResult {
    Success,
    Error(u8),
}

impl From<HandlerResult> for ExitCode {
    fn from(result: HandlerResult) -> Self {
        match result {
            HandlerResult::Success => ExitCode::SUCCESS,
            HandlerResult::Error(code) => ExitCode::from(code),
        }
    }
}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (no findings or warnings only) |
| 1 | Findings detected (errors) |
| 2 | Operation error (file not found, permission denied, etc.) |

## Handler Categories

### Scan Handlers

```rust
// Normal scan
run_normal_mode(&cli) -> ExitCode

// Watch mode (continuous scanning)
run_watch_mode(&cli) -> ExitCode
```

### Baseline Handlers

```rust
// Create baseline
handle_baseline(&cli) -> ExitCode

// Check for drift
handle_check_drift(&cli) -> ExitCode

// Save baseline to specific file
handle_save_baseline(&cli, path) -> ExitCode

// Filter results against baseline
filter_against_baseline(result, path) -> ScanResult
```

### Configuration Handlers

```rust
// Initialize config file
handle_init_config(&cli) -> ExitCode

// Save current settings as profile
handle_save_profile(&cli, name) -> ExitCode

// Show profile details
handle_show_profile(name) -> ExitCode
```

### Remote Handlers

```rust
// Scan remote repository
handle_remote_scan(&cli) -> ExitCode

// Scan list of repositories
handle_remote_list_scan(&cli) -> ExitCode

// Scan awesome-claude-code repositories
handle_awesome_claude_code_scan(&cli) -> ExitCode
```

## Usage Example

```rust
use cc_audit::handlers::{run_normal_mode, handle_baseline};

// Run a scan
let exit_code = run_normal_mode(&cli);

// Create baseline
let exit_code = handle_baseline(&cli);
```
