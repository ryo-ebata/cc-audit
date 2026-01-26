# Run Module

Scan execution and orchestration.

## Overview

This module provides the core scanning functionality, coordinating all the layers to perform security scans.

## Files

| File | Description |
|------|-------------|
| `mod.rs` | Module exports |
| `scanner.rs` | `run_scan`, `run_scan_with_config` |
| `config.rs` | `EffectiveConfig` - CLI + config merging |
| `client.rs` | `ScanMode`, client detection |
| `formatter.rs` | Output formatting helpers |
| `cve.rs` | CVE database scanning |
| `malware.rs` | Malware signature scanning |
| `text_file.rs` | Text file detection |
| `watch.rs` | Watch mode support |

## Key Types

### ScanMode

```rust
pub enum ScanMode {
    Directory(PathBuf),
    Client(ClientType),
    Remote(String),
}
```

### EffectiveConfig

Merged configuration from all sources:

```rust
pub struct EffectiveConfig {
    // Merged from CLI + config file + profile
    pub strict: bool,
    pub recursive: bool,
    pub verbose: bool,
    pub format: OutputFormat,
    pub scan_type: ScanType,
    pub disabled_rules: HashSet<String>,
    // ...
}
```

## Main Functions

### run_scan

Basic scan with default configuration:

```rust
pub fn run_scan(path: &Path) -> ScanResult;
```

### run_scan_with_config

Scan with custom configuration:

```rust
pub fn run_scan_with_config(path: &Path, config: &EffectiveConfig) -> ScanResult;
```

### scan_path_with_malware_db

Scan with malware database:

```rust
pub fn scan_path_with_malware_db(
    path: &Path,
    db: &MalwareDatabase,
    config: &EffectiveConfig,
) -> Vec<Finding>;
```

### scan_path_with_cve_db

Scan with CVE database:

```rust
pub fn scan_path_with_cve_db(
    path: &Path,
    db: &CveDatabase,
) -> Vec<CveEntry>;
```

## Watch Mode

Continuous scanning with file watching:

```rust
pub fn setup_watch_mode(path: &Path, config: &Config) -> WatchModeResult;
pub fn watch_iteration(watcher: &mut FileWatcher) -> Option<PathBuf>;
```

## Data Flow

```
┌─────────────────┐
│  CLI Arguments  │
│  Config File    │
│  Profile        │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ EffectiveConfig │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   run_scan()    │
│  (This Module)  │
├─────────────────┤
│ - Discovery     │
│ - Parsing       │
│ - Detection     │
│ - Aggregation   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   ScanResult    │
└─────────────────┘
```

## Usage Example

```rust
use cc_audit::run::{run_scan, run_scan_with_config, EffectiveConfig};

// Simple scan
let result = run_scan(Path::new("."));
println!("Findings: {}", result.findings.len());

// Scan with configuration
let config = EffectiveConfig::from_cli(&cli);
let result = run_scan_with_config(Path::new("."), &config);

// Format output
let output = format_result(&result, OutputFormat::Json);
println!("{}", output);
```

## Client Detection

```rust
use cc_audit::run::{resolve_scan_paths, detect_client_for_path, ScanMode};

// Auto-detect client
let client = detect_client_for_path(Path::new("."));

// Resolve paths to scan modes
let modes = resolve_scan_paths(&paths);
for mode in modes {
    match mode {
        ScanMode::Directory(path) => { /* local scan */ }
        ScanMode::Client(client) => { /* client config scan */ }
        ScanMode::Remote(url) => { /* remote repo scan */ }
    }
}
```
