# Config Module (L2)

The configuration layer handles loading, merging, and managing configuration for cc-audit.

## Architecture Layer

**Layer 2 (Configuration)** - Receives input from L1 (Input) and provides configuration to L3 (Discovery) and above.

## Responsibilities

- Load configuration from files (YAML, JSON, TOML)
- Merge CLI arguments with config file settings
- Manage profiles for reusable configurations
- Handle severity configuration for rule filtering
- Provide configuration templates for new projects

## Files

| File | Description |
|------|-------------|
| `mod.rs` | Module exports, tests |
| `types.rs` | Configuration type definitions (`Config`, `ScanConfig`, etc.) |
| `loading.rs` | File loading logic for different formats |
| `severity.rs` | `SeverityConfig` for rule severity overrides |
| `template.rs` | Configuration template generation |
| `error.rs` | `ConfigError` for configuration failures |

## Key Types

### Config

Main configuration structure loaded from `.cc-audit.yaml`:

```rust
pub struct Config {
    pub watch: WatchConfig,
    pub text_files: TextFilesConfig,
    pub ignore: IgnoreConfig,
    pub scan: ScanConfig,
    pub severity: SeverityConfig,
    pub baseline: BaselineConfig,
    pub rules: Vec<CustomRule>,
    pub malware_signatures: Vec<MalwareSignature>,
    pub disabled_rules: HashSet<String>,
}
```

### SeverityConfig

Controls rule severity overrides:

```rust
pub struct SeverityConfig {
    pub default: RuleSeverity,  // error or warn
    pub warn: HashSet<String>,  // Rules to treat as warnings
    pub ignore: HashSet<String>, // Rules to skip entirely
}
```

### EffectiveConfig

Merged configuration from CLI + config file + profile:

```rust
pub struct EffectiveConfig {
    pub cli: Cli,
    pub config: Config,
    pub profile: Option<Profile>,
}
```

## Supported Config Formats

| Format | File Name |
|--------|-----------|
| YAML | `.cc-audit.yaml`, `.cc-audit.yml` |
| JSON | `.cc-audit.json` |
| TOML | `.cc-audit.toml` |

## Configuration Hierarchy

1. CLI arguments (highest priority)
2. Config file (`.cc-audit.yaml`)
3. Profile settings
4. Default values (lowest priority)

## Usage Example

```rust
use cc_audit::config::{Config, EffectiveConfig};

// Load from file
let config = Config::from_file(Path::new(".cc-audit.yaml"))?;

// Or auto-discover in project
let config = Config::load(Some(Path::new(".")));

// Generate template for new project
let template = Config::generate_template();
```
