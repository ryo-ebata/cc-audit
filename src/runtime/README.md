# Runtime Module (Cross-cutting)

Runtime execution control and infrastructure.

## Architecture Layer

**Cross-cutting (横断層)** - Provides infrastructure that spans multiple layers.

## Overview

This module provides runtime execution infrastructure:
- Scan context management
- Pipeline orchestration
- Executor for running scans
- Hook mode for CI/CD integration

> **Note**: This module is a skeleton for v1.x and will be fully implemented in future versions.

## Files

| File | Description |
|------|-------------|
| `mod.rs` | Module exports and re-exports |
| `context.rs` | `ScanContext` - Runtime context for scans |
| `executor.rs` | `ScanExecutor` - Executes scan pipelines |
| `hook.rs` | `HookRunner` - Runs pre/post scan hooks |
| `pipeline.rs` | `Pipeline`, `PipelineStage` - Scan orchestration |

## Key Types

### ScanContext

Runtime context for a scan operation:

```rust
pub struct ScanContext {
    pub config: EffectiveConfig,
    pub start_time: Instant,
    pub findings: Vec<Finding>,
    pub errors: Vec<ScanError>,
}
```

### ScanExecutor

Executes scan pipelines:

```rust
pub struct ScanExecutor {
    pipeline: Pipeline,
}

impl ScanExecutor {
    pub fn new(pipeline: Pipeline) -> Self;
    pub fn execute(&self, context: &mut ScanContext) -> ScanResult;
}
```

### Pipeline

Orchestrates scan stages:

```rust
pub struct Pipeline {
    stages: Vec<PipelineStage>,
}

pub enum PipelineStage {
    Discovery,
    Parse,
    Detect,
    Aggregate,
    Output,
}
```

### HookRunner

Runs pre/post scan hooks:

```rust
pub struct HookRunner {
    pre_hooks: Vec<Hook>,
    post_hooks: Vec<Hook>,
}

impl HookRunner {
    pub fn run_pre_hooks(&self, context: &ScanContext) -> Result<()>;
    pub fn run_post_hooks(&self, context: &ScanContext, result: &ScanResult) -> Result<()>;
}
```

## Re-exported Types

```rust
// From hook_mode
pub use HookAnalyzer, HookEvent, HookEventName, HookResponse;
pub use BashInput, EditInput, WriteInput;
pub use run_hook_mode;
```

## Pipeline Flow

```
┌─────────────────────────────────────────────────────────┐
│                    ScanExecutor                          │
├─────────────────────────────────────────────────────────┤
│  Pre-hooks → Discovery → Parse → Detect → Aggregate     │
│                                               ↓          │
│                                            Output        │
│                                               ↓          │
│                                          Post-hooks      │
└─────────────────────────────────────────────────────────┘
```

## Usage Example

```rust
use cc_audit::runtime::{ScanContext, ScanExecutor, Pipeline, PipelineStage};

// Create pipeline
let pipeline = Pipeline::new(vec![
    PipelineStage::Discovery,
    PipelineStage::Parse,
    PipelineStage::Detect,
    PipelineStage::Aggregate,
    PipelineStage::Output,
]);

// Create executor
let executor = ScanExecutor::new(pipeline);

// Execute
let mut context = ScanContext::new(config);
let result = executor.execute(&mut context);
```

## Hook Mode

For CI/CD integration via Claude Code Hooks API:

```rust
use cc_audit::runtime::run_hook_mode;

// Run in hook mode (reads from stdin, writes to stdout)
let exit_code = run_hook_mode();
```

## Future Plans

The runtime module will be expanded in future versions to include:
- Parallel execution
- Streaming results
- Progress reporting
- Cancellation support
- Resource management
