//! Runtime execution control (横断層).
//!
//! This module provides runtime execution infrastructure:
//! - Scan context management
//! - Pipeline orchestration
//! - Executor for running scans
//! - Hook mode for CI/CD integration
//!
//! Note: This module is a skeleton for v1.x and will be fully
//! implemented in future versions.

pub mod context;
pub mod executor;
pub mod hook;
pub mod pipeline;

// Re-export from hook_mode (will be fully integrated in future)
pub use crate::hook_mode::{
    BashInput, EditInput, HookAnalyzer, HookEvent, HookEventName, HookResponse, WriteInput,
    run_hook_mode,
};

// Re-export local modules
pub use context::ScanContext;
pub use executor::ScanExecutor;
pub use hook::HookRunner;
pub use pipeline::{Pipeline, PipelineStage};
