//! Scan execution and orchestration.
//!
//! This module provides the core scanning functionality, including:
//! - Scan mode determination and path resolution
//! - Configuration merging (CLI + config file)
//! - Running scans with various scanners
//! - Output formatting
//! - Watch mode support

mod client;
mod cve;
mod formatter;
mod malware;
mod scanner;
mod watch;

// Re-exports for public API
pub use crate::config::EffectiveConfig;
pub use client::{ScanMode, detect_client_for_path, resolve_scan_paths_from_check_args};
pub use cve::scan_path_with_cve_db;
pub use formatter::{format_result_check_args, format_result_with_config};
pub use malware::scan_path_with_malware_db;
pub use scanner::{run_scan_with_check_args, run_scan_with_check_args_config};
pub use watch::{WatchModeResult, setup_watch_mode, watch_iteration};
