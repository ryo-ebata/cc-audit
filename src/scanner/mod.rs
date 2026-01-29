//! Security scanner module.
//!
//! **DEPRECATED**: This module is deprecated since v3.3.0 and will be removed in v4.0.0.
//!
//! This module re-exports scanner implementations from `engine/scanners/`
//! for backward compatibility only. New code should import directly from
//! `crate::engine::scanners` or `crate::engine::scanner`.
//!
//! # Migration Guide
//!
//! ```rust,ignore
//! // Old (deprecated):
//! use crate::scanner::{Scanner, ScannerConfig};
//! use crate::scanner::SkillScanner;
//!
//! // New (recommended):
//! use crate::engine::scanner::{Scanner, ScannerConfig};
//! use crate::engine::scanners::SkillScanner;
//! ```

// Re-export everything from engine/scanners for backward compatibility
pub use crate::engine::scanners::*;

// Re-export Scanner traits and ScannerConfig from engine/scanner
pub use crate::engine::scanner::{ContentScanner, Scanner, ScannerConfig};
