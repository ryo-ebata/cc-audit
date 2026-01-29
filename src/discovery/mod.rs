//! Discovery layer (L3) for scan target enumeration.
//!
//! This module handles:
//! - Directory traversal and file discovery
//! - Ignore filtering (.gitignore, .cc-auditignore)
//! - File pattern matching
//! - Scan target definitions
//! - Text file detection

pub mod patterns;
pub mod targets;
pub mod text_detection;
pub mod walker;

pub use crate::ignore::IgnoreFilter;
pub use patterns::{
    COMMAND_PATTERNS, DEPENDENCY_PATTERNS, FilePattern, MCP_PATTERNS, SKILL_PATTERNS,
};
pub use targets::{ScanTarget, TargetKind};
pub use text_detection::{is_config_file, is_text_file, is_text_file_with_config};
pub use walker::{DirectoryWalker, WalkConfig};
