//! Input layer (L1) for input source abstraction.
//!
//! This module handles:
//! - CLI argument parsing
//! - Input source resolution (local paths, remote URLs, clients)
//! - Client detection

pub mod source;

// Re-export from existing modules (will be moved here in Phase 10)
pub use crate::cli::{BadgeFormat, Cli, OutputFormat, ScanType};
pub use crate::client::{
    ClientType, DetectedClient, detect_client, detect_installed_clients, list_installed_clients,
};
pub use source::{InputSource, SourceResolver};
