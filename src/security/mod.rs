//! Security utilities for cc-audit
//!
//! This module provides security-focused utilities including:
//! - Path validation and traversal prevention
//! - Safe file I/O operations
//! - Canonical path handling

mod canonical;
mod path_validation;
mod safe_io;

pub use canonical::{CanonicalError, CanonicalPathSet};
pub use path_validation::{PathSecurityError, SafePath};
pub use safe_io::{SafeFileReader, SafeIoError};
