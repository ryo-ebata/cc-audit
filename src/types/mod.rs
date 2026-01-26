//! Type-safe wrapper types for improved compile-time guarantees.
//!
//! This module provides NewType pattern implementations to prevent
//! primitive type misuse and improve API clarity.

mod newtypes;
mod paths;

pub use newtypes::{AuthToken, CommandArgs, CompiledPattern, FileHash, GitRef, RuleId, ServerName};
pub use paths::{PathValidationError, ScanTarget};
