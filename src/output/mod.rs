//! Output layer (L7).
//!
//! This module handles output formatting and reporting:
//! - Terminal output with colored severity indicators
//! - JSON output for machine consumption
//! - SARIF output for IDE integration
//! - HTML reports for browser viewing
//! - Markdown reports for documentation
//!
//! The output layer takes ScanResult from L6 and produces
//! formatted output to stdout or files.

pub mod formatter;

// Re-export from existing reporter module (will be moved here in Phase 10)
pub use crate::reporter::{
    Reporter, html::HtmlReporter, json::JsonReporter, markdown::MarkdownReporter,
    sarif::SarifReporter, terminal::TerminalReporter,
};

// Re-export formatter
pub use formatter::OutputFormatter;
