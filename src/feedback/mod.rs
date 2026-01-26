//! Feedback module for false positive reporting.
//!
//! This module provides functionality to collect and submit false positive
//! reports to help improve detection accuracy.

pub mod report;
pub mod submitter;

pub use report::FalsePositiveReport;
pub use submitter::{ReportSubmitter, SubmitResult, SubmitTarget};
