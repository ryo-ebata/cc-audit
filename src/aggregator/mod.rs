//! Aggregation layer (L6).
//!
//! This module aggregates findings from the detection engine:
//! - Collects findings from multiple sources
//! - Calculates risk scores
//! - Generates summaries
//! - Handles baseline comparison
//!
//! The aggregator takes raw findings from L5 and produces
//! a comprehensive ScanResult for the output layer (L7).

pub mod collector;
pub mod summary;

// Re-export from existing modules (will be moved here in Phase 10)
pub use crate::baseline::{Baseline, DriftEntry, DriftReport};
pub use crate::rules::{ScanResult, Summary};
pub use crate::scoring::{CategoryScore, RiskLevel, RiskScore, SeverityBreakdown};

// Re-export local modules
pub use collector::FindingCollector;
pub use summary::SummaryBuilder;
