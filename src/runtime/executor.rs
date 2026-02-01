//! Scan executor.
//!
//! Note: This is a skeleton for v1.x.

use super::context::ScanContext;
use super::pipeline::Pipeline;
use crate::error::Result;
use crate::rules::ScanResult;

/// Executor for running scans.
///
/// Note: This is a skeleton for v1.x. The actual executor
/// implementation will be added in future versions.
pub struct ScanExecutor {
    context: ScanContext,
    pipeline: Pipeline,
}

impl ScanExecutor {
    /// Create a new scan executor.
    pub fn new(context: ScanContext) -> Self {
        Self {
            context,
            pipeline: Pipeline::new(),
        }
    }

    /// Get the scan context.
    pub fn context(&self) -> &ScanContext {
        &self.context
    }

    /// Get the pipeline.
    pub fn pipeline(&self) -> &Pipeline {
        &self.pipeline
    }

    /// Run the scan.
    ///
    /// Note: This is a skeleton that returns an empty result.
    /// The actual implementation will use the pipeline to
    /// execute each stage.
    pub fn run(&mut self) -> Result<ScanResult> {
        use crate::rules::Summary;

        // Skeleton: just advance through pipeline stages
        while self.pipeline.advance()? {}

        // Return empty result for now
        Ok(ScanResult {
            version: env!("CARGO_PKG_VERSION").to_string(),
            scanned_at: chrono::Utc::now().to_rfc3339(),
            target: self
                .context
                .paths
                .first()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            summary: Summary {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
                passed: true,
                errors: 0,
                warnings: 0,
            },
            findings: Vec::new(),
            risk_score: None,
            elapsed_ms: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::path::PathBuf;

    #[test]
    fn test_executor_creation() {
        let ctx = ScanContext::new(vec![PathBuf::from(".")], Config::default());
        let executor = ScanExecutor::new(ctx);

        assert!(!executor.pipeline().is_complete());
    }

    #[test]
    fn test_executor_run() {
        let ctx = ScanContext::new(vec![PathBuf::from(".")], Config::default());
        let mut executor = ScanExecutor::new(ctx);

        let result = executor.run().unwrap();
        assert!(executor.pipeline().is_complete());
        assert!(result.findings.is_empty());
    }
}
