//! Scan executor.
//!
use super::context::ScanContext;
use super::pipeline::Pipeline;
use crate::error::{AuditError, Result};
use crate::rules::ScanResult;
use crate::{CheckArgs, run_scan_with_check_args_config};

/// Executor for running scans.
///
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
    pub fn run(&mut self) -> Result<ScanResult> {
        let args = CheckArgs {
            paths: self.context.paths.clone(),
            strict: self.context.strict,
            ..CheckArgs::default()
        };
        let result = run_scan_with_check_args_config(&args, self.context.config.clone())
            .ok_or_else(|| AuditError::Config("scan failed to produce a result".to_string()))?;

        while self.pipeline.advance()? {}

        Ok(result)
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
        let ctx = ScanContext::new(
            vec![PathBuf::from("tests/fixtures/rules/sc_001.txt")],
            Config::default(),
        );
        let mut executor = ScanExecutor::new(ctx);

        let result = executor.run().unwrap();
        assert!(executor.pipeline().is_complete());
        assert!(!result.findings.is_empty());
        assert!(!result.summary.passed);
        assert!(result.risk_score.is_some());
        assert!(result.elapsed_ms > 0);
    }
}
