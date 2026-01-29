//! Pipeline orchestration.
//!
//! Note: This is a skeleton for v1.x.

use crate::error::Result;

/// A stage in the scan pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineStage {
    /// Input resolution (L1).
    Input,
    /// Configuration loading (L2).
    Config,
    /// Target discovery (L3).
    Discovery,
    /// Content parsing (L4).
    Parsing,
    /// Detection engine (L5).
    Detection,
    /// Result aggregation (L6).
    Aggregation,
    /// Output formatting (L7).
    Output,
}

impl PipelineStage {
    /// Get the next stage in the pipeline.
    pub fn next(&self) -> Option<Self> {
        match self {
            Self::Input => Some(Self::Config),
            Self::Config => Some(Self::Discovery),
            Self::Discovery => Some(Self::Parsing),
            Self::Parsing => Some(Self::Detection),
            Self::Detection => Some(Self::Aggregation),
            Self::Aggregation => Some(Self::Output),
            Self::Output => None,
        }
    }

    /// Get the stage name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Config => "config",
            Self::Discovery => "discovery",
            Self::Parsing => "parsing",
            Self::Detection => "detection",
            Self::Aggregation => "aggregation",
            Self::Output => "output",
        }
    }
}

/// Pipeline for running scans.
///
/// Note: This is a skeleton for v1.x. The actual pipeline
/// implementation will be added in future versions.
pub struct Pipeline {
    current_stage: PipelineStage,
}

impl Pipeline {
    /// Create a new pipeline.
    pub fn new() -> Self {
        Self {
            current_stage: PipelineStage::Input,
        }
    }

    /// Get the current stage.
    pub fn current_stage(&self) -> PipelineStage {
        self.current_stage
    }

    /// Advance to the next stage.
    pub fn advance(&mut self) -> Result<bool> {
        if let Some(next) = self.current_stage.next() {
            self.current_stage = next;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Check if the pipeline is complete.
    pub fn is_complete(&self) -> bool {
        self.current_stage == PipelineStage::Output
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_stages() {
        let mut pipeline = Pipeline::new();

        assert_eq!(pipeline.current_stage(), PipelineStage::Input);
        assert!(!pipeline.is_complete());

        // Advance through all stages
        while pipeline.advance().unwrap() {}

        assert!(pipeline.is_complete());
        assert_eq!(pipeline.current_stage(), PipelineStage::Output);
    }

    #[test]
    fn test_stage_names() {
        assert_eq!(PipelineStage::Input.name(), "input");
        assert_eq!(PipelineStage::Detection.name(), "detection");
        assert_eq!(PipelineStage::Output.name(), "output");
    }

    #[test]
    fn test_all_stage_names() {
        // Comprehensive test for all 7 stage names
        assert_eq!(PipelineStage::Input.name(), "input");
        assert_eq!(PipelineStage::Config.name(), "config");
        assert_eq!(PipelineStage::Discovery.name(), "discovery");
        assert_eq!(PipelineStage::Parsing.name(), "parsing");
        assert_eq!(PipelineStage::Detection.name(), "detection");
        assert_eq!(PipelineStage::Aggregation.name(), "aggregation");
        assert_eq!(PipelineStage::Output.name(), "output");
    }

    #[test]
    fn test_stage_next_chain() {
        // Test complete next() chain from Input to Output
        assert_eq!(PipelineStage::Input.next(), Some(PipelineStage::Config));
        assert_eq!(PipelineStage::Config.next(), Some(PipelineStage::Discovery));
        assert_eq!(
            PipelineStage::Discovery.next(),
            Some(PipelineStage::Parsing)
        );
        assert_eq!(
            PipelineStage::Parsing.next(),
            Some(PipelineStage::Detection)
        );
        assert_eq!(
            PipelineStage::Detection.next(),
            Some(PipelineStage::Aggregation)
        );
        assert_eq!(
            PipelineStage::Aggregation.next(),
            Some(PipelineStage::Output)
        );
        assert_eq!(PipelineStage::Output.next(), None);
    }

    #[test]
    fn test_pipeline_advance_returns_false_at_end() {
        let mut pipeline = Pipeline::new();

        // Advance to Output stage
        while pipeline.advance().unwrap() {}

        // Should be at Output
        assert_eq!(pipeline.current_stage(), PipelineStage::Output);

        // Calling advance() again should return false
        let result = pipeline.advance().unwrap();
        assert!(!result);

        // Should still be at Output
        assert_eq!(pipeline.current_stage(), PipelineStage::Output);
    }

    #[test]
    fn test_pipeline_multiple_advances() {
        let mut pipeline = Pipeline::new();

        // First advance: Input -> Config
        assert_eq!(pipeline.current_stage(), PipelineStage::Input);
        assert!(pipeline.advance().unwrap());
        assert_eq!(pipeline.current_stage(), PipelineStage::Config);

        // Second advance: Config -> Discovery
        assert!(pipeline.advance().unwrap());
        assert_eq!(pipeline.current_stage(), PipelineStage::Discovery);

        // Third advance: Discovery -> Parsing
        assert!(pipeline.advance().unwrap());
        assert_eq!(pipeline.current_stage(), PipelineStage::Parsing);

        // Fourth advance: Parsing -> Detection
        assert!(pipeline.advance().unwrap());
        assert_eq!(pipeline.current_stage(), PipelineStage::Detection);

        // Fifth advance: Detection -> Aggregation
        assert!(pipeline.advance().unwrap());
        assert_eq!(pipeline.current_stage(), PipelineStage::Aggregation);

        // Sixth advance: Aggregation -> Output
        assert!(pipeline.advance().unwrap());
        assert_eq!(pipeline.current_stage(), PipelineStage::Output);
        assert!(pipeline.is_complete());

        // Seventh advance: Output -> None (returns false)
        assert!(!pipeline.advance().unwrap());
        assert_eq!(pipeline.current_stage(), PipelineStage::Output);
    }
}
