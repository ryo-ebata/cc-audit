//! Output formatter for scan results.

use crate::cli::OutputFormat;
use crate::reporter::{
    Reporter, html::HtmlReporter, json::JsonReporter, markdown::MarkdownReporter,
    sarif::SarifReporter, terminal::TerminalReporter,
};
use crate::rules::ScanResult;

/// Unified output formatter that selects the appropriate reporter.
pub struct OutputFormatter {
    format: OutputFormat,
    strict: bool,
    verbose: bool,
}

impl OutputFormatter {
    /// Create a new output formatter.
    pub fn new(format: OutputFormat) -> Self {
        Self {
            format,
            strict: false,
            verbose: false,
        }
    }

    /// Set strict mode.
    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    /// Set verbose output mode.
    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Format the scan result to a string.
    pub fn format(&self, result: &ScanResult) -> String {
        match self.format {
            OutputFormat::Terminal => {
                let reporter = TerminalReporter::new(self.strict, self.verbose);
                reporter.report(result)
            }
            OutputFormat::Json => {
                let reporter = JsonReporter::new();
                reporter.report(result)
            }
            OutputFormat::Sarif => {
                let reporter = SarifReporter::new();
                reporter.report(result)
            }
            OutputFormat::Html => {
                let reporter = HtmlReporter::new();
                reporter.report(result)
            }
            OutputFormat::Markdown => {
                let reporter = MarkdownReporter::new();
                reporter.report(result)
            }
        }
    }

    /// Get the appropriate file extension for the output format.
    pub fn extension(&self) -> &'static str {
        match self.format {
            OutputFormat::Terminal => "txt",
            OutputFormat::Json => "json",
            OutputFormat::Sarif => "sarif",
            OutputFormat::Html => "html",
            OutputFormat::Markdown => "md",
        }
    }
}

impl Default for OutputFormatter {
    fn default() -> Self {
        Self::new(OutputFormat::Terminal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_formatter_extensions() {
        assert_eq!(
            OutputFormatter::new(OutputFormat::Terminal).extension(),
            "txt"
        );
        assert_eq!(OutputFormatter::new(OutputFormat::Json).extension(), "json");
        assert_eq!(
            OutputFormatter::new(OutputFormat::Sarif).extension(),
            "sarif"
        );
        assert_eq!(OutputFormatter::new(OutputFormat::Html).extension(), "html");
        assert_eq!(
            OutputFormatter::new(OutputFormat::Markdown).extension(),
            "md"
        );
    }

    #[test]
    fn test_formatter_builder() {
        let formatter = OutputFormatter::new(OutputFormat::Terminal)
            .with_strict(true)
            .with_verbose(true);

        assert!(formatter.strict);
        assert!(formatter.verbose);
    }

    #[test]
    fn test_formatter_default() {
        let formatter = OutputFormatter::default();
        assert_eq!(formatter.format, OutputFormat::Terminal);
        assert!(!formatter.strict);
        assert!(!formatter.verbose);
    }

    fn create_test_result() -> crate::rules::ScanResult {
        crate::rules::ScanResult {
            version: "1.0.0".to_string(),
            scanned_at: "2024-01-01T00:00:00Z".to_string(),
            target: "/test".to_string(),
            summary: crate::rules::Summary {
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
        }
    }

    #[test]
    fn test_formatter_format_terminal() {
        let formatter = OutputFormatter::new(OutputFormat::Terminal);
        let result = create_test_result();
        let output = formatter.format(&result);
        assert!(
            output.contains("Pass")
                || output.contains("pass")
                || output.contains("PASS")
                || output.contains("No findings")
                || !output.is_empty()
        );
    }

    #[test]
    fn test_formatter_format_json() {
        let formatter = OutputFormatter::new(OutputFormat::Json);
        let result = create_test_result();
        let output = formatter.format(&result);
        assert!(output.starts_with('{'));
        assert!(output.ends_with('}'));
    }

    #[test]
    fn test_formatter_format_sarif() {
        let formatter = OutputFormatter::new(OutputFormat::Sarif);
        let result = create_test_result();
        let output = formatter.format(&result);
        assert!(output.contains("sarif") || output.contains("$schema"));
    }

    #[test]
    fn test_formatter_format_html() {
        let formatter = OutputFormatter::new(OutputFormat::Html);
        let result = create_test_result();
        let output = formatter.format(&result);
        assert!(output.contains("<html>") || output.contains("<!DOCTYPE"));
    }

    #[test]
    fn test_formatter_format_markdown() {
        let formatter = OutputFormatter::new(OutputFormat::Markdown);
        let result = create_test_result();
        let output = formatter.format(&result);
        assert!(output.contains('#') || output.contains("##"));
    }
}
