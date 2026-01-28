//! False positive report submission.

use super::FalsePositiveReport;
use std::io::Write;
use std::process::Command;
use thiserror::Error;

/// Target for submitting false positive reports.
#[derive(Debug, Clone)]
pub enum SubmitTarget {
    /// Submit to GitHub Issues using gh CLI
    GitHub {
        /// Repository in "owner/repo" format
        repo: String,
    },
    /// Submit to a custom endpoint (future use)
    Endpoint(String),
    /// Dry run - print to stdout without submitting
    DryRun,
}

impl Default for SubmitTarget {
    fn default() -> Self {
        Self::GitHub {
            repo: "ryo-ebata/cc-audit".to_string(),
        }
    }
}

/// Result of a report submission.
#[derive(Debug)]
pub struct SubmitResult {
    /// Whether the submission was successful
    pub success: bool,
    /// The issue URL if created
    pub issue_url: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Error type for submission failures.
#[derive(Debug, Error)]
pub enum SubmitError {
    #[error("gh CLI not found. Please install: https://cli.github.com/")]
    GhNotInstalled,

    #[error("gh CLI authentication required. Run: gh auth login")]
    GhAuthRequired,

    #[error("Failed to create issue: {0}")]
    IssueCreationFailed(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Submitter for false positive reports.
pub struct ReportSubmitter {
    target: SubmitTarget,
    labels: Vec<String>,
}

impl ReportSubmitter {
    /// Create a new submitter with default GitHub target.
    pub fn new() -> Self {
        Self {
            target: SubmitTarget::default(),
            labels: vec!["false-positive".to_string(), "triage".to_string()],
        }
    }

    /// Set the submission target.
    pub fn with_target(mut self, target: SubmitTarget) -> Self {
        self.target = target;
        self
    }

    /// Set additional labels.
    pub fn with_labels(mut self, labels: Vec<String>) -> Self {
        self.labels = labels;
        self
    }

    /// Check if gh CLI is available.
    pub fn check_gh_cli() -> Result<bool, SubmitError> {
        let output = Command::new("gh").arg("--version").output();

        match output {
            Ok(o) if o.status.success() => Ok(true),
            Ok(_) => Err(SubmitError::GhNotInstalled),
            Err(_) => Err(SubmitError::GhNotInstalled),
        }
    }

    /// Check if gh CLI is authenticated.
    pub fn check_gh_auth() -> Result<bool, SubmitError> {
        let output = Command::new("gh")
            .args(["auth", "status"])
            .output()
            .map_err(|_| SubmitError::GhNotInstalled)?;

        if output.status.success() {
            Ok(true)
        } else {
            Err(SubmitError::GhAuthRequired)
        }
    }

    /// Submit a false positive report.
    pub fn submit(&self, report: &FalsePositiveReport) -> Result<SubmitResult, SubmitError> {
        match &self.target {
            SubmitTarget::GitHub { repo } => self.submit_to_github(report, repo),
            SubmitTarget::Endpoint(url) => self.submit_to_endpoint(report, url),
            SubmitTarget::DryRun => self.dry_run(report),
        }
    }

    /// Submit to GitHub Issues.
    fn submit_to_github(
        &self,
        report: &FalsePositiveReport,
        repo: &str,
    ) -> Result<SubmitResult, SubmitError> {
        // Check gh CLI availability
        Self::check_gh_cli()?;
        Self::check_gh_auth()?;

        let title = report.to_github_issue_title();
        let body = report.to_github_issue_body();

        // Build gh command
        let mut cmd = Command::new("gh");
        cmd.args(["issue", "create"])
            .args(["--repo", repo])
            .args(["--title", &title])
            .args(["--body", &body]);

        // Add labels
        for label in &self.labels {
            cmd.args(["--label", label]);
        }

        let output = cmd.output()?;

        if output.status.success() {
            let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Ok(SubmitResult {
                success: true,
                issue_url: Some(url),
                error: None,
            })
        } else {
            let error = String::from_utf8_lossy(&output.stderr).to_string();
            Err(SubmitError::IssueCreationFailed(error))
        }
    }

    /// Submit to a custom endpoint (placeholder for future use).
    fn submit_to_endpoint(
        &self,
        _report: &FalsePositiveReport,
        url: &str,
    ) -> Result<SubmitResult, SubmitError> {
        // Future: implement HTTP POST to custom endpoint
        Ok(SubmitResult {
            success: false,
            issue_url: None,
            error: Some(format!("Endpoint submission not yet implemented: {}", url)),
        })
    }

    /// Dry run - print report without submitting.
    fn dry_run(&self, report: &FalsePositiveReport) -> Result<SubmitResult, SubmitError> {
        let title = report.to_github_issue_title();
        let body = report.to_github_issue_body();

        let mut stdout = std::io::stdout();
        writeln!(stdout, "=== DRY RUN: GitHub Issue ====")?;
        writeln!(stdout, "Title: {}", title)?;
        writeln!(stdout, "Labels: {}", self.labels.join(", "))?;
        writeln!(stdout, "---")?;
        writeln!(stdout, "{}", body)?;
        writeln!(stdout, "=============================")?;

        Ok(SubmitResult {
            success: true,
            issue_url: None,
            error: None,
        })
    }
}

impl Default for ReportSubmitter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_target() {
        let submitter = ReportSubmitter::new();
        match submitter.target {
            SubmitTarget::GitHub { ref repo } => {
                assert_eq!(repo, "ryo-ebata/cc-audit");
            }
            _ => panic!("Expected GitHub target"),
        }
    }

    #[test]
    fn test_dry_run() {
        let submitter = ReportSubmitter::new().with_target(SubmitTarget::DryRun);

        let report = FalsePositiveReport::new("SL-001")
            .with_extension("js")
            .with_description("Test description");

        let result = submitter.submit(&report).unwrap();
        assert!(result.success);
        assert!(result.issue_url.is_none());
    }

    #[test]
    fn test_custom_labels() {
        let submitter = ReportSubmitter::new().with_labels(vec![
            "bug".to_string(),
            "false-positive".to_string(),
            "needs-review".to_string(),
        ]);

        assert_eq!(submitter.labels.len(), 3);
        assert!(submitter.labels.contains(&"bug".to_string()));
    }

    #[test]
    fn test_submit_to_endpoint() {
        let submitter = ReportSubmitter::new().with_target(SubmitTarget::Endpoint(
            "https://example.com/api".to_string(),
        ));

        let report = FalsePositiveReport::new("SL-001")
            .with_extension("js")
            .with_description("Test description");

        let result = submitter.submit(&report).unwrap();
        assert!(!result.success);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("not yet implemented"));
    }

    #[test]
    fn test_submit_result_fields() {
        let result = SubmitResult {
            success: true,
            issue_url: Some("https://github.com/test/test/issues/1".to_string()),
            error: None,
        };

        assert!(result.success);
        assert!(result.issue_url.is_some());
        assert!(result.error.is_none());
    }

    #[test]
    fn test_submit_error_display() {
        let err1 = SubmitError::GhNotInstalled;
        assert!(err1.to_string().contains("gh CLI not found"));

        let err2 = SubmitError::GhAuthRequired;
        assert!(err2.to_string().contains("gh CLI authentication required"));

        let err3 = SubmitError::IssueCreationFailed("test error".to_string());
        assert!(err3.to_string().contains("test error"));
    }

    #[test]
    fn test_submit_target_github() {
        let target = SubmitTarget::GitHub {
            repo: "custom/repo".to_string(),
        };

        match target {
            SubmitTarget::GitHub { repo } => assert_eq!(repo, "custom/repo"),
            _ => panic!("Expected GitHub target"),
        }
    }

    #[test]
    fn test_submit_target_endpoint() {
        let target = SubmitTarget::Endpoint("https://example.com".to_string());

        match target {
            SubmitTarget::Endpoint(url) => assert_eq!(url, "https://example.com"),
            _ => panic!("Expected Endpoint target"),
        }
    }

    #[test]
    fn test_default_submitter() {
        let submitter = ReportSubmitter::default();
        assert_eq!(submitter.labels.len(), 2);
        assert!(submitter.labels.contains(&"false-positive".to_string()));
        assert!(submitter.labels.contains(&"triage".to_string()));
    }

    #[test]
    fn test_with_target_chaining() {
        let submitter = ReportSubmitter::new()
            .with_target(SubmitTarget::DryRun)
            .with_labels(vec!["custom".to_string()]);

        match submitter.target {
            SubmitTarget::DryRun => {}
            _ => panic!("Expected DryRun target"),
        }
        assert_eq!(submitter.labels.len(), 1);
    }
}
