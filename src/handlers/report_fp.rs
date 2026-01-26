//! False positive report handler.

use crate::Cli;
use crate::feedback::{FalsePositiveReport, ReportSubmitter, SubmitTarget};
use colored::Colorize;
use std::io::{self, BufRead, Write};
use std::process::ExitCode;

/// Maximum input length to prevent memory exhaustion attacks.
const MAX_INPUT_LENGTH: usize = 10_000;

/// Read a line with length limit to prevent DoS.
fn read_line_limited(stdin: &io::Stdin, max_len: usize) -> io::Result<String> {
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;

    // Truncate if too long
    if line.len() > max_len {
        line.truncate(max_len);
    }

    Ok(line)
}

/// Handle the --report-fp command.
pub fn handle_report_fp(cli: &Cli) -> ExitCode {
    println!("{}", "False Positive Report".bold());
    println!("{}", "═".repeat(40));
    println!();

    // Check if telemetry is disabled
    if cli.no_telemetry {
        eprintln!(
            "{}",
            "Telemetry is disabled. Report will not be submitted.".yellow()
        );
        return ExitCode::from(2);
    }

    // Interactive prompts
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    // 1. Rule ID (required)
    print!("Rule ID (e.g., SL-001): ");
    if stdout.flush().is_err() {
        eprintln!("{}", "Error: Failed to write to stdout".red());
        return ExitCode::from(2);
    }

    let rule_id = match read_line_limited(&stdin, 100) {
        Ok(line) if !line.trim().is_empty() => line.trim().to_uppercase(),
        _ => {
            eprintln!("{}", "Error: Rule ID is required".red());
            return ExitCode::from(2);
        }
    };

    // Validate rule ID format
    if !is_valid_rule_id(&rule_id) {
        eprintln!(
            "{}",
            "Error: Invalid rule ID format. Expected format: XX-NNN (e.g., SL-001)".red()
        );
        return ExitCode::from(2);
    }

    // 2. File extension (optional)
    print!("File extension (optional, e.g., js, py): ");
    let _ = stdout.flush();
    let extension = read_line_limited(&stdin, 50)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_start_matches('.').to_string());

    // 3. Description (optional)
    println!("Description (why is this a false positive?):");
    print!("> ");
    let _ = stdout.flush();
    let description = read_line_limited(&stdin, MAX_INPUT_LENGTH)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    // Build the report
    let mut report = FalsePositiveReport::new(&rule_id);

    if let Some(ext) = extension {
        report = report.with_extension(ext);
    }

    if let Some(desc) = description {
        report = report.with_description(desc);
    }

    // Generate anonymous ID from username
    if let Ok(username) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
        report = report.with_anonymous_id(username.as_bytes());
    }

    println!();
    println!("{}", "Report Preview:".bold());
    println!("{}", "-".repeat(40));
    println!("{}", report.to_github_issue_body());
    println!("{}", "-".repeat(40));

    // Confirm submission
    print!("Submit this report? [y/N]: ");
    let _ = stdout.flush();
    let confirm = read_line_limited(&stdin, 10)
        .map(|s| s.trim().to_lowercase())
        .unwrap_or_default();

    if confirm != "y" && confirm != "yes" {
        println!("{}", "Report cancelled.".yellow());
        return ExitCode::SUCCESS;
    }

    // Determine target
    let target = if cli.report_fp_dry_run {
        SubmitTarget::DryRun
    } else if let Some(ref endpoint) = cli.report_fp_endpoint {
        SubmitTarget::Endpoint(endpoint.clone())
    } else {
        SubmitTarget::default()
    };

    // Submit the report
    let submitter = ReportSubmitter::new().with_target(target);

    println!();
    println!("{}", "Submitting report...".cyan());

    match submitter.submit(&report) {
        Ok(result) => {
            if result.success {
                if let Some(url) = result.issue_url {
                    println!("{} Report submitted successfully!", "✓".green());
                    println!("Issue URL: {}", url.cyan());
                } else {
                    println!("{} Report processed.", "✓".green());
                }
                ExitCode::SUCCESS
            } else {
                if let Some(error) = result.error {
                    eprintln!("{} Submission failed: {}", "✗".red(), error);
                } else {
                    eprintln!("{} Submission failed.", "✗".red());
                }
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("{} {}", "Error:".red(), e);
            ExitCode::from(2)
        }
    }
}

/// Validate rule ID format (XX-NNN).
fn is_valid_rule_id(id: &str) -> bool {
    let parts: Vec<&str> = id.split('-').collect();
    if parts.len() != 2 {
        return false;
    }

    // First part should be 2-4 uppercase letters
    let prefix = parts[0];
    if prefix.len() < 2 || prefix.len() > 4 || !prefix.chars().all(|c| c.is_ascii_uppercase()) {
        return false;
    }

    // Second part should be 1-4 digits
    let suffix = parts[1];
    if suffix.is_empty() || suffix.len() > 4 || !suffix.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_rule_ids() {
        assert!(is_valid_rule_id("SL-001"));
        assert!(is_valid_rule_id("EX-002"));
        assert!(is_valid_rule_id("PI-003"));
        assert!(is_valid_rule_id("OP-1"));
        assert!(is_valid_rule_id("MALW-0001"));
        assert!(is_valid_rule_id("CVE-1234"));
    }

    #[test]
    fn test_invalid_rule_ids() {
        assert!(!is_valid_rule_id("")); // Empty
        assert!(!is_valid_rule_id("SL001")); // No hyphen
        assert!(!is_valid_rule_id("sl-001")); // Lowercase
        assert!(!is_valid_rule_id("S-001")); // Single letter prefix
        assert!(!is_valid_rule_id("SL-")); // No number
        assert!(!is_valid_rule_id("-001")); // No prefix
        assert!(!is_valid_rule_id("ABCDE-001")); // Too long prefix
        assert!(!is_valid_rule_id("SL-12345")); // Too long suffix
        assert!(!is_valid_rule_id("SL-ABC")); // Non-numeric suffix
    }
}
