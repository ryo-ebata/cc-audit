//! Baseline management handlers.

use crate::{Baseline, CheckArgs, RiskScore, ScanResult, Summary};
use colored::Colorize;
use rustc_hash::FxHashMap;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Handle baseline command.
pub fn handle_baseline(paths: &[PathBuf]) -> ExitCode {
    for path in paths {
        match Baseline::from_directory(path) {
            Ok(baseline) => {
                if let Err(e) = baseline.save(path) {
                    eprintln!("Failed to save baseline for {}: {}", path.display(), e);
                    return ExitCode::from(2);
                }
                println!(
                    "Baseline created for {} ({} files)",
                    path.display(),
                    baseline.file_count
                );
            }
            Err(e) => {
                eprintln!("Failed to create baseline for {}: {}", path.display(), e);
                return ExitCode::from(2);
            }
        }
    }
    println!("\nBaseline saved. Use --check-drift to detect changes.");
    ExitCode::SUCCESS
}

/// Handle save-baseline command.
pub fn handle_save_baseline(paths: &[PathBuf], baseline_path: &Path) -> ExitCode {
    // Single path case: use relative paths (compatible with check_drift)
    // Multiple paths case: use prefixed paths to distinguish sources
    let single_path = paths.len() == 1;

    let mut combined_hashes = FxHashMap::default();

    for path in paths {
        match Baseline::from_directory(path) {
            Ok(baseline) => {
                for (file_path, hash) in baseline.file_hashes {
                    // For single path, use relative path directly
                    // For multiple paths, prefix with path to distinguish
                    let key = if single_path {
                        file_path
                    } else {
                        format!("{}:{}", path.display(), file_path)
                    };
                    combined_hashes.insert(key, hash);
                }
            }
            Err(e) => {
                eprintln!("Failed to create baseline for {}: {}", path.display(), e);
                return ExitCode::from(2);
            }
        }
    }

    let baseline = Baseline {
        version: env!("CARGO_PKG_VERSION").to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        file_count: combined_hashes.len(),
        file_hashes: combined_hashes,
    };

    if let Err(e) = baseline.save_to_file(baseline_path) {
        eprintln!(
            "Failed to save baseline to {}: {}",
            baseline_path.display(),
            e
        );
        return ExitCode::from(2);
    }

    println!(
        "Baseline saved to {} ({} files)",
        baseline_path.display(),
        baseline.file_count
    );
    ExitCode::SUCCESS
}

/// Handle check-drift command.
pub fn handle_check_drift(args: &CheckArgs) -> ExitCode {
    let mut has_any_drift = false;

    // If --baseline-file is specified, load from that file
    if let Some(ref baseline_file) = args.baseline_file {
        let baseline = match Baseline::load_from_file(baseline_file) {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "Failed to load baseline from {}: {}",
                    baseline_file.display(),
                    e
                );
                return ExitCode::from(2);
            }
        };

        for path in &args.paths {
            match baseline.check_drift(path) {
                Ok(report) => {
                    println!("Checking drift for: {}\n", path.display());
                    println!("{}", report.format_terminal());
                    if report.has_drift {
                        has_any_drift = true;
                    }
                }
                Err(e) => {
                    eprintln!("Failed to check drift for {}: {}", path.display(), e);
                    return ExitCode::from(2);
                }
            }
        }
    } else {
        // Load baseline from each path's default location
        for path in &args.paths {
            match Baseline::load(path) {
                Ok(baseline) => match baseline.check_drift(path) {
                    Ok(report) => {
                        println!("Checking drift for: {}\n", path.display());
                        println!("{}", report.format_terminal());
                        if report.has_drift {
                            has_any_drift = true;
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to check drift for {}: {}", path.display(), e);
                        return ExitCode::from(2);
                    }
                },
                Err(e) => {
                    eprintln!(
                        "No baseline found for {}. Run with --baseline first.\nError: {}",
                        path.display(),
                        e
                    );
                    return ExitCode::from(2);
                }
            }
        }
    }

    if has_any_drift {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Filter scan results against a baseline file.
pub fn filter_against_baseline(mut result: ScanResult, baseline_path: &Path) -> ScanResult {
    // Load the baseline scan result
    let baseline_result = match fs::read_to_string(baseline_path) {
        Ok(content) => match serde_json::from_str::<ScanResult>(&content) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "{} Failed to parse baseline file: {}",
                    "Warning:".yellow(),
                    e
                );
                return result;
            }
        },
        Err(e) => {
            eprintln!(
                "{} Failed to read baseline file: {}",
                "Warning:".yellow(),
                e
            );
            return result;
        }
    };

    // Create a set of baseline finding signatures (id + file + line combo)
    let baseline_signatures: HashSet<String> = baseline_result
        .findings
        .iter()
        .map(|f| format!("{}:{}:{}", f.id, f.location.file, f.location.line))
        .collect();

    // Filter out findings that exist in baseline
    let original_count = result.findings.len();
    result.findings.retain(|f| {
        let sig = format!("{}:{}:{}", f.id, f.location.file, f.location.line);
        !baseline_signatures.contains(&sig)
    });

    let filtered_count = original_count - result.findings.len();
    if filtered_count > 0 {
        eprintln!(
            "{} {} findings filtered (already in baseline)",
            "Info:".cyan(),
            filtered_count
        );
    }

    // Recalculate summary (preserve rule_severity information)
    result.summary = Summary::from_findings_with_rule_severity(&result.findings);
    if let Some(ref mut risk_score) = result.risk_score {
        *risk_score = RiskScore::from_findings(&result.findings);
    }

    result
}
