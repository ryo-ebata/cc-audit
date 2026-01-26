//! Scan mode handlers.

use crate::{Cli, WatchModeResult, format_result, run_scan, setup_watch_mode, watch_iteration};
use std::fs;
use std::process::ExitCode;
use tracing::{debug, info};

use super::filter_against_baseline;

/// Handle --watch command.
pub fn run_watch_mode(cli: &Cli) -> ExitCode {
    info!("Starting watch mode");
    println!("Starting watch mode...");
    println!("Press Ctrl+C to stop\n");

    let watcher = match setup_watch_mode(cli) {
        Ok(w) => w,
        Err(WatchModeResult::WatcherCreationFailed(e)) => {
            eprintln!("Failed to create file watcher: {}", e);
            return ExitCode::from(2);
        }
        Err(WatchModeResult::WatchPathFailed(path, e)) => {
            eprintln!("Failed to watch {}: {}", path, e);
            return ExitCode::from(2);
        }
        Err(WatchModeResult::Success) => unreachable!(),
    };

    // Initial scan
    if let Some(output) = watch_iteration(cli) {
        println!("{}", output);
    }

    // Watch loop
    loop {
        if watcher.wait_for_change() {
            // Clear screen for better readability
            print!("\x1B[2J\x1B[1;1H");
            println!("File change detected, re-scanning...\n");

            if let Some(output) = watch_iteration(cli) {
                println!("{}", output);
            }
        } else {
            // Watcher disconnected
            break;
        }
    }

    ExitCode::SUCCESS
}

/// Run normal scan mode.
pub fn run_normal_mode(cli: &Cli) -> ExitCode {
    info!(paths = ?cli.paths, "Starting scan");
    match run_scan(cli) {
        Some(mut result) => {
            // Filter against baseline if --baseline-file is specified
            if let Some(ref baseline_path) = cli.baseline_file {
                result = filter_against_baseline(result, baseline_path);
            }

            let output = format_result(cli, &result);

            // Write to file if --output is specified
            if let Some(ref output_path) = cli.output {
                match fs::write(output_path, &output) {
                    Ok(()) => {
                        println!("Output written to {}", output_path.display());
                    }
                    Err(e) => {
                        eprintln!("Failed to write output to {}: {}", output_path.display(), e);
                        return ExitCode::from(2);
                    }
                }
            } else {
                println!("{}", output);
            }

            debug!(
                errors = result.summary.errors,
                warnings = result.summary.warnings,
                findings = result.findings.len(),
                "Scan completed"
            );

            // Determine exit code based on mode:
            // - warn_only: always exit 0 (warnings don't fail CI)
            // - strict: exit 1 if any findings (errors or warnings)
            // - normal: exit 1 if any errors
            if cli.warn_only {
                ExitCode::SUCCESS
            } else if cli.strict {
                // In strict mode, any finding (error or warning) is a failure
                if result.summary.errors > 0 || result.summary.warnings > 0 {
                    ExitCode::from(1)
                } else {
                    ExitCode::SUCCESS
                }
            } else {
                // Normal mode: result.summary.passed is based on errors == 0
                if result.summary.passed {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                }
            }
        }
        None => {
            debug!("Scan returned no result");
            ExitCode::from(2)
        }
    }
}
