//! Scan mode handlers.

use crate::run::EffectiveConfig;
use crate::{
    Cli, Config, WatchModeResult, format_result, run_scan, setup_watch_mode, watch_iteration,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tracing::{debug, info, warn};

use super::filter_against_baseline;

/// Validate that a path is safe to write to.
/// Prevents symlink attacks and path traversal issues.
fn validate_output_path(path: &Path) -> Result<(), String> {
    // Check for path traversal attempts
    let path_str = path.to_string_lossy();
    if path_str.contains("..") {
        return Err("Path contains parent directory reference (..)".to_string());
    }

    // If path exists, check it's not a symlink
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err("Output path is a symbolic link".to_string());
        }
    }

    // Check parent directory exists and is writable
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            return Err(format!(
                "Parent directory does not exist: {}",
                parent.display()
            ));
        }

        // Check parent is not a symlink
        if parent.exists() {
            let metadata = std::fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
            if metadata.file_type().is_symlink() {
                return Err("Parent directory is a symbolic link".to_string());
            }
        }
    }

    Ok(())
}

/// Validate that a path is safe to read from.
fn validate_input_path(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("Path does not exist: {}", path.display()));
    }

    // Check for symlinks to prevent symlink attacks
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if metadata.file_type().is_symlink() {
        warn!(
            path = %path.display(),
            "Input path is a symbolic link, following symlink"
        );
        // We allow symlinks for reading but log a warning
    }

    Ok(())
}

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
#[allow(clippy::comparison_to_empty)]
pub fn run_normal_mode(cli: &Cli) -> ExitCode {
    info!(paths = ?cli.paths, "Starting scan");

    // Load config to get effective settings
    let project_root = cli.paths.first().and_then(|p| {
        if p.is_dir() {
            Some(p.as_path())
        } else {
            p.parent()
        }
    });
    let config = Config::load(project_root);
    let effective = EffectiveConfig::from_cli_and_config(cli, &config);

    // Get the effective output path (CLI or config file)
    let effective_output_path: Option<PathBuf> = effective.output.as_ref().map(PathBuf::from);

    // Validate output path before scanning
    if let Some(ref output_path) = effective_output_path
        && let Err(e) = validate_output_path(output_path)
    {
        eprintln!("Invalid output path: {}", e);
        return ExitCode::from(2);
    }

    // Validate baseline path if specified
    if let Some(ref baseline_path) = cli.baseline_file
        && let Err(e) = validate_input_path(baseline_path)
    {
        eprintln!("Invalid baseline path: {}", e);
        return ExitCode::from(2);
    }

    match run_scan(cli) {
        Some(mut result) => {
            // Filter against baseline if --baseline-file is specified
            if let Some(ref baseline_path) = cli.baseline_file {
                result = filter_against_baseline(result, baseline_path);
            }

            let output = format_result(cli, &result);

            // Write to file if output path is specified (CLI or config)
            if let Some(ref output_path) = effective_output_path {
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
            let warn_only = effective.warn_only;

            if warn_only {
                ExitCode::SUCCESS
            } else if effective.strict {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn create_test_cli(paths: Vec<PathBuf>) -> Cli {
        Cli {
            paths,
            ..Default::default()
        }
    }

    #[test]
    fn test_run_normal_mode_valid_path() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("SKILL.md");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            "---\nname: test\ndescription: Test skill\n---\n# Test"
        )
        .unwrap();

        let cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        let exit_code = run_normal_mode(&cli);
        // Should succeed with no findings
        assert_eq!(exit_code, ExitCode::SUCCESS);
    }

    #[test]
    fn test_run_normal_mode_with_warn_only() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("SKILL.md");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            "---\nname: test\ndescription: Test skill\n---\n# Test"
        )
        .unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.warn_only = true;
        let exit_code = run_normal_mode(&cli);
        // warn_only always succeeds
        assert_eq!(exit_code, ExitCode::SUCCESS);
    }

    #[test]
    fn test_run_normal_mode_with_output_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("SKILL.md");
        let output_path = temp_dir.path().join("output.json");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            "---\nname: test\ndescription: Test skill\n---\n# Test"
        )
        .unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.output = Some(output_path.clone());
        let exit_code = run_normal_mode(&cli);
        assert_eq!(exit_code, ExitCode::SUCCESS);
        assert!(output_path.exists());
    }

    #[test]
    fn test_run_normal_mode_with_strict() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("SKILL.md");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            "---\nname: test\ndescription: Test skill\n---\n# Test"
        )
        .unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.strict = true;
        let exit_code = run_normal_mode(&cli);
        // Should succeed with no findings
        assert_eq!(exit_code, ExitCode::SUCCESS);
    }

    #[test]
    fn test_run_normal_mode_with_baseline() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("SKILL.md");
        let baseline_path = temp_dir.path().join("baseline.json");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            "---\nname: test\ndescription: Test skill\n---\n# Test"
        )
        .unwrap();

        // Create empty baseline
        let mut baseline_file = fs::File::create(&baseline_path).unwrap();
        writeln!(baseline_file, "[]").unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.baseline_file = Some(baseline_path);
        let exit_code = run_normal_mode(&cli);
        assert_eq!(exit_code, ExitCode::SUCCESS);
    }

    #[test]
    fn test_run_normal_mode_output_write_fail() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("SKILL.md");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            "---\nname: test\ndescription: Test skill\n---\n# Test"
        )
        .unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        // Use a path that should fail to write
        cli.output = Some(PathBuf::from("/nonexistent/directory/output.json"));
        let exit_code = run_normal_mode(&cli);
        // Should fail with exit code 2
        assert_eq!(exit_code, ExitCode::from(2));
    }

    #[test]
    fn test_validate_output_path_valid() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("output.json");

        assert!(validate_output_path(&output_path).is_ok());
    }

    #[test]
    fn test_validate_output_path_traversal() {
        let path = PathBuf::from("/tmp/../etc/passwd");
        let result = validate_output_path(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("parent directory reference"));
    }

    #[test]
    fn test_validate_output_path_nonexistent_parent() {
        let path = PathBuf::from("/nonexistent_dir_12345/output.json");
        let result = validate_output_path(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_output_path_symlink() {
        use std::os::unix::fs::symlink;

        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("target.json");
        let link = temp_dir.path().join("link.json");

        // Create target file
        fs::write(&target, "test").unwrap();
        // Create symlink
        symlink(&target, &link).unwrap();

        let result = validate_output_path(&link);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("symbolic link"));
    }

    #[test]
    fn test_validate_input_path_valid() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.json");
        fs::write(&file_path, "[]").unwrap();

        assert!(validate_input_path(&file_path).is_ok());
    }

    #[test]
    fn test_validate_input_path_nonexistent() {
        let path = PathBuf::from("/nonexistent_file_12345.json");
        let result = validate_input_path(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_output_path_parent_symlink() {
        use std::os::unix::fs::symlink;

        let temp_dir = TempDir::new().unwrap();
        let real_dir = temp_dir.path().join("real_dir");
        let link_dir = temp_dir.path().join("link_dir");

        // Create real directory
        fs::create_dir(&real_dir).unwrap();
        // Create symlink to directory
        symlink(&real_dir, &link_dir).unwrap();

        // Try to validate a path within the symlinked directory
        let path = link_dir.join("output.json");
        let result = validate_output_path(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("symbolic link"));
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_input_path_symlink() {
        use std::os::unix::fs::symlink;

        let temp_dir = TempDir::new().unwrap();
        let target = temp_dir.path().join("target.json");
        let link = temp_dir.path().join("link.json");

        // Create target file
        fs::write(&target, "[]").unwrap();
        // Create symlink
        symlink(&target, &link).unwrap();

        // Should succeed (symlinks are allowed for reading but logged)
        let result = validate_input_path(&link);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_output_path_empty_parent() {
        // Test path with no parent (just a filename)
        let path = PathBuf::from("output.json");
        // This should be valid (empty parent means current directory)
        let result = validate_output_path(&path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_output_path_existing_file() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("existing.json");

        // Create the file first
        fs::write(&output_path, "{}").unwrap();

        // Should be valid (existing regular file)
        let result = validate_output_path(&output_path);
        assert!(result.is_ok());
    }
}
