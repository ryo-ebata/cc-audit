//! Scan mode handlers.

use crate::run::EffectiveConfig;
use crate::{
    CheckArgs, Config, WatchModeResult, format_result_check_args, run_scan_with_check_args_config,
    setup_watch_mode, watch_iteration,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tracing::{debug, info, warn};

use super::{
    filter_against_baseline, handle_baseline, handle_check_drift, handle_compare, handle_fix,
    handle_hook_mode, handle_pin, handle_pin_verify, handle_report_fp, handle_save_baseline,
    handle_save_profile, handle_sbom, handle_show_profile, require_config,
};

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

/// Handle `cc-audit check` subcommand.
pub fn handle_check(args: &CheckArgs, verbose: bool) -> ExitCode {
    info!(paths = ?args.paths, "Starting check command");

    // Determine project root for config lookup
    // For --compare, use the first compare path; otherwise use paths
    let project_root = if let Some(ref compare_paths) = args.compare {
        compare_paths.first().and_then(|p| {
            if p.is_dir() {
                Some(p.as_path())
            } else {
                p.parent()
            }
        })
    } else {
        args.paths.first().and_then(|p| {
            if p.is_dir() {
                Some(p.as_path())
            } else {
                p.parent()
            }
        })
    };

    // Load config: prefer --config option, then require config file
    let config = if let Some(ref config_path) = args.config {
        match Config::from_file(config_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "Error: Failed to load configuration from {}: {}",
                    config_path.display(),
                    e
                );
                return ExitCode::from(2);
            }
        }
    } else {
        match require_config(project_root) {
            Ok((config, _path)) => config,
            Err(exit_code) => return exit_code,
        }
    };

    // Handle --save-baseline <file>
    if let Some(ref baseline_path) = args.save_baseline {
        return handle_save_baseline(&args.paths, baseline_path);
    }

    // Handle baseline creation (--baseline)
    if args.baseline {
        return handle_baseline(&args.paths);
    }

    // Handle drift detection
    if args.check_drift {
        return handle_check_drift(args);
    }

    // Handle --compare <path1> <path2>
    if let Some(ref paths) = args.compare {
        return handle_compare(args, paths);
    }

    // Handle --fix or --fix-dry-run
    if args.fix || args.fix_dry_run {
        return handle_fix(args);
    }

    // Handle --hook-mode (Claude Code Hook integration)
    if args.hook_mode {
        return handle_hook_mode();
    }

    // Handle --pin (create MCP tool pins)
    if args.pin || args.pin_update {
        return handle_pin(args, verbose);
    }

    // Handle --pin-verify (verify MCP tool pins)
    if args.pin_verify {
        return handle_pin_verify(args);
    }

    // Handle --save-profile
    if let Some(ref profile_name) = args.save_profile {
        return handle_save_profile(args, profile_name, verbose);
    }

    // Handle --report-fp (false positive reporting)
    if args.report_fp {
        return handle_report_fp(args);
    }

    // Handle --sbom (SBOM generation)
    if args.sbom {
        return handle_sbom(args);
    }

    // Handle --profile (info mode when no paths to scan)
    if let Some(ref profile_name) = args.profile
        && args.paths.len() == 1
        && args.paths[0].as_os_str() == "."
        && !args.paths[0].exists()
    {
        return handle_show_profile(profile_name);
    }

    // Handle watch mode
    if args.watch {
        return run_watch_mode_check_args(args);
    }

    // Normal scan mode
    run_normal_mode_check_args(args, config)
}

/// Run watch mode with CheckArgs.
fn run_watch_mode_check_args(args: &CheckArgs) -> ExitCode {
    info!("Starting watch mode");
    println!("Starting watch mode...");
    println!("Press Ctrl+C to stop\n");

    let watcher = match setup_watch_mode(args) {
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
    if let Some(output) = watch_iteration(args) {
        println!("{}", output);
    }

    // Watch loop
    loop {
        if watcher.wait_for_change() {
            // Clear screen for better readability
            print!("\x1B[2J\x1B[1;1H");
            println!("File change detected, re-scanning...\n");

            if let Some(output) = watch_iteration(args) {
                println!("{}", output);
            }
        } else {
            // Watcher disconnected
            break;
        }
    }

    ExitCode::SUCCESS
}

/// Run normal scan mode with CheckArgs and pre-loaded config.
fn run_normal_mode_check_args(args: &CheckArgs, config: Config) -> ExitCode {
    let effective = EffectiveConfig::from_check_args_and_config(args, &config);

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
    if let Some(ref baseline_path) = args.baseline_file
        && let Err(e) = validate_input_path(baseline_path)
    {
        eprintln!("Invalid baseline path: {}", e);
        return ExitCode::from(2);
    }

    match run_scan_with_check_args_config(args, config) {
        Some(mut result) => {
            // Filter against baseline if --baseline-file is specified
            if let Some(ref baseline_path) = args.baseline_file {
                result = filter_against_baseline(result, baseline_path);
            }

            let output = format_result_check_args(args, &result);

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

            // Determine exit code based on mode
            let warn_only = effective.warn_only;

            if warn_only {
                ExitCode::SUCCESS
            } else if effective.strict {
                if result.summary.errors > 0 || result.summary.warnings > 0 {
                    ExitCode::from(1)
                } else {
                    ExitCode::SUCCESS
                }
            } else if result.summary.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        None => {
            debug!("Scan returned no result");
            ExitCode::from(2)
        }
    }
}

/// Run normal scan mode with CheckArgs (for external callers).
pub fn run_normal_check_mode(args: &CheckArgs) -> ExitCode {
    // Determine project root for config lookup
    let project_root = args.paths.first().and_then(|p| {
        if p.is_dir() {
            Some(p.as_path())
        } else {
            p.parent()
        }
    });

    // Load config
    let config = Config::load(project_root);

    run_normal_mode_check_args(args, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CheckArgs;
    use std::io::Write;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn create_test_check_args(paths: Vec<PathBuf>) -> CheckArgs {
        CheckArgs {
            paths,
            ..Default::default()
        }
    }

    /// Create a minimal config file in the given directory for tests
    fn create_test_config(dir: &Path) {
        let config_content = "# Minimal test config\n";
        fs::write(dir.join(".cc-audit.yaml"), config_content).unwrap();
    }

    #[test]
    fn test_run_normal_check_mode_valid_path() {
        let temp_dir = TempDir::new().unwrap();
        create_test_config(temp_dir.path());
        let file_path = temp_dir.path().join("SKILL.md");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            "---\nname: test\ndescription: Test skill\n---\n# Test"
        )
        .unwrap();

        let args = create_test_check_args(vec![temp_dir.path().to_path_buf()]);
        let exit_code = run_normal_check_mode(&args);
        // Should succeed with no findings
        assert_eq!(exit_code, ExitCode::SUCCESS);
    }

    #[test]
    fn test_run_normal_check_mode_with_warn_only() {
        let temp_dir = TempDir::new().unwrap();
        create_test_config(temp_dir.path());
        let file_path = temp_dir.path().join("SKILL.md");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            "---\nname: test\ndescription: Test skill\n---\n# Test"
        )
        .unwrap();

        let mut args = create_test_check_args(vec![temp_dir.path().to_path_buf()]);
        args.warn_only = true;
        let exit_code = run_normal_check_mode(&args);
        // warn_only always succeeds
        assert_eq!(exit_code, ExitCode::SUCCESS);
    }

    #[test]
    fn test_run_normal_check_mode_with_output_file() {
        let temp_dir = TempDir::new().unwrap();
        create_test_config(temp_dir.path());
        let file_path = temp_dir.path().join("SKILL.md");
        let output_path = temp_dir.path().join("output.json");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            "---\nname: test\ndescription: Test skill\n---\n# Test"
        )
        .unwrap();

        let mut args = create_test_check_args(vec![temp_dir.path().to_path_buf()]);
        args.output = Some(output_path.clone());
        let exit_code = run_normal_check_mode(&args);
        assert_eq!(exit_code, ExitCode::SUCCESS);
        assert!(output_path.exists());
    }

    #[test]
    fn test_run_normal_check_mode_with_strict() {
        let temp_dir = TempDir::new().unwrap();
        create_test_config(temp_dir.path());
        let file_path = temp_dir.path().join("SKILL.md");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            "---\nname: test\ndescription: Test skill\n---\n# Test"
        )
        .unwrap();

        let mut args = create_test_check_args(vec![temp_dir.path().to_path_buf()]);
        args.strict = true;
        let exit_code = run_normal_check_mode(&args);
        // Should succeed with no findings
        assert_eq!(exit_code, ExitCode::SUCCESS);
    }

    #[test]
    fn test_run_normal_check_mode_with_baseline() {
        let temp_dir = TempDir::new().unwrap();
        create_test_config(temp_dir.path());
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

        let mut args = create_test_check_args(vec![temp_dir.path().to_path_buf()]);
        args.baseline_file = Some(baseline_path);
        let exit_code = run_normal_check_mode(&args);
        assert_eq!(exit_code, ExitCode::SUCCESS);
    }

    #[test]
    fn test_run_normal_check_mode_output_write_fail() {
        let temp_dir = TempDir::new().unwrap();
        create_test_config(temp_dir.path());
        let file_path = temp_dir.path().join("SKILL.md");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            "---\nname: test\ndescription: Test skill\n---\n# Test"
        )
        .unwrap();

        let mut args = create_test_check_args(vec![temp_dir.path().to_path_buf()]);
        // Use a path that should fail to write
        args.output = Some(PathBuf::from("/nonexistent/directory/output.json"));
        let exit_code = run_normal_check_mode(&args);
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
