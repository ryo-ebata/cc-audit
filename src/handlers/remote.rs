//! Remote repository scanning handlers.

use crate::remote::{AWESOME_CLAUDE_CODE_URL, GitCloner};
use crate::run::EffectiveConfig;
use crate::{BadgeFormat, CheckArgs, ClonedRepo, Config, OutputFormat, run_scan_with_check_args};
use colored::Colorize;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::ExitCode;

use super::run_normal_check_mode;

/// Handle --remote command: scan a single remote repository.
pub fn handle_remote_scan(args: &CheckArgs) -> ExitCode {
    let url = match &args.remote {
        Some(u) => u,
        None => {
            eprintln!("Error: --remote requires a URL");
            return ExitCode::from(2);
        }
    };

    // Load config from current directory to get effective settings
    let config = Config::load(Some(std::path::Path::new(".")));
    let effective = EffectiveConfig::from_check_args_and_config(args, &config);

    println!("Cloning repository: {}", url);

    // Create cloner with optional authentication (use effective config for auth)
    let cloner = if let Some(ref token) = effective.remote_auth {
        GitCloner::new().with_auth_token(Some(token.clone()))
    } else {
        GitCloner::new()
    };

    // Clone the repository (use effective config for git_ref)
    let cloned: ClonedRepo = match cloner.clone(url, &effective.git_ref) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to clone repository: {}", e);
            return ExitCode::from(2);
        }
    };

    println!("Scanning: {}", cloned.path().display());

    // Create CheckArgs for scanning the cloned repo
    let scan_args = create_scan_check_args(vec![cloned.path().to_path_buf()], args, &effective);

    // Run the scan
    run_normal_check_mode(&scan_args)
}

/// Handle --remote-list command: scan multiple repositories from a file.
pub fn handle_remote_list_scan(args: &CheckArgs) -> ExitCode {
    let list_path = match &args.remote_list {
        Some(p) => p,
        None => {
            eprintln!("Error: --remote-list requires a file path");
            return ExitCode::from(2);
        }
    };

    // Load config from current directory to get effective settings
    let config = Config::load(Some(std::path::Path::new(".")));
    let effective = EffectiveConfig::from_check_args_and_config(args, &config);

    // Read URLs from file
    let file = match fs::File::open(list_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open URL list file: {}", e);
            return ExitCode::from(2);
        }
    };

    let reader = BufReader::new(file);
    let urls: Vec<String> = reader
        .lines()
        .map_while(Result::ok)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    if urls.is_empty() {
        eprintln!("No URLs found in {}", list_path.display());
        return ExitCode::from(2);
    }

    println!("Found {} repositories to scan", urls.len());

    let cloner = if let Some(ref token) = effective.remote_auth {
        GitCloner::new().with_auth_token(Some(token.clone()))
    } else {
        GitCloner::new()
    };

    let mut total_findings = 0;
    let mut failed_count = 0;

    for (i, url) in urls.iter().enumerate() {
        println!("\n[{}/{}] Scanning: {}", i + 1, urls.len(), url);

        match cloner.clone(url, &effective.git_ref) {
            Ok(cloned) => {
                let cloned: ClonedRepo = cloned;
                let scan_args = create_scan_check_args_batch(
                    vec![cloned.path().to_path_buf()],
                    args,
                    &effective,
                );

                if let Some(result) = run_scan_with_check_args(&scan_args) {
                    let count = result.summary.critical
                        + result.summary.high
                        + result.summary.medium
                        + result.summary.low;
                    total_findings += count;
                    println!(
                        "  {} {} findings ({} critical, {} high, {} medium, {} low)",
                        if count > 0 {
                            "⚠".yellow()
                        } else {
                            "✓".green()
                        },
                        count,
                        result.summary.critical,
                        result.summary.high,
                        result.summary.medium,
                        result.summary.low
                    );
                } else {
                    failed_count += 1;
                    eprintln!("  {} Scan failed", "✗".red());
                }
            }
            Err(e) => {
                failed_count += 1;
                eprintln!("  {} Clone failed: {}", "✗".red(), e);
            }
        }
    }

    println!("\n{}", "═".repeat(50));
    println!(
        "Summary: {} repos scanned, {} total findings, {} failed",
        urls.len() - failed_count,
        total_findings,
        failed_count
    );

    if total_findings > 0 || failed_count > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Handle --awesome-claude-code command: scan awesome-claude-code repository links.
pub fn handle_awesome_claude_code_scan(args: &CheckArgs) -> ExitCode {
    println!("Fetching awesome-claude-code repository...");

    // Load config from current directory to get effective settings
    let config = Config::load(Some(std::path::Path::new(".")));
    let effective = EffectiveConfig::from_check_args_and_config(args, &config);

    let cloner = if let Some(ref token) = effective.remote_auth {
        GitCloner::new().with_auth_token(Some(token.clone()))
    } else {
        GitCloner::new()
    };

    // Clone awesome-claude-code to get the README
    let awesome_repo: ClonedRepo = match cloner.clone(AWESOME_CLAUDE_CODE_URL, "HEAD") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to clone awesome-claude-code: {}", e);
            return ExitCode::from(2);
        }
    };

    // Parse README.md for GitHub URLs
    let readme_path = awesome_repo.path().join("README.md");
    let readme_content = match fs::read_to_string(&readme_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to read README.md: {}", e);
            return ExitCode::from(2);
        }
    };

    // Extract GitHub URLs from markdown
    let github_url_pattern =
        regex::Regex::new(r"https://github\.com/[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+")
            .expect("Invalid regex");

    let urls: Vec<String> = github_url_pattern
        .find_iter(&readme_content)
        .map(|m| m.as_str().to_string())
        .filter(|url| !url.contains("anthropics/awesome-claude-code")) // Exclude self
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    if urls.is_empty() {
        eprintln!("No GitHub URLs found in awesome-claude-code README");
        return ExitCode::from(2);
    }

    println!("Found {} repositories to scan", urls.len());

    let mut total_findings = 0;
    let mut failed_count = 0;
    let mut results: Vec<(String, usize, usize, usize, usize, usize)> = Vec::new();

    for (i, url) in urls.iter().enumerate() {
        println!("\n[{}/{}] Scanning: {}", i + 1, urls.len(), url);

        match cloner.clone(url, "HEAD") {
            Ok(cloned) => {
                let cloned: ClonedRepo = cloned;
                let scan_args = create_scan_check_args_batch(
                    vec![cloned.path().to_path_buf()],
                    args,
                    &effective,
                );

                if let Some(result) = run_scan_with_check_args(&scan_args) {
                    let count = result.summary.critical
                        + result.summary.high
                        + result.summary.medium
                        + result.summary.low;
                    total_findings += count;
                    results.push((
                        url.clone(),
                        count,
                        result.summary.critical,
                        result.summary.high,
                        result.summary.medium,
                        result.summary.low,
                    ));
                    println!(
                        "  {} {} findings ({} critical, {} high, {} medium, {} low)",
                        if count > 0 {
                            "⚠".yellow()
                        } else {
                            "✓".green()
                        },
                        count,
                        result.summary.critical,
                        result.summary.high,
                        result.summary.medium,
                        result.summary.low
                    );
                } else {
                    failed_count += 1;
                    eprintln!("  {} Scan failed", "✗".red());
                }
            }
            Err(e) => {
                failed_count += 1;
                eprintln!("  {} Clone failed: {}", "✗".red(), e);
            }
        }
    }

    // Print summary
    println!("\n{}", "═".repeat(60));
    println!(
        "{} Summary: {} repos scanned, {} total findings, {} failed {}",
        "".bold(),
        urls.len() - failed_count,
        total_findings,
        failed_count,
        "".bold()
    );

    if effective.summary {
        println!("\n{}", "Repository Results:".bold());
        println!("{:-<60}", "");

        // Sort by total findings (descending)
        let mut sorted_results = results.clone();
        sorted_results.sort_by(|a, b| b.1.cmp(&a.1));

        for (url, _total, critical, high, medium, low) in sorted_results {
            let status = if critical > 0 || high > 0 {
                "FAIL".red().bold()
            } else if medium > 0 || low > 0 {
                "WARN".yellow()
            } else {
                "PASS".green()
            };
            println!(
                "{} {} (C:{} H:{} M:{} L:{})",
                status,
                url.replace("https://github.com/", ""),
                critical,
                high,
                medium,
                low
            );
        }
    }

    if total_findings > 0 || failed_count > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Create CheckArgs for scanning with all settings inherited from original args.
fn create_scan_check_args(
    paths: Vec<PathBuf>,
    args: &CheckArgs,
    effective: &EffectiveConfig,
) -> CheckArgs {
    CheckArgs {
        paths,
        config: args.config.clone(),
        remote: None, // Don't recurse into remote
        git_ref: effective.git_ref.clone(),
        remote_auth: effective.remote_auth.clone(),
        remote_list: None,
        awesome_claude_code: false,
        parallel_clones: effective.parallel_clones,
        badge: effective.badge,
        badge_format: effective.badge_format,
        summary: effective.summary,
        format: effective.format,
        strict: effective.strict,
        warn_only: effective.warn_only,
        min_severity: effective.min_severity,
        min_rule_severity: effective.min_rule_severity,
        scan_type: effective.scan_type,
        no_recursive: false, // Always recursive for remote repos
        ci: effective.ci,
        min_confidence: Some(effective.min_confidence),
        watch: false,
        skip_comments: effective.skip_comments,
        strict_secrets: effective.strict_secrets,
        fix_hint: effective.fix_hint,
        compact: effective.compact,
        no_malware_scan: effective.no_malware_scan,
        cve_db: effective.cve_db.as_ref().map(PathBuf::from),
        no_cve_scan: effective.no_cve_scan,
        malware_db: effective.malware_db.as_ref().map(PathBuf::from),
        custom_rules: effective.custom_rules.as_ref().map(PathBuf::from),
        baseline: false,
        check_drift: false,
        output: effective.output.as_ref().map(PathBuf::from),
        save_baseline: None,
        baseline_file: args.baseline_file.clone(),
        compare: None,
        fix: false,
        fix_dry_run: false,
        pin: false,
        pin_verify: false,
        pin_update: false,
        pin_force: false,
        ignore_pin: false,
        deep_scan: effective.deep_scan,
        profile: args.profile.clone(),
        save_profile: None,
        all_clients: false,
        client: None,
        report_fp: false,
        report_fp_dry_run: false,
        report_fp_endpoint: None,
        no_telemetry: args.no_telemetry,
        sbom: false,
        sbom_format: None,
        sbom_npm: false,
        sbom_cargo: false,
        hook_mode: false,
    }
}

/// Create CheckArgs for batch scanning (simplified settings).
fn create_scan_check_args_batch(
    paths: Vec<PathBuf>,
    args: &CheckArgs,
    effective: &EffectiveConfig,
) -> CheckArgs {
    CheckArgs {
        paths,
        config: args.config.clone(),
        remote: None,
        git_ref: effective.git_ref.clone(),
        remote_auth: effective.remote_auth.clone(),
        remote_list: None,
        awesome_claude_code: false,
        parallel_clones: effective.parallel_clones,
        badge: false, // No badge for batch
        badge_format: BadgeFormat::Markdown,
        summary: false,                 // No summary in batch items
        format: OutputFormat::Terminal, // Always terminal for batch
        strict: effective.strict,
        warn_only: effective.warn_only,
        min_severity: effective.min_severity,
        min_rule_severity: effective.min_rule_severity,
        scan_type: effective.scan_type,
        no_recursive: false, // Always recursive
        ci: false,           // No CI mode in batch
        min_confidence: Some(effective.min_confidence),
        watch: false,
        skip_comments: effective.skip_comments,
        strict_secrets: effective.strict_secrets,
        fix_hint: false, // No fix hints in batch
        compact: effective.compact,
        no_malware_scan: effective.no_malware_scan,
        cve_db: effective.cve_db.as_ref().map(PathBuf::from),
        no_cve_scan: effective.no_cve_scan,
        malware_db: effective.malware_db.as_ref().map(PathBuf::from),
        custom_rules: effective.custom_rules.as_ref().map(PathBuf::from),
        baseline: false,
        check_drift: false,
        output: None,
        save_baseline: None,
        baseline_file: None,
        compare: None,
        fix: false,
        fix_dry_run: false,
        pin: false,
        pin_verify: false,
        pin_update: false,
        pin_force: false,
        ignore_pin: false,
        deep_scan: effective.deep_scan,
        profile: args.profile.clone(),
        save_profile: None,
        all_clients: false,
        client: None,
        report_fp: false,
        report_fp_dry_run: false,
        report_fp_endpoint: None,
        no_telemetry: args.no_telemetry,
        sbom: false,
        sbom_format: None,
        sbom_npm: false,
        sbom_cargo: false,
        hook_mode: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Confidence;
    use crate::cli::ScanType;
    use std::io::Write;
    use tempfile::TempDir;

    /// Helper to create minimal CheckArgs for testing
    fn create_test_check_args(paths: Vec<PathBuf>) -> CheckArgs {
        CheckArgs {
            paths,
            config: None,
            remote: None,
            git_ref: "HEAD".to_string(),
            remote_auth: None,
            remote_list: None,
            awesome_claude_code: false,
            parallel_clones: 1,
            badge: false,
            badge_format: BadgeFormat::Markdown,
            summary: false,
            format: OutputFormat::Terminal,
            strict: false,
            warn_only: false,
            min_severity: None,
            min_rule_severity: None,
            scan_type: ScanType::Skill,
            no_recursive: false,
            ci: false,
            min_confidence: None,
            watch: false,
            skip_comments: false,
            strict_secrets: false,
            fix_hint: false,
            compact: false,
            no_malware_scan: false,
            cve_db: None,
            no_cve_scan: false,
            malware_db: None,
            custom_rules: None,
            baseline: false,
            check_drift: false,
            output: None,
            save_baseline: None,
            baseline_file: None,
            compare: None,
            fix: false,
            fix_dry_run: false,
            pin: false,
            pin_verify: false,
            pin_update: false,
            pin_force: false,
            ignore_pin: false,
            deep_scan: false,
            profile: None,
            save_profile: None,
            all_clients: false,
            client: None,
            report_fp: false,
            report_fp_dry_run: false,
            report_fp_endpoint: None,
            no_telemetry: false,
            sbom: false,
            sbom_format: None,
            sbom_npm: false,
            sbom_cargo: false,
            hook_mode: false,
        }
    }

    #[test]
    fn test_handle_remote_scan_missing_url() {
        let args = create_test_check_args(vec![]);
        let exit_code = handle_remote_scan(&args);
        assert_eq!(
            exit_code,
            ExitCode::from(2),
            "Should return error code when URL is missing"
        );
    }

    #[test]
    fn test_handle_remote_list_scan_missing_file() {
        let args = create_test_check_args(vec![]);
        let exit_code = handle_remote_list_scan(&args);
        assert_eq!(
            exit_code,
            ExitCode::from(2),
            "Should return error code when file path is missing"
        );
    }

    #[test]
    fn test_handle_remote_list_scan_file_not_found() {
        let mut args = create_test_check_args(vec![]);
        args.remote_list = Some(PathBuf::from("/nonexistent/urls.txt"));

        let exit_code = handle_remote_list_scan(&args);
        assert_eq!(
            exit_code,
            ExitCode::from(2),
            "Should return error code when file doesn't exist"
        );
    }

    #[test]
    fn test_handle_remote_list_scan_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let list_file = temp_dir.path().join("empty.txt");
        fs::write(&list_file, "").unwrap();

        let mut args = create_test_check_args(vec![]);
        args.remote_list = Some(list_file);

        let exit_code = handle_remote_list_scan(&args);
        assert_eq!(
            exit_code,
            ExitCode::from(2),
            "Should return error code when no URLs found"
        );
    }

    #[test]
    fn test_handle_remote_list_scan_only_comments() {
        let temp_dir = TempDir::new().unwrap();
        let list_file = temp_dir.path().join("comments.txt");

        let mut file = fs::File::create(&list_file).unwrap();
        writeln!(file, "# This is a comment").unwrap();
        writeln!(file, "# Another comment").unwrap();
        writeln!(file).unwrap();
        writeln!(file, "   ").unwrap();

        let mut args = create_test_check_args(vec![]);
        args.remote_list = Some(list_file);

        let exit_code = handle_remote_list_scan(&args);
        assert_eq!(
            exit_code,
            ExitCode::from(2),
            "Should return error code when only comments/empty lines"
        );
    }

    #[test]
    fn test_create_scan_check_args_inherits_settings() {
        let mut base_args = create_test_check_args(vec![]);
        base_args.strict = true;
        base_args.skip_comments = true;
        base_args.min_confidence = Some(Confidence::Certain);

        let effective = EffectiveConfig::from_check_args_and_config(&base_args, &Config::default());

        let scan_args =
            create_scan_check_args(vec![PathBuf::from("/test/path")], &base_args, &effective);

        assert_eq!(scan_args.paths, vec![PathBuf::from("/test/path")]);
        assert!(scan_args.strict, "Should inherit strict mode");
        assert!(scan_args.skip_comments, "Should inherit skip_comments");
        assert_eq!(
            scan_args.min_confidence,
            Some(Confidence::Certain),
            "Should inherit min_confidence"
        );
        assert!(scan_args.remote.is_none(), "Should not recurse into remote");
    }

    #[test]
    fn test_create_scan_check_args_batch_simplifies_settings() {
        let mut base_args = create_test_check_args(vec![]);
        base_args.badge = true;
        base_args.summary = true;
        base_args.ci = true;
        base_args.fix_hint = true;

        let effective = EffectiveConfig::from_check_args_and_config(&base_args, &Config::default());

        let batch_args =
            create_scan_check_args_batch(vec![PathBuf::from("/test/path")], &base_args, &effective);

        assert!(!batch_args.badge, "Should disable badge in batch");
        assert!(!batch_args.summary, "Should disable summary in batch");
        assert!(!batch_args.ci, "Should disable CI mode in batch");
        assert!(!batch_args.fix_hint, "Should disable fix_hint in batch");
        assert_eq!(
            batch_args.format,
            OutputFormat::Terminal,
            "Should use terminal format in batch"
        );
    }

    #[test]
    fn test_create_scan_check_args_no_recursive_always_false() {
        let mut base_args = create_test_check_args(vec![]);
        base_args.no_recursive = true; // User wants no recursion

        let effective = EffectiveConfig::from_check_args_and_config(&base_args, &Config::default());

        let scan_args =
            create_scan_check_args(vec![PathBuf::from("/test/path")], &base_args, &effective);

        assert!(
            !scan_args.no_recursive,
            "Should always be recursive for remote repos"
        );
    }
}
