//! Compare handler for comparing scan results between directories.

use crate::run::EffectiveConfig;
use crate::{CheckArgs, Config, run_scan_with_check_args};
use colored::Colorize;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;

/// Handle --compare command.
pub fn handle_compare(args: &CheckArgs, paths: &[PathBuf]) -> ExitCode {
    if paths.len() != 2 {
        eprintln!("Error: --compare requires exactly 2 paths");
        return ExitCode::from(2);
    }

    let path1 = &paths[0];
    let path2 = &paths[1];

    println!("Comparing {} vs {}\n", path1.display(), path2.display());

    // Load config from first path to get effective settings
    let project_root = if path1.is_dir() {
        Some(path1.as_path())
    } else {
        path1.parent()
    };
    let config = Config::load(project_root);
    let effective = EffectiveConfig::from_check_args_and_config(args, &config);

    // Create CheckArgs for scanning with same options but different paths
    let create_scan_args = |path: PathBuf| -> CheckArgs {
        CheckArgs {
            paths: vec![path],
            config: args.config.clone(),
            remote: None,
            git_ref: effective.git_ref.clone(),
            remote_auth: effective.remote_auth.clone(),
            remote_list: None,
            awesome_claude_code: false,
            parallel_clones: effective.parallel_clones,
            badge: effective.badge,
            badge_format: effective.badge_format,
            summary: false,
            format: effective.format,
            strict: effective.strict,
            warn_only: effective.warn_only,
            min_severity: effective.min_severity,
            min_rule_severity: effective.min_rule_severity,
            scan_type: effective.scan_type,
            no_recursive: !effective.recursive,
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
    };

    // Scan both paths
    let args1 = create_scan_args(path1.clone());
    let result1 = match run_scan_with_check_args(&args1) {
        Some(r) => r,
        None => {
            eprintln!("Failed to scan {}", path1.display());
            return ExitCode::from(2);
        }
    };

    let args2 = create_scan_args(path2.clone());
    let result2 = match run_scan_with_check_args(&args2) {
        Some(r) => r,
        None => {
            eprintln!("Failed to scan {}", path2.display());
            return ExitCode::from(2);
        }
    };

    // Compare findings
    let findings1: HashSet<_> = result1
        .findings
        .iter()
        .map(|f| (&f.id, &f.message))
        .collect();
    let findings2: HashSet<_> = result2
        .findings
        .iter()
        .map(|f| (&f.id, &f.message))
        .collect();

    let only_in_1: Vec<_> = result1
        .findings
        .iter()
        .filter(|f| !findings2.contains(&(&f.id, &f.message)))
        .collect();
    let only_in_2: Vec<_> = result2
        .findings
        .iter()
        .filter(|f| !findings1.contains(&(&f.id, &f.message)))
        .collect();

    if only_in_1.is_empty() && only_in_2.is_empty() {
        println!("{}", "No differences found.".green());
        return ExitCode::SUCCESS;
    }

    if !only_in_1.is_empty() {
        println!(
            "{}",
            format!(
                "Only in {} ({} findings):",
                path1.display(),
                only_in_1.len()
            )
            .yellow()
            .bold()
        );
        for f in &only_in_1 {
            println!("  {} [{}] {}", "-".red(), f.id, f.message);
        }
        println!();
    }

    if !only_in_2.is_empty() {
        println!(
            "{}",
            format!(
                "Only in {} ({} findings):",
                path2.display(),
                only_in_2.len()
            )
            .yellow()
            .bold()
        );
        for f in &only_in_2 {
            println!("  {} [{}] {}", "+".green(), f.id, f.message);
        }
        println!();
    }

    println!(
        "Summary: {} removed, {} added",
        only_in_1.len(),
        only_in_2.len()
    );

    ExitCode::from(1)
}
