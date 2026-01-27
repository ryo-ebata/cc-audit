//! Compare handler for comparing scan results between directories.

use crate::{Cli, run_scan};
use colored::Colorize;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;

/// Handle --compare command.
pub fn handle_compare(cli: &Cli, paths: &[PathBuf]) -> ExitCode {
    if paths.len() != 2 {
        eprintln!("Error: --compare requires exactly 2 paths");
        return ExitCode::from(2);
    }

    let path1 = &paths[0];
    let path2 = &paths[1];

    println!("Comparing {} vs {}\n", path1.display(), path2.display());

    // Create CLI for scanning with same options but different paths
    let create_scan_cli = |path: PathBuf| -> Cli {
        Cli {
            paths: vec![path],
            remote: None,
            git_ref: "HEAD".to_string(),
            remote_auth: None,
            remote_list: None,
            awesome_claude_code: false,
            parallel_clones: 4,
            badge: false,
            badge_format: cli.badge_format,
            summary: false,
            format: cli.format,
            strict: cli.strict,
            warn_only: cli.warn_only,
            min_severity: cli.min_severity,
            min_rule_severity: cli.min_rule_severity,
            scan_type: cli.scan_type,
            recursive: cli.recursive,
            ci: cli.ci,
            verbose: cli.verbose,
            include_tests: cli.include_tests,
            include_node_modules: cli.include_node_modules,
            include_vendor: cli.include_vendor,
            min_confidence: cli.min_confidence,
            watch: false,
            init_hook: false,
            remove_hook: false,
            skip_comments: cli.skip_comments,
            strict_secrets: cli.strict_secrets,
            fix_hint: cli.fix_hint,
            compact: cli.compact,
            no_malware_scan: cli.no_malware_scan,
            cve_db: cli.cve_db.clone(),
            no_cve_scan: cli.no_cve_scan,
            malware_db: cli.malware_db.clone(),
            custom_rules: cli.custom_rules.clone(),
            baseline: false,
            check_drift: false,
            init: false,
            output: None,
            save_baseline: None,
            baseline_file: None,
            compare: None,
            fix: false,
            fix_dry_run: false,
            mcp_server: false,
            hook_mode: false,
            pin: false,
            pin_verify: false,
            pin_update: false,
            pin_force: false,
            ignore_pin: false,
            deep_scan: cli.deep_scan,
            profile: cli.profile.clone(),
            save_profile: None,
            all_clients: false,
            client: None,
            report_fp: false,
            report_fp_dry_run: false,
            report_fp_endpoint: None,
            no_telemetry: cli.no_telemetry,
            sbom: false,
            sbom_format: None,
            sbom_npm: false,
            sbom_cargo: false,
            proxy: false,
            proxy_port: None,
            proxy_target: None,
            proxy_tls: false,
            proxy_block: false,
            proxy_log: None,
        }
    };

    // Scan both paths
    let cli1 = create_scan_cli(path1.clone());
    let result1 = match run_scan(&cli1) {
        Some(r) => r,
        None => {
            eprintln!("Failed to scan {}", path1.display());
            return ExitCode::from(2);
        }
    };

    let cli2 = create_scan_cli(path2.clone());
    let result2 = match run_scan(&cli2) {
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
