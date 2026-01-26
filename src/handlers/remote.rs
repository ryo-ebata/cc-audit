//! Remote repository scanning handlers.

use crate::remote::{AWESOME_CLAUDE_CODE_URL, GitCloner};
use crate::{Cli, ClonedRepo, OutputFormat, run_scan};
use colored::Colorize;
use std::fs;
use std::io::{BufRead, BufReader};
use std::process::ExitCode;

use super::run_normal_mode;

/// Handle --remote command: scan a single remote repository.
pub fn handle_remote_scan(cli: &Cli) -> ExitCode {
    let url = match &cli.remote {
        Some(u) => u,
        None => {
            eprintln!("Error: --remote requires a URL");
            return ExitCode::from(2);
        }
    };

    println!("Cloning repository: {}", url);

    // Create cloner with optional authentication
    let cloner = if let Some(ref token) = cli.remote_auth {
        GitCloner::new().with_auth_token(Some(token.clone()))
    } else {
        GitCloner::new()
    };

    // Clone the repository
    let cloned: ClonedRepo = match cloner.clone(url, &cli.git_ref) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to clone repository: {}", e);
            return ExitCode::from(2);
        }
    };

    println!("Scanning: {}", cloned.path().display());

    // Create a new CLI for scanning the cloned repo
    let scan_cli = Cli {
        paths: vec![cloned.path().to_path_buf()],
        scan_type: cli.scan_type,
        format: cli.format,
        strict: cli.strict,
        warn_only: cli.warn_only,
        min_severity: cli.min_severity,
        min_rule_severity: cli.min_rule_severity,
        verbose: cli.verbose,
        recursive: true, // Always recursive for remote repos
        ci: cli.ci,
        include_tests: cli.include_tests,
        include_node_modules: cli.include_node_modules,
        include_vendor: cli.include_vendor,
        min_confidence: cli.min_confidence,
        watch: false, // No watch mode for remote
        init_hook: false,
        remove_hook: false,
        skip_comments: cli.skip_comments,
        strict_secrets: cli.strict_secrets,
        fix_hint: cli.fix_hint,
        no_malware_scan: cli.no_malware_scan,
        cve_db: cli.cve_db.clone(),
        no_cve_scan: cli.no_cve_scan,
        malware_db: cli.malware_db.clone(),
        custom_rules: cli.custom_rules.clone(),
        baseline: false,
        check_drift: false,
        init: false,
        output: cli.output.clone(),
        save_baseline: None,
        baseline_file: cli.baseline_file.clone(),
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
        remote: None, // Don't recurse into remote
        git_ref: cli.git_ref.clone(),
        remote_auth: cli.remote_auth.clone(),
        remote_list: None,
        awesome_claude_code: false,
        parallel_clones: cli.parallel_clones,
        badge: cli.badge,
        badge_format: cli.badge_format,
        summary: cli.summary,
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
    };

    // Run the scan
    run_normal_mode(&scan_cli)
}

/// Handle --remote-list command: scan multiple repositories from a file.
pub fn handle_remote_list_scan(cli: &Cli) -> ExitCode {
    let list_path = match &cli.remote_list {
        Some(p) => p,
        None => {
            eprintln!("Error: --remote-list requires a file path");
            return ExitCode::from(2);
        }
    };

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

    let cloner = if let Some(ref token) = cli.remote_auth {
        GitCloner::new().with_auth_token(Some(token.clone()))
    } else {
        GitCloner::new()
    };

    let mut total_findings = 0;
    let mut failed_count = 0;

    for (i, url) in urls.iter().enumerate() {
        println!("\n[{}/{}] Scanning: {}", i + 1, urls.len(), url);

        match cloner.clone(url, &cli.git_ref) {
            Ok(cloned) => {
                let cloned: ClonedRepo = cloned;
                let scan_cli = Cli {
                    paths: vec![cloned.path().to_path_buf()],
                    scan_type: cli.scan_type,
                    format: OutputFormat::Terminal, // Always terminal for batch
                    strict: cli.strict,
                    warn_only: cli.warn_only,
                    min_severity: cli.min_severity,
                    min_rule_severity: cli.min_rule_severity,
                    verbose: cli.verbose,
                    recursive: true,
                    ci: false,
                    include_tests: cli.include_tests,
                    include_node_modules: cli.include_node_modules,
                    include_vendor: cli.include_vendor,
                    min_confidence: cli.min_confidence,
                    watch: false,
                    init_hook: false,
                    remove_hook: false,
                    skip_comments: cli.skip_comments,
                    strict_secrets: cli.strict_secrets,
                    fix_hint: false,
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
                    remote: None,
                    git_ref: cli.git_ref.clone(),
                    remote_auth: cli.remote_auth.clone(),
                    remote_list: None,
                    awesome_claude_code: false,
                    parallel_clones: cli.parallel_clones,
                    badge: false,
                    badge_format: cli.badge_format,
                    summary: false,
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
                };

                if let Some(result) = run_scan(&scan_cli) {
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
pub fn handle_awesome_claude_code_scan(cli: &Cli) -> ExitCode {
    println!("Fetching awesome-claude-code repository...");

    let cloner = if let Some(ref token) = cli.remote_auth {
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
                let scan_cli = Cli {
                    paths: vec![cloned.path().to_path_buf()],
                    scan_type: cli.scan_type,
                    format: OutputFormat::Terminal,
                    strict: cli.strict,
                    warn_only: cli.warn_only,
                    min_severity: cli.min_severity,
                    min_rule_severity: cli.min_rule_severity,
                    verbose: cli.verbose,
                    recursive: true,
                    ci: false,
                    include_tests: cli.include_tests,
                    include_node_modules: cli.include_node_modules,
                    include_vendor: cli.include_vendor,
                    min_confidence: cli.min_confidence,
                    watch: false,
                    init_hook: false,
                    remove_hook: false,
                    skip_comments: cli.skip_comments,
                    strict_secrets: cli.strict_secrets,
                    fix_hint: false,
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
                    remote: None,
                    git_ref: "HEAD".to_string(),
                    remote_auth: cli.remote_auth.clone(),
                    remote_list: None,
                    awesome_claude_code: false,
                    parallel_clones: cli.parallel_clones,
                    badge: false,
                    badge_format: cli.badge_format,
                    summary: false,
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
                };

                if let Some(result) = run_scan(&scan_cli) {
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

    if cli.summary {
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
