//! Remote repository scanning handlers.

use crate::remote::{AWESOME_CLAUDE_CODE_URL, GitCloner};
use crate::run::EffectiveConfig;
use crate::{CheckArgs, ClonedRepo, Config, run_scan_with_check_args};
use colored::Colorize;
use std::fs;
use std::io::{BufRead, BufReader};
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
    let scan_args = args.for_scan(vec![cloned.path().to_path_buf()], &effective);

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
                let scan_args = args.for_batch_scan(vec![cloned.path().to_path_buf()], &effective);

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
                let scan_args = args.for_batch_scan(vec![cloned.path().to_path_buf()], &effective);

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
