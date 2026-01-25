use cc_audit::{
    AutoFixer, Baseline, Cli, Config, HookInstaller, McpServer, Profile, ScanResult,
    WatchModeResult, format_result, profile_from_cli, run_scan, setup_watch_mode, watch_iteration,
};
use clap::Parser;
use colored::Colorize;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Handle config initialization
    if cli.init {
        return handle_init_config(&cli);
    }

    // Handle hook installation/removal
    if cli.init_hook {
        return handle_init_hook(&cli);
    }

    if cli.remove_hook {
        return handle_remove_hook(&cli);
    }

    // Handle --save-baseline <file>
    if let Some(ref baseline_path) = cli.save_baseline {
        return handle_save_baseline(&cli, baseline_path);
    }

    // Handle baseline creation (legacy --baseline)
    if cli.baseline {
        return handle_baseline(&cli);
    }

    // Handle drift detection
    if cli.check_drift {
        return handle_check_drift(&cli);
    }

    // Handle --compare <path1> <path2>
    if let Some(ref paths) = cli.compare {
        return handle_compare(&cli, paths);
    }

    // Handle --fix or --fix-dry-run
    if cli.fix || cli.fix_dry_run {
        return handle_fix(&cli);
    }

    // Handle --mcp-server
    if cli.mcp_server {
        return handle_mcp_server();
    }

    // Handle --save-profile
    if let Some(ref profile_name) = cli.save_profile {
        return handle_save_profile(&cli, profile_name);
    }

    // Handle --profile (info mode when no paths to scan)
    if let Some(ref profile_name) = cli.profile {
        // If profile is specified but paths are essentially just ".", show profile info
        if cli.paths.len() == 1 && cli.paths[0].as_os_str() == "." && !cli.paths[0].exists() {
            return handle_show_profile(profile_name);
        }
    }

    if cli.watch {
        return run_watch_mode(&cli);
    }

    // Normal mode (with optional --baseline-file comparison)
    run_normal_mode(&cli)
}

fn handle_init_hook(cli: &Cli) -> ExitCode {
    let path = cli
        .paths
        .first()
        .map(|p| p.as_path())
        .unwrap_or_else(|| std::path::Path::new("."));
    match HookInstaller::install(path) {
        Ok(()) => {
            println!("Pre-commit hook installed successfully.");
            println!("cc-audit will now run automatically before each commit.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Failed to install hook: {}", e);
            ExitCode::from(2)
        }
    }
}

fn handle_remove_hook(cli: &Cli) -> ExitCode {
    let path = cli
        .paths
        .first()
        .map(|p| p.as_path())
        .unwrap_or_else(|| std::path::Path::new("."));
    match HookInstaller::uninstall(path) {
        Ok(()) => {
            println!("Pre-commit hook removed successfully.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Failed to remove hook: {}", e);
            ExitCode::from(2)
        }
    }
}

fn handle_init_config(cli: &Cli) -> ExitCode {
    let output_path = cli
        .paths
        .first()
        .map(|p| {
            if p.is_dir() {
                p.join(".cc-audit.yaml")
            } else {
                p.clone()
            }
        })
        .unwrap_or_else(|| std::path::PathBuf::from(".cc-audit.yaml"));

    // Check if file already exists
    if output_path.exists() {
        eprintln!(
            "Error: Configuration file already exists at {}",
            output_path.display()
        );
        eprintln!("Remove it first or specify a different path.");
        return ExitCode::from(2);
    }

    let template = Config::generate_template();

    match fs::write(&output_path, &template) {
        Ok(()) => {
            println!(
                "Created configuration file template at {}",
                output_path.display()
            );
            println!("\nYou can customize this file to:");
            println!("  - Set default scan options");
            println!("  - Configure ignore patterns");
            println!("  - Add custom rules");
            println!("  - Define malware signatures");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: Failed to write configuration file: {}", e);
            ExitCode::from(2)
        }
    }
}

fn run_watch_mode(cli: &Cli) -> ExitCode {
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

fn handle_baseline(cli: &Cli) -> ExitCode {
    for path in &cli.paths {
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

fn handle_save_baseline(cli: &Cli, baseline_path: &std::path::Path) -> ExitCode {
    // Combine all paths into a single baseline
    let mut combined_hashes = std::collections::HashMap::new();

    for path in &cli.paths {
        match Baseline::from_directory(path) {
            Ok(baseline) => {
                for (file_path, hash) in baseline.file_hashes {
                    let full_path = format!("{}:{}", path.display(), file_path);
                    combined_hashes.insert(full_path, hash);
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

fn handle_mcp_server() -> ExitCode {
    let server = McpServer::new();
    match server.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("MCP server error: {}", e);
            ExitCode::from(2)
        }
    }
}

fn handle_save_profile(cli: &Cli, profile_name: &str) -> ExitCode {
    let profile = profile_from_cli(profile_name, cli);

    match profile.save() {
        Ok(path) => {
            println!(
                "{} Profile '{}' saved to {}",
                "Success:".green().bold(),
                profile_name,
                path.display()
            );
            println!("\nTo use this profile:");
            println!("  cc-audit --profile {} <path>", profile_name);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{} Failed to save profile: {}", "Error:".red().bold(), e);
            ExitCode::from(2)
        }
    }
}

fn handle_show_profile(profile_name: &str) -> ExitCode {
    match Profile::load(profile_name) {
        Ok(profile) => {
            println!("{}", format!("Profile: {}", profile.name).cyan().bold());
            println!("{}\n", profile.description);

            println!("Settings:");
            println!("  strict:          {}", profile.strict);
            println!("  recursive:       {}", profile.recursive);
            println!("  ci:              {}", profile.ci);
            println!("  verbose:         {}", profile.verbose);
            println!("  skip_comments:   {}", profile.skip_comments);
            println!("  fix_hint:        {}", profile.fix_hint);
            println!("  no_malware_scan: {}", profile.no_malware_scan);
            println!("  deep_scan:       {}", profile.deep_scan);
            println!("  min_confidence:  {}", profile.min_confidence);

            if let Some(ref format) = profile.format {
                println!("  format:          {}", format);
            }
            if let Some(ref scan_type) = profile.scan_type {
                println!("  scan_type:       {}", scan_type);
            }

            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{} {}", "Error:".red().bold(), e);
            println!("\nAvailable profiles: {:?}", Profile::list_all());
            ExitCode::from(2)
        }
    }
}

fn handle_fix(cli: &Cli) -> ExitCode {
    let dry_run = cli.fix_dry_run;

    // First, run a scan to get findings
    let result = match run_scan(cli) {
        Some(r) => r,
        None => {
            eprintln!("Failed to scan");
            return ExitCode::from(2);
        }
    };

    if result.findings.is_empty() {
        println!("{}", "No findings to fix.".green());
        return ExitCode::SUCCESS;
    }

    // Generate and apply fixes
    let fixer = AutoFixer::new(dry_run);
    let fixes = fixer.generate_fixes(&result.findings);

    if fixes.is_empty() {
        println!(
            "{}",
            "No auto-fixable issues found. Manual review required.".yellow()
        );
        println!(
            "\nFound {} issues, but none have automatic fixes available.",
            result.findings.len()
        );
        return ExitCode::from(1);
    }

    println!(
        "Found {} fixable issue(s) out of {} total findings.\n",
        fixes.len(),
        result.findings.len()
    );

    let fix_result = fixer.apply_fixes(&fixes);
    println!("{}", fix_result.format_terminal(dry_run));

    if fix_result.errors.is_empty() {
        if dry_run {
            println!("{}", "Run with --fix to apply these changes.".cyan().bold());
        }
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn handle_compare(cli: &Cli, paths: &[std::path::PathBuf]) -> ExitCode {
    if paths.len() != 2 {
        eprintln!("Error: --compare requires exactly 2 paths");
        return ExitCode::from(2);
    }

    let path1 = &paths[0];
    let path2 = &paths[1];

    println!("Comparing {} vs {}\n", path1.display(), path2.display());

    // Create CLI for scanning with same options but different paths
    let create_scan_cli = |path: std::path::PathBuf| -> Cli {
        Cli {
            paths: vec![path],
            format: cli.format,
            strict: cli.strict,
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
            fix_hint: cli.fix_hint,
            no_malware_scan: cli.no_malware_scan,
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
            deep_scan: cli.deep_scan,
            profile: cli.profile.clone(),
            save_profile: None,
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
    use std::collections::HashSet;

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

fn handle_check_drift(cli: &Cli) -> ExitCode {
    let mut has_any_drift = false;

    for path in &cli.paths {
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

    if has_any_drift {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn run_normal_mode(cli: &Cli) -> ExitCode {
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

            if result.summary.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        None => ExitCode::from(2),
    }
}

fn filter_against_baseline(mut result: ScanResult, baseline_path: &std::path::Path) -> ScanResult {
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
    use std::collections::HashSet;
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

    // Recalculate summary
    result.summary = cc_audit::Summary::from_findings(&result.findings);
    if let Some(ref mut risk_score) = result.risk_score {
        *risk_score = cc_audit::RiskScore::from_findings(&result.findings);
    }

    result
}
