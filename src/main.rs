use cc_audit::{
    Baseline, Cli, Config, HookInstaller, WatchModeResult, format_result, run_scan,
    setup_watch_mode, watch_iteration,
};
use clap::Parser;
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

    // Handle baseline creation
    if cli.baseline {
        return handle_baseline(&cli);
    }

    // Handle drift detection
    if cli.check_drift {
        return handle_check_drift(&cli);
    }

    if cli.watch {
        return run_watch_mode(&cli);
    }

    // Normal mode
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
        Some(result) => {
            println!("{}", format_result(cli, &result));

            if result.summary.passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        None => ExitCode::from(2),
    }
}
