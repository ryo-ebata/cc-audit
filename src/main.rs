use cc_audit::{
    Cli, HookInstaller, WatchModeResult, format_result, run_scan, setup_watch_mode, watch_iteration,
};
use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();

    // Handle hook installation/removal
    if cli.init_hook {
        return handle_init_hook(&cli);
    }

    if cli.remove_hook {
        return handle_remove_hook(&cli);
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
