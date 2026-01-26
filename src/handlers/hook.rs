//! Git hook management handlers.

use crate::{Cli, HookInstaller};
use std::path::Path;
use std::process::ExitCode;

/// Handle --init-hook command.
pub fn handle_init_hook(cli: &Cli) -> ExitCode {
    let path = cli
        .paths
        .first()
        .map(|p| p.as_path())
        .unwrap_or_else(|| Path::new("."));
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

/// Handle --remove-hook command.
pub fn handle_remove_hook(cli: &Cli) -> ExitCode {
    let path = cli
        .paths
        .first()
        .map(|p| p.as_path())
        .unwrap_or_else(|| Path::new("."));
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
