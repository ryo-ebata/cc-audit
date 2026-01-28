//! Git hook management handlers.

use crate::{HookAction, HookInstaller};
use std::path::Path;
use std::process::ExitCode;

/// Handle `cc-audit hook <init|remove>` subcommand.
pub fn handle_hook(action: HookAction) -> ExitCode {
    match action {
        HookAction::Init { path } => handle_init_hook_path(&path),
        HookAction::Remove { path } => handle_remove_hook_path(&path),
    }
}

/// Handle `cc-audit hook init [path]`.
fn handle_init_hook_path(path: &Path) -> ExitCode {
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

/// Handle `cc-audit hook remove [path]`.
fn handle_remove_hook_path(path: &Path) -> ExitCode {
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
