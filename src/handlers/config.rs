//! Configuration and profile management handlers.

use crate::{Cli, Config, Profile, profile_from_cli};
use std::fs;
use std::path::Path;
use std::process::ExitCode;

/// Handle `init` subcommand.
pub fn handle_init_config(path: &Path) -> ExitCode {
    let output_path = if path.is_dir() {
        path.join(".cc-audit.yaml")
    } else {
        path.to_path_buf()
    };

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

/// Handle --save-profile command.
pub fn handle_save_profile(cli: &Cli, profile_name: &str) -> ExitCode {
    // Create profile from current CLI settings
    let profile = profile_from_cli(profile_name, cli);

    match profile.save() {
        Ok(path) => {
            println!("Profile '{}' saved to {}", profile_name, path.display());
            println!("\nUse --profile {} to load these settings.", profile_name);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Failed to save profile: {}", e);
            ExitCode::from(2)
        }
    }
}

/// Handle showing a profile.
pub fn handle_show_profile(profile_name: &str) -> ExitCode {
    match Profile::load(profile_name) {
        Ok(profile) => {
            println!("Profile: {}", profile.name);
            println!("Description: {}", profile.description);
            println!("\nSettings:");
            if let Some(format) = &profile.format {
                println!("  format: {}", format);
            }
            if profile.strict {
                println!("  strict: true");
            }
            if profile.verbose {
                println!("  verbose: true");
            }
            if profile.recursive {
                println!("  recursive: true");
            }
            if profile.ci {
                println!("  ci: true");
            }
            if let Some(scan_type) = &profile.scan_type {
                println!("  scan_type: {}", scan_type);
            }
            if !profile.min_confidence.is_empty() {
                println!("  min_confidence: {}", profile.min_confidence);
            }
            if profile.fix_hint {
                println!("  fix_hint: true");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Failed to load profile '{}': {}", profile_name, e);
            ExitCode::from(2)
        }
    }
}
