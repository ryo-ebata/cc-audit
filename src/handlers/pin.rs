//! MCP tool pinning handler.

use crate::cli::Cli;
use crate::pinning::{PINNING_FILENAME, ToolPins};
use colored::Colorize;
use std::path::Path;
use std::process::ExitCode;

/// Handle the `pin` command to create or update pins.
pub fn handle_pin(cli: &Cli) -> ExitCode {
    let target_path = cli
        .paths
        .first()
        .cloned()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    // Find MCP config file
    let mcp_path = find_mcp_config(&target_path);

    if mcp_path.is_none() {
        eprintln!(
            "{} No MCP configuration file found in {}",
            "Error:".red().bold(),
            target_path.display()
        );
        eprintln!(
            "{}",
            "Looked for: mcp.json, .mcp.json, settings.json".dimmed()
        );
        return ExitCode::from(2);
    }

    let mcp_path = mcp_path.unwrap();

    // Check if we're updating existing pins
    if cli.pin_update {
        return handle_pin_update(&target_path, &mcp_path);
    }

    // Check if pins already exist
    if ToolPins::exists(&target_path) && !cli.pin_force {
        eprintln!(
            "{} Pins already exist at {}",
            "Warning:".yellow().bold(),
            target_path.join(PINNING_FILENAME).display()
        );
        eprintln!("{}", "Use --pin-update to update existing pins".dimmed());
        eprintln!("{}", "Use --pin-force to overwrite existing pins".dimmed());
        return ExitCode::from(2);
    }

    // Create new pins
    match ToolPins::from_mcp_config(&mcp_path) {
        Ok(pins) => {
            if let Err(e) = pins.save(&target_path) {
                eprintln!("{} Failed to save pins: {}", "Error:".red().bold(), e);
                return ExitCode::from(2);
            }

            println!(
                "{} Pinned {} MCP tool(s) to {}",
                "✅".green(),
                pins.tools.len(),
                target_path.join(PINNING_FILENAME).display()
            );

            if cli.verbose {
                println!();
                for (name, tool) in &pins.tools {
                    println!("  {} {}", "📌".dimmed(), name);
                    println!("     Source: {}", tool.source.dimmed());
                    println!("     Hash: {}", &tool.hash[..24].dimmed());
                }
            }

            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{} Failed to read MCP config: {}", "Error:".red().bold(), e);
            ExitCode::from(2)
        }
    }
}

/// Handle the `pin --verify` command.
pub fn handle_pin_verify(cli: &Cli) -> ExitCode {
    let target_path = cli
        .paths
        .first()
        .cloned()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    // Load existing pins
    let pins = match ToolPins::load(&target_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} Failed to load pins: {}", "Error:".red().bold(), e);
            eprintln!("{}", "Run 'cc-audit --pin' first to create pins.".dimmed());
            return ExitCode::from(2);
        }
    };

    // Find MCP config file
    let mcp_path = find_mcp_config(&target_path);

    if mcp_path.is_none() {
        eprintln!(
            "{} No MCP configuration file found in {}",
            "Error:".red().bold(),
            target_path.display()
        );
        return ExitCode::from(2);
    }

    let mcp_path = mcp_path.unwrap();

    // Verify pins against current config
    match pins.verify(&mcp_path) {
        Ok(result) => {
            print!("{}", result.format_terminal());

            if result.has_changes {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(e) => {
            eprintln!("{} Failed to verify pins: {}", "Error:".red().bold(), e);
            ExitCode::from(2)
        }
    }
}

/// Handle the `pin --update` command.
fn handle_pin_update(target_path: &Path, mcp_path: &Path) -> ExitCode {
    // Load existing pins
    let mut pins = match ToolPins::load(target_path) {
        Ok(p) => p,
        Err(_) => {
            eprintln!(
                "{} No existing pins found. Creating new pins.",
                "Note:".cyan()
            );
            match ToolPins::from_mcp_config(mcp_path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{} Failed to read MCP config: {}", "Error:".red().bold(), e);
                    return ExitCode::from(2);
                }
            }
        }
    };

    // Update pins
    if let Err(e) = pins.update(mcp_path) {
        eprintln!("{} Failed to update pins: {}", "Error:".red().bold(), e);
        return ExitCode::from(2);
    }

    // Save updated pins
    if let Err(e) = pins.save(target_path) {
        eprintln!("{} Failed to save pins: {}", "Error:".red().bold(), e);
        return ExitCode::from(2);
    }

    println!(
        "{} Updated pins with {} MCP tool(s)",
        "✅".green(),
        pins.tools.len()
    );

    ExitCode::SUCCESS
}

/// Find the MCP configuration file in a directory.
fn find_mcp_config(dir: &Path) -> Option<std::path::PathBuf> {
    let candidates = ["mcp.json", ".mcp.json", "settings.json"];

    // If dir is a file, use it directly
    if dir.is_file() {
        return Some(dir.to_path_buf());
    }

    // Check for Claude Code config locations
    let claude_dir = dir.join(".claude");
    if claude_dir.exists() {
        for name in &candidates {
            let path = claude_dir.join(name);
            if path.exists() {
                return Some(path);
            }
        }
    }

    // Check in current directory
    for name in &candidates {
        let path = dir.join(name);
        if path.exists() {
            return Some(path);
        }
    }

    // Check common locations
    let common_paths = [
        dir.join(".vscode/settings.json"),
        dir.join(".cursor/mcp.json"),
    ];

    for path in &common_paths {
        if path.exists() {
            return Some(path.clone());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_cli(args: &[&str]) -> Cli {
        let mut full_args = vec!["cc-audit"];
        full_args.extend(args);
        Cli::parse_from(full_args)
    }

    fn create_test_mcp_config() -> &'static str {
        r#"{
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@anthropic/mcp-server-github"]
                }
            }
        }"#
    }

    #[test]
    fn test_handle_pin_no_mcp_config() {
        let temp_dir = TempDir::new().unwrap();
        let cli = create_test_cli(&["--pin", temp_dir.path().to_str().unwrap()]);

        let result = handle_pin(&cli);
        assert_eq!(result, ExitCode::from(2));
    }

    #[test]
    fn test_handle_pin_creates_pins() {
        let temp_dir = TempDir::new().unwrap();
        let mcp_path = temp_dir.path().join("mcp.json");
        fs::write(&mcp_path, create_test_mcp_config()).unwrap();

        let cli = create_test_cli(&["--pin", temp_dir.path().to_str().unwrap()]);

        let result = handle_pin(&cli);
        assert_eq!(result, ExitCode::SUCCESS);

        let pins_path = temp_dir.path().join(PINNING_FILENAME);
        assert!(pins_path.exists());
    }

    #[test]
    fn test_handle_pin_exists_without_force() {
        let temp_dir = TempDir::new().unwrap();
        let mcp_path = temp_dir.path().join("mcp.json");
        fs::write(&mcp_path, create_test_mcp_config()).unwrap();

        // Create pins first
        let cli = create_test_cli(&["--pin", temp_dir.path().to_str().unwrap()]);
        handle_pin(&cli);

        // Try to create again without force
        let cli = create_test_cli(&["--pin", temp_dir.path().to_str().unwrap()]);
        let result = handle_pin(&cli);
        assert_eq!(result, ExitCode::from(2));
    }

    #[test]
    fn test_handle_pin_with_force() {
        let temp_dir = TempDir::new().unwrap();
        let mcp_path = temp_dir.path().join("mcp.json");
        fs::write(&mcp_path, create_test_mcp_config()).unwrap();

        // Create pins first
        let cli = create_test_cli(&["--pin", temp_dir.path().to_str().unwrap()]);
        handle_pin(&cli);

        // Create again with force
        let cli = create_test_cli(&["--pin", "--pin-force", temp_dir.path().to_str().unwrap()]);
        let result = handle_pin(&cli);
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_handle_pin_verify_no_pins() {
        let temp_dir = TempDir::new().unwrap();
        let cli = create_test_cli(&["--pin-verify", temp_dir.path().to_str().unwrap()]);

        let result = handle_pin_verify(&cli);
        assert_eq!(result, ExitCode::from(2));
    }

    #[test]
    fn test_handle_pin_verify_no_changes() {
        let temp_dir = TempDir::new().unwrap();
        let mcp_path = temp_dir.path().join("mcp.json");
        fs::write(&mcp_path, create_test_mcp_config()).unwrap();

        // Create pins
        let cli = create_test_cli(&["--pin", temp_dir.path().to_str().unwrap()]);
        handle_pin(&cli);

        // Verify - no changes
        let cli = create_test_cli(&["--pin-verify", temp_dir.path().to_str().unwrap()]);
        let result = handle_pin_verify(&cli);
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_handle_pin_verify_with_changes() {
        let temp_dir = TempDir::new().unwrap();
        let mcp_path = temp_dir.path().join("mcp.json");
        fs::write(&mcp_path, create_test_mcp_config()).unwrap();

        // Create pins
        let cli = create_test_cli(&["--pin", temp_dir.path().to_str().unwrap()]);
        handle_pin(&cli);

        // Modify config
        let modified_config = r#"{
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@evil/mcp-server-github"]
                }
            }
        }"#;
        fs::write(&mcp_path, modified_config).unwrap();

        // Verify - should detect changes
        let cli = create_test_cli(&["--pin-verify", temp_dir.path().to_str().unwrap()]);
        let result = handle_pin_verify(&cli);
        assert_eq!(result, ExitCode::from(1));
    }

    #[test]
    fn test_handle_pin_update() {
        let temp_dir = TempDir::new().unwrap();
        let mcp_path = temp_dir.path().join("mcp.json");
        fs::write(&mcp_path, create_test_mcp_config()).unwrap();

        // Create pins
        let cli = create_test_cli(&["--pin", temp_dir.path().to_str().unwrap()]);
        handle_pin(&cli);

        // Modify config
        let modified_config = r#"{
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@anthropic/mcp-server-github@1.0.0"]
                }
            }
        }"#;
        fs::write(&mcp_path, modified_config).unwrap();

        // Update pins
        let cli = create_test_cli(&["--pin-update", temp_dir.path().to_str().unwrap()]);
        let result = handle_pin(&cli);
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_find_mcp_config_mcp_json() {
        let temp_dir = TempDir::new().unwrap();
        let mcp_path = temp_dir.path().join("mcp.json");
        fs::write(&mcp_path, "{}").unwrap();

        let found = find_mcp_config(temp_dir.path());
        assert!(found.is_some());
        assert!(found.unwrap().ends_with("mcp.json"));
    }

    #[test]
    fn test_find_mcp_config_claude_dir() {
        let temp_dir = TempDir::new().unwrap();
        let claude_dir = temp_dir.path().join(".claude");
        fs::create_dir(&claude_dir).unwrap();
        fs::write(claude_dir.join("mcp.json"), "{}").unwrap();

        let found = find_mcp_config(temp_dir.path());
        assert!(found.is_some());
    }

    #[test]
    fn test_find_mcp_config_none() {
        let temp_dir = TempDir::new().unwrap();
        let found = find_mcp_config(temp_dir.path());
        assert!(found.is_none());
    }

    #[test]
    fn test_find_mcp_config_file_path() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("my-config.json");
        fs::write(&config_path, "{}").unwrap();

        let found = find_mcp_config(&config_path);
        assert!(found.is_some());
        assert_eq!(found.unwrap(), config_path);
    }

    #[test]
    fn test_handle_pin_verbose() {
        let temp_dir = TempDir::new().unwrap();
        let mcp_path = temp_dir.path().join("mcp.json");
        fs::write(&mcp_path, create_test_mcp_config()).unwrap();

        let cli = create_test_cli(&["--pin", "--verbose", temp_dir.path().to_str().unwrap()]);

        let result = handle_pin(&cli);
        assert_eq!(result, ExitCode::SUCCESS);
    }
}
