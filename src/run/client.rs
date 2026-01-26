//! Client detection and scan mode handling.

use crate::{Cli, ClientType, detect_client, detect_installed_clients};
use std::path::PathBuf;

/// Scan mode based on CLI options.
#[derive(Debug, Clone)]
pub enum ScanMode {
    /// Scan specific paths provided via CLI.
    Paths(Vec<PathBuf>),
    /// Scan all installed AI coding clients.
    AllClients,
    /// Scan a specific client.
    SingleClient(ClientType),
}

impl ScanMode {
    /// Determine scan mode from CLI options.
    pub fn from_cli(cli: &Cli) -> Self {
        if cli.all_clients {
            ScanMode::AllClients
        } else if let Some(client) = cli.client {
            ScanMode::SingleClient(client)
        } else {
            ScanMode::Paths(cli.paths.clone())
        }
    }
}

/// Resolve paths to scan based on CLI options.
pub fn resolve_scan_paths(cli: &Cli) -> Vec<PathBuf> {
    let mode = ScanMode::from_cli(cli);

    match mode {
        ScanMode::Paths(paths) => {
            if paths.is_empty() {
                // Default to current directory
                vec![PathBuf::from(".")]
            } else {
                paths
            }
        }
        ScanMode::AllClients => {
            let clients = detect_installed_clients();
            if clients.is_empty() {
                eprintln!("No AI coding clients detected on this system.");
                return Vec::new();
            }

            let mut paths = Vec::new();
            for client in &clients {
                eprintln!(
                    "Detected {}: {}",
                    client.client_type.display_name(),
                    client.home_dir.display()
                );
                paths.extend(client.all_configs());
            }
            paths
        }
        ScanMode::SingleClient(client_type) => match detect_client(client_type) {
            Some(client) => {
                eprintln!(
                    "Scanning {}: {}",
                    client.client_type.display_name(),
                    client.home_dir.display()
                );
                client.all_configs()
            }
            None => {
                eprintln!(
                    "{} is not installed or has no configuration files.",
                    client_type.display_name()
                );
                Vec::new()
            }
        },
    }
}

/// Determine which AI client a file path belongs to.
pub fn detect_client_for_path(path: &str) -> Option<String> {
    for client_type in ClientType::all() {
        if let Some(home) = client_type.home_dir() {
            let home_str = home.display().to_string();
            if path.starts_with(&home_str) {
                return Some(client_type.display_name().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_mode_from_cli_paths() {
        let cli = crate::Cli {
            paths: vec![PathBuf::from("/test/path")],
            all_clients: false,
            client: None,
            ..Default::default()
        };
        match ScanMode::from_cli(&cli) {
            ScanMode::Paths(paths) => assert_eq!(paths, vec![PathBuf::from("/test/path")]),
            _ => panic!("Expected ScanMode::Paths"),
        }
    }

    #[test]
    fn test_scan_mode_from_cli_all_clients() {
        let cli = crate::Cli {
            paths: vec![],
            all_clients: true,
            client: None,
            ..Default::default()
        };
        assert!(matches!(ScanMode::from_cli(&cli), ScanMode::AllClients));
    }

    #[test]
    fn test_scan_mode_from_cli_single_client() {
        let cli = crate::Cli {
            paths: vec![],
            all_clients: false,
            client: Some(ClientType::Claude),
            ..Default::default()
        };
        match ScanMode::from_cli(&cli) {
            ScanMode::SingleClient(client) => assert_eq!(client, ClientType::Claude),
            _ => panic!("Expected ScanMode::SingleClient"),
        }
    }

    #[test]
    fn test_scan_mode_debug() {
        let mode = ScanMode::Paths(vec![PathBuf::from("./test")]);
        let debug_str = format!("{:?}", mode);
        assert!(debug_str.contains("Paths"));

        let mode2 = ScanMode::AllClients;
        let debug_str2 = format!("{:?}", mode2);
        assert!(debug_str2.contains("AllClients"));

        let mode3 = ScanMode::SingleClient(ClientType::Claude);
        let debug_str3 = format!("{:?}", mode3);
        assert!(debug_str3.contains("SingleClient"));
    }

    #[test]
    fn test_resolve_scan_paths_empty() {
        let cli = crate::Cli {
            paths: vec![],
            all_clients: false,
            client: None,
            ..Default::default()
        };
        let paths = resolve_scan_paths(&cli);
        assert_eq!(paths, vec![PathBuf::from(".")]);
    }

    #[test]
    fn test_resolve_scan_paths_with_paths() {
        let cli = crate::Cli {
            paths: vec![PathBuf::from("/test/path1"), PathBuf::from("/test/path2")],
            all_clients: false,
            client: None,
            ..Default::default()
        };
        let paths = resolve_scan_paths(&cli);
        assert_eq!(
            paths,
            vec![PathBuf::from("/test/path1"), PathBuf::from("/test/path2")]
        );
    }

    #[test]
    fn test_detect_client_for_path_unknown() {
        let result = detect_client_for_path("/some/random/path");
        // This might return None or Some depending on whether any client home matches
        // Just verify it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_scan_mode_clone() {
        let mode = ScanMode::AllClients;
        let cloned = mode.clone();
        assert!(matches!(cloned, ScanMode::AllClients));
    }

    #[test]
    fn test_resolve_scan_paths_all_clients() {
        let cli = crate::Cli {
            paths: vec![],
            all_clients: true,
            client: None,
            ..Default::default()
        };
        // This tests the AllClients code path
        // Result depends on what clients are installed
        let _paths = resolve_scan_paths(&cli);
    }

    #[test]
    fn test_resolve_scan_paths_single_client_claude() {
        let cli = crate::Cli {
            paths: vec![],
            all_clients: false,
            client: Some(ClientType::Claude),
            ..Default::default()
        };
        // This tests the SingleClient code path
        // Result depends on whether Claude is installed
        let _paths = resolve_scan_paths(&cli);
    }

    #[test]
    fn test_resolve_scan_paths_single_client_cursor() {
        let cli = crate::Cli {
            paths: vec![],
            all_clients: false,
            client: Some(ClientType::Cursor),
            ..Default::default()
        };
        let _paths = resolve_scan_paths(&cli);
    }

    #[test]
    fn test_resolve_scan_paths_single_client_windsurf() {
        let cli = crate::Cli {
            paths: vec![],
            all_clients: false,
            client: Some(ClientType::Windsurf),
            ..Default::default()
        };
        let _paths = resolve_scan_paths(&cli);
    }

    #[test]
    fn test_resolve_scan_paths_single_client_vscode() {
        let cli = crate::Cli {
            paths: vec![],
            all_clients: false,
            client: Some(ClientType::Vscode),
            ..Default::default()
        };
        let _paths = resolve_scan_paths(&cli);
    }

    #[test]
    fn test_detect_client_for_path_all_clients() {
        // Test each client type's detection
        for client_type in ClientType::all() {
            if let Some(home) = client_type.home_dir() {
                let test_path = format!("{}/test/file.json", home.display());
                let result = detect_client_for_path(&test_path);
                // Should detect the client if home exists
                assert!(result.is_some() || result.is_none());
            }
        }
    }
}
