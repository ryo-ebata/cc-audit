//! AI coding client detection and configuration paths.
//!
//! This module provides functionality to detect installed AI coding clients
//! (Claude, Cursor, Windsurf, VS Code) and locate their configuration files.

use crate::rules::ParseEnumError;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Supported AI coding clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientType {
    /// Claude Desktop / Claude Code
    Claude,
    /// Cursor IDE
    Cursor,
    /// Windsurf IDE
    Windsurf,
    /// VS Code with MCP extensions
    Vscode,
}

impl std::str::FromStr for ClientType {
    type Err = ParseEnumError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace(['-', '_'], "").as_str() {
            "claude" | "claudecode" | "claudedesktop" => Ok(ClientType::Claude),
            "cursor" => Ok(ClientType::Cursor),
            "windsurf" => Ok(ClientType::Windsurf),
            "vscode" | "code" => Ok(ClientType::Vscode),
            _ => Err(ParseEnumError::invalid("ClientType", s)),
        }
    }
}

impl ClientType {
    /// Returns all supported client types.
    pub fn all() -> &'static [ClientType] {
        &[
            ClientType::Claude,
            ClientType::Cursor,
            ClientType::Windsurf,
            ClientType::Vscode,
        ]
    }

    /// Returns the display name of the client.
    pub fn display_name(&self) -> &'static str {
        match self {
            ClientType::Claude => "Claude",
            ClientType::Cursor => "Cursor",
            ClientType::Windsurf => "Windsurf",
            ClientType::Vscode => "VS Code",
        }
    }

    /// Returns the home directory path for this client.
    /// Returns `None` if the home directory cannot be determined.
    pub fn home_dir(&self) -> Option<PathBuf> {
        match self {
            ClientType::Claude => Self::claude_home_dir(),
            ClientType::Cursor => Self::cursor_home_dir(),
            ClientType::Windsurf => Self::windsurf_home_dir(),
            ClientType::Vscode => Self::vscode_home_dir(),
        }
    }

    #[cfg(target_os = "windows")]
    fn claude_home_dir() -> Option<PathBuf> {
        dirs::data_dir().map(|d| d.join("Claude"))
    }

    #[cfg(not(target_os = "windows"))]
    fn claude_home_dir() -> Option<PathBuf> {
        dirs::home_dir().map(|d| d.join(".claude"))
    }

    #[cfg(target_os = "windows")]
    fn cursor_home_dir() -> Option<PathBuf> {
        dirs::data_dir().map(|d| d.join("Cursor"))
    }

    #[cfg(not(target_os = "windows"))]
    fn cursor_home_dir() -> Option<PathBuf> {
        dirs::home_dir().map(|d| d.join(".cursor"))
    }

    #[cfg(target_os = "windows")]
    fn windsurf_home_dir() -> Option<PathBuf> {
        // Windsurf may not be available on Windows yet
        dirs::data_dir().map(|d| d.join("Windsurf"))
    }

    #[cfg(not(target_os = "windows"))]
    fn windsurf_home_dir() -> Option<PathBuf> {
        dirs::home_dir().map(|d| d.join(".windsurf"))
    }

    #[cfg(target_os = "windows")]
    fn vscode_home_dir() -> Option<PathBuf> {
        dirs::data_dir().map(|d| d.join("Code"))
    }

    #[cfg(not(target_os = "windows"))]
    fn vscode_home_dir() -> Option<PathBuf> {
        dirs::home_dir().map(|d| d.join(".vscode"))
    }

    /// Returns the MCP configuration file paths for this client.
    pub fn mcp_config_paths(&self) -> Vec<PathBuf> {
        let Some(home) = self.home_dir() else {
            return Vec::new();
        };

        match self {
            ClientType::Claude => vec![
                home.join("mcp.json"),
                home.join("claude_desktop_config.json"),
            ],
            ClientType::Cursor => vec![home.join("mcp.json")],
            ClientType::Windsurf => vec![home.join("mcp_config.json")],
            ClientType::Vscode => {
                // VS Code MCP extensions store config in globalStorage
                let mut paths = Vec::new();
                if let Some(data_dir) = dirs::data_dir() {
                    // Roo-Cline extension
                    paths.push(
                        data_dir
                            .join("Code")
                            .join("User")
                            .join("globalStorage")
                            .join("rooveterinaryinc.roo-cline")
                            .join("settings")
                            .join("cline_mcp_settings.json"),
                    );
                    // Claude Dev extension
                    paths.push(
                        data_dir
                            .join("Code")
                            .join("User")
                            .join("globalStorage")
                            .join("saoudrizwan.claude-dev")
                            .join("settings")
                            .join("cline_mcp_settings.json"),
                    );
                }
                paths
            }
        }
    }

    /// Returns the settings/hooks configuration file paths for this client.
    pub fn settings_config_paths(&self) -> Vec<PathBuf> {
        let Some(home) = self.home_dir() else {
            return Vec::new();
        };

        match self {
            ClientType::Claude => vec![home.join("settings.json")],
            ClientType::Cursor => vec![home.join("settings.json")],
            ClientType::Windsurf => vec![home.join("settings.json")],
            ClientType::Vscode => vec![],
        }
    }

    /// Checks if this client is installed on the system.
    pub fn is_installed(&self) -> bool {
        self.home_dir().map(|p| p.exists()).unwrap_or(false)
    }

    /// Returns all scannable paths for this client (MCP + settings).
    pub fn all_config_paths(&self) -> Vec<PathBuf> {
        let mut paths = self.mcp_config_paths();
        paths.extend(self.settings_config_paths());
        paths
    }
}

impl std::fmt::Display for ClientType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Information about a detected AI coding client.
#[derive(Debug, Clone)]
pub struct DetectedClient {
    /// The type of client.
    pub client_type: ClientType,
    /// The home directory of the client.
    pub home_dir: PathBuf,
    /// Existing MCP configuration files.
    pub mcp_configs: Vec<PathBuf>,
    /// Existing settings configuration files.
    pub settings_configs: Vec<PathBuf>,
}

impl DetectedClient {
    /// Returns all existing configuration files for this client.
    pub fn all_configs(&self) -> Vec<PathBuf> {
        let mut configs = self.mcp_configs.clone();
        configs.extend(self.settings_configs.clone());
        configs
    }

    /// Returns true if any configuration files exist.
    pub fn has_configs(&self) -> bool {
        !self.mcp_configs.is_empty() || !self.settings_configs.is_empty()
    }
}

/// Detects all installed AI coding clients on the system.
///
/// Returns a list of detected clients with their configuration file paths.
/// Only clients with at least one existing configuration file are returned.
pub fn detect_installed_clients() -> Vec<DetectedClient> {
    ClientType::all()
        .iter()
        .filter_map(|ct| detect_client(*ct))
        .collect()
}

/// Detects a specific client type.
///
/// Returns `None` if the client is not installed or has no configuration files.
pub fn detect_client(client_type: ClientType) -> Option<DetectedClient> {
    let home = client_type.home_dir()?;

    if !home.exists() {
        return None;
    }

    let mcp_configs: Vec<PathBuf> = client_type
        .mcp_config_paths()
        .into_iter()
        .filter(|p| p.exists())
        .collect();

    let settings_configs: Vec<PathBuf> = client_type
        .settings_config_paths()
        .into_iter()
        .filter(|p| p.exists())
        .collect();

    // Only return if at least one config file exists
    if mcp_configs.is_empty() && settings_configs.is_empty() {
        return None;
    }

    Some(DetectedClient {
        client_type,
        home_dir: home,
        mcp_configs,
        settings_configs,
    })
}

/// Lists all installed clients (even without configuration files).
pub fn list_installed_clients() -> Vec<ClientType> {
    ClientType::all()
        .iter()
        .filter(|ct| ct.is_installed())
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_type_display_name() {
        assert_eq!(ClientType::Claude.display_name(), "Claude");
        assert_eq!(ClientType::Cursor.display_name(), "Cursor");
        assert_eq!(ClientType::Windsurf.display_name(), "Windsurf");
        assert_eq!(ClientType::Vscode.display_name(), "VS Code");
    }

    #[test]
    fn test_client_type_all() {
        let all = ClientType::all();
        assert_eq!(all.len(), 4);
        assert!(all.contains(&ClientType::Claude));
        assert!(all.contains(&ClientType::Cursor));
        assert!(all.contains(&ClientType::Windsurf));
        assert!(all.contains(&ClientType::Vscode));
    }

    #[test]
    fn test_client_type_display() {
        assert_eq!(format!("{}", ClientType::Claude), "Claude");
        assert_eq!(format!("{}", ClientType::Cursor), "Cursor");
    }

    #[test]
    fn test_home_dir_returns_some() {
        // Home dir should always be resolvable on a real system
        for ct in ClientType::all() {
            let home = ct.home_dir();
            assert!(home.is_some(), "home_dir() should return Some for {:?}", ct);
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_claude_home_dir_unix() {
        let home = ClientType::Claude.home_dir();
        assert!(home.is_some());
        let path = home.unwrap();
        assert!(path.to_string_lossy().contains(".claude"));
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn test_cursor_home_dir_unix() {
        let home = ClientType::Cursor.home_dir();
        assert!(home.is_some());
        let path = home.unwrap();
        assert!(path.to_string_lossy().contains(".cursor"));
    }

    #[test]
    fn test_mcp_config_paths_not_empty() {
        // All clients should have at least one potential MCP config path
        for ct in ClientType::all() {
            let paths = ct.mcp_config_paths();
            assert!(
                !paths.is_empty() || *ct == ClientType::Vscode,
                "mcp_config_paths() should not be empty for {:?}",
                ct
            );
        }
    }

    #[test]
    fn test_detected_client_has_configs() {
        let client = DetectedClient {
            client_type: ClientType::Claude,
            home_dir: PathBuf::from("/tmp/claude"),
            mcp_configs: vec![PathBuf::from("/tmp/claude/mcp.json")],
            settings_configs: vec![],
        };
        assert!(client.has_configs());

        let empty_client = DetectedClient {
            client_type: ClientType::Claude,
            home_dir: PathBuf::from("/tmp/claude"),
            mcp_configs: vec![],
            settings_configs: vec![],
        };
        assert!(!empty_client.has_configs());
    }

    #[test]
    fn test_detected_client_all_configs() {
        let client = DetectedClient {
            client_type: ClientType::Claude,
            home_dir: PathBuf::from("/tmp/claude"),
            mcp_configs: vec![PathBuf::from("/tmp/claude/mcp.json")],
            settings_configs: vec![PathBuf::from("/tmp/claude/settings.json")],
        };
        let all = client.all_configs();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_client_type_serialize() {
        let json = serde_json::to_string(&ClientType::Claude).unwrap();
        assert_eq!(json, "\"claude\"");

        let json = serde_json::to_string(&ClientType::Vscode).unwrap();
        assert_eq!(json, "\"vscode\"");
    }

    #[test]
    fn test_client_type_deserialize() {
        let ct: ClientType = serde_json::from_str("\"claude\"").unwrap();
        assert_eq!(ct, ClientType::Claude);

        let ct: ClientType = serde_json::from_str("\"vscode\"").unwrap();
        assert_eq!(ct, ClientType::Vscode);
    }
}
