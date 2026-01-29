//! MCP tool pinning for rug-pull attack detection.
//!
//! This module provides functionality to pin MCP server configurations
//! and detect unauthorized changes that may indicate supply chain attacks.

use crate::error::{AuditError, Result};
use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Default filename for pinning data.
pub const PINNING_FILENAME: &str = ".cc-audit-pins.json";

/// Represents pinned MCP tool configurations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolPins {
    /// Version of the pinning format.
    pub version: String,
    /// When the pins were first created.
    pub created_at: String,
    /// When the pins were last updated.
    pub updated_at: String,
    /// Pinned tools by name.
    pub tools: FxHashMap<String, PinnedTool>,
}

/// A single pinned tool entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedTool {
    /// SHA-256 hash of the tool configuration.
    pub hash: String,
    /// Source of the tool (e.g., "npx @anthropic/mcp-server-github").
    pub source: String,
    /// When this tool was pinned.
    pub pinned_at: String,
    /// Optional version info extracted from source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Result of verifying pins against current configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinVerifyResult {
    /// Tools that have been modified since pinning.
    pub modified: Vec<PinMismatch>,
    /// Tools that were added since pinning.
    pub added: Vec<String>,
    /// Tools that were removed since pinning.
    pub removed: Vec<String>,
    /// Whether any changes were detected.
    pub has_changes: bool,
}

/// A mismatch between pinned and current configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinMismatch {
    /// Name of the tool.
    pub name: String,
    /// Original pinned hash.
    pub pinned_hash: String,
    /// Current hash.
    pub current_hash: String,
    /// Source of the tool.
    pub source: String,
}

impl ToolPins {
    /// Create new pins from an MCP configuration file.
    pub fn from_mcp_config(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path).map_err(|e| AuditError::ReadError {
            path: path.display().to_string(),
            source: e,
        })?;

        Self::from_mcp_content(&content, path)
    }

    /// Create new pins from MCP configuration content.
    pub fn from_mcp_content(content: &str, path: &Path) -> Result<Self> {
        let config: serde_json::Value =
            serde_json::from_str(content).map_err(|e| AuditError::ParseError {
                path: path.display().to_string(),
                message: e.to_string(),
            })?;

        let mut tools = FxHashMap::default();
        let now = chrono::Utc::now().to_rfc3339();

        // Extract mcpServers from the config
        if let Some(mcp_servers) = config.get("mcpServers").and_then(|v| v.as_object()) {
            for (name, server_config) in mcp_servers {
                let pinned_tool = Self::create_pinned_tool(name, server_config, &now);
                tools.insert(name.clone(), pinned_tool);
            }
        }

        Ok(Self {
            version: "1".to_string(),
            created_at: now.clone(),
            updated_at: now,
            tools,
        })
    }

    /// Create a pinned tool entry from server configuration.
    fn create_pinned_tool(_name: &str, config: &serde_json::Value, timestamp: &str) -> PinnedTool {
        // Compute hash of the entire server configuration
        let config_str = serde_json::to_string(config).unwrap_or_default();
        let hash = Self::compute_hash(&config_str);

        // Extract source from command and args
        let source = Self::extract_source(config);

        // Try to extract version from source
        let version = Self::extract_version(&source);

        PinnedTool {
            hash,
            source,
            pinned_at: timestamp.to_string(),
            version,
        }
    }

    /// Compute SHA-256 hash of content.
    fn compute_hash(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("sha256:{:x}", hasher.finalize())
    }

    /// Extract source string from server configuration.
    fn extract_source(config: &serde_json::Value) -> String {
        let command = config
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        let args = config
            .get("args")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();

        if !command.is_empty() && !args.is_empty() {
            format!("{} {}", command, args)
        } else if !command.is_empty() {
            command.to_string()
        } else if !args.is_empty() {
            args
        } else {
            config
                .get("url")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string()
        }
    }

    /// Try to extract version from source string.
    fn extract_version(source: &str) -> Option<String> {
        // Look for common version patterns:
        // @scope/package@version, package@version, package:version
        let patterns = [
            // npm scoped package: @scope/package@version
            regex::Regex::new(r"@[\w-]+/[\w-]+@([\d.]+[\w.-]*)").ok()?,
            // npm package: package@version
            regex::Regex::new(r"[\w-]+@([\d.]+[\w.-]*)").ok()?,
            // docker: package:version (allows word tags like "latest")
            regex::Regex::new(r"[\w-]+:([\w][\w.-]*)").ok()?,
        ];

        for pattern in &patterns {
            if let Some(caps) = pattern.captures(source)
                && let Some(version) = caps.get(1)
            {
                return Some(version.as_str().to_string());
            }
        }

        None
    }

    /// Save pins to the default location.
    pub fn save(&self, dir: &Path) -> Result<()> {
        let pin_path = if dir.is_file() {
            dir.parent()
                .unwrap_or(Path::new("."))
                .join(PINNING_FILENAME)
        } else {
            dir.join(PINNING_FILENAME)
        };

        self.save_to_file(&pin_path)
    }

    /// Save pins to a specific file.
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self).map_err(|e| AuditError::ParseError {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;

        fs::write(path, json).map_err(|e| AuditError::ReadError {
            path: path.display().to_string(),
            source: e,
        })?;

        Ok(())
    }

    /// Load pins from the default location.
    pub fn load(dir: &Path) -> Result<Self> {
        let pin_path = if dir.is_file() {
            dir.parent()
                .unwrap_or(Path::new("."))
                .join(PINNING_FILENAME)
        } else {
            dir.join(PINNING_FILENAME)
        };

        Self::load_from_file(&pin_path)
    }

    /// Load pins from a specific file.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(AuditError::FileNotFound(path.display().to_string()));
        }

        let content = fs::read_to_string(path).map_err(|e| AuditError::ReadError {
            path: path.display().to_string(),
            source: e,
        })?;

        serde_json::from_str(&content).map_err(|e| AuditError::ParseError {
            path: path.display().to_string(),
            message: e.to_string(),
        })
    }

    /// Check if a pins file exists.
    pub fn exists(dir: &Path) -> bool {
        let pin_path = if dir.is_file() {
            dir.parent()
                .unwrap_or(Path::new("."))
                .join(PINNING_FILENAME)
        } else {
            dir.join(PINNING_FILENAME)
        };

        pin_path.exists()
    }

    /// Verify current configuration against pins.
    pub fn verify(&self, mcp_path: &Path) -> Result<PinVerifyResult> {
        let current = Self::from_mcp_config(mcp_path)?;

        let mut modified = Vec::new();
        let mut added = Vec::new();
        let mut removed = Vec::new();

        // Check for modified and removed tools
        for (name, pinned) in &self.tools {
            match current.tools.get(name) {
                Some(current_tool) => {
                    if pinned.hash != current_tool.hash {
                        modified.push(PinMismatch {
                            name: name.clone(),
                            pinned_hash: pinned.hash.clone(),
                            current_hash: current_tool.hash.clone(),
                            source: current_tool.source.clone(),
                        });
                    }
                }
                None => {
                    removed.push(name.clone());
                }
            }
        }

        // Check for added tools
        for name in current.tools.keys() {
            if !self.tools.contains_key(name) {
                added.push(name.clone());
            }
        }

        let has_changes = !modified.is_empty() || !added.is_empty() || !removed.is_empty();

        Ok(PinVerifyResult {
            modified,
            added,
            removed,
            has_changes,
        })
    }

    /// Update pins with current configuration.
    pub fn update(&mut self, mcp_path: &Path) -> Result<()> {
        let current = Self::from_mcp_config(mcp_path)?;

        self.tools = current.tools;
        self.updated_at = chrono::Utc::now().to_rfc3339();

        Ok(())
    }
}

impl PinVerifyResult {
    /// Format the result for terminal output.
    pub fn format_terminal(&self) -> String {
        use colored::Colorize;

        let mut output = String::new();

        if !self.has_changes {
            output.push_str(
                &"✅ All MCP tool pins verified. No changes detected.\n"
                    .green()
                    .to_string(),
            );
            return output;
        }

        output.push_str(&format!(
            "{}\n\n",
            "━━━ MCP TOOL PIN MISMATCH (Potential Rug Pull) ━━━"
                .red()
                .bold()
        ));

        if !self.modified.is_empty() {
            output.push_str(&format!("{}\n", "Modified tools:".yellow().bold()));
            for mismatch in &self.modified {
                output.push_str(&format!("  {} {}\n", "~".yellow(), mismatch.name));
                output.push_str(&format!("    Source: {}\n", mismatch.source));
                let pinned_display = if mismatch.pinned_hash.len() > 23 {
                    &mismatch.pinned_hash[..23]
                } else {
                    &mismatch.pinned_hash
                };
                let current_display = if mismatch.current_hash.len() > 23 {
                    &mismatch.current_hash[..23]
                } else {
                    &mismatch.current_hash
                };
                output.push_str(&format!("    Pinned:  {}...\n", pinned_display));
                output.push_str(&format!("    Current: {}...\n", current_display));
            }
            output.push('\n');
        }

        if !self.added.is_empty() {
            output.push_str(&format!("{}\n", "Added tools:".green().bold()));
            for name in &self.added {
                output.push_str(&format!("  {} {}\n", "+".green(), name));
            }
            output.push('\n');
        }

        if !self.removed.is_empty() {
            output.push_str(&format!("{}\n", "Removed tools:".red().bold()));
            for name in &self.removed {
                output.push_str(&format!("  {} {}\n", "-".red(), name));
            }
            output.push('\n');
        }

        output.push_str(&format!(
            "Summary: {} modified, {} added, {} removed\n",
            self.modified.len(),
            self.added.len(),
            self.removed.len()
        ));

        output.push_str(&format!(
            "\n{}\n",
            "Run 'cc-audit pin --update' to accept these changes."
                .cyan()
                .dimmed()
        ));

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_mcp_config() -> &'static str {
        r#"{
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@anthropic/mcp-server-github"]
                },
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@anthropic/mcp-server-filesystem", "/path"]
                }
            }
        }"#
    }

    #[test]
    fn test_create_pins_from_config() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("mcp.json");
        fs::write(&config_path, create_test_mcp_config()).unwrap();

        let pins = ToolPins::from_mcp_config(&config_path).unwrap();

        assert_eq!(pins.version, "1");
        assert_eq!(pins.tools.len(), 2);
        assert!(pins.tools.contains_key("github"));
        assert!(pins.tools.contains_key("filesystem"));
    }

    #[test]
    fn test_pinned_tool_hash() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("mcp.json");
        fs::write(&config_path, create_test_mcp_config()).unwrap();

        let pins = ToolPins::from_mcp_config(&config_path).unwrap();
        let github = pins.tools.get("github").unwrap();

        assert!(github.hash.starts_with("sha256:"));
        assert!(github.source.contains("@anthropic/mcp-server-github"));
    }

    #[test]
    fn test_save_and_load_pins() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("mcp.json");
        fs::write(&config_path, create_test_mcp_config()).unwrap();

        let pins = ToolPins::from_mcp_config(&config_path).unwrap();
        pins.save(temp_dir.path()).unwrap();

        let loaded = ToolPins::load(temp_dir.path()).unwrap();
        assert_eq!(pins.tools.len(), loaded.tools.len());
    }

    #[test]
    fn test_verify_no_changes() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("mcp.json");
        fs::write(&config_path, create_test_mcp_config()).unwrap();

        let pins = ToolPins::from_mcp_config(&config_path).unwrap();
        let result = pins.verify(&config_path).unwrap();

        assert!(!result.has_changes);
        assert!(result.modified.is_empty());
        assert!(result.added.is_empty());
        assert!(result.removed.is_empty());
    }

    #[test]
    fn test_verify_modified_tool() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("mcp.json");
        fs::write(&config_path, create_test_mcp_config()).unwrap();

        let pins = ToolPins::from_mcp_config(&config_path).unwrap();

        // Modify the config
        let modified_config = r#"{
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@evil/mcp-server-github"]
                },
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@anthropic/mcp-server-filesystem", "/path"]
                }
            }
        }"#;
        fs::write(&config_path, modified_config).unwrap();

        let result = pins.verify(&config_path).unwrap();

        assert!(result.has_changes);
        assert_eq!(result.modified.len(), 1);
        assert_eq!(result.modified[0].name, "github");
    }

    #[test]
    fn test_verify_added_tool() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("mcp.json");
        fs::write(&config_path, create_test_mcp_config()).unwrap();

        let pins = ToolPins::from_mcp_config(&config_path).unwrap();

        // Add a new tool
        let modified_config = r#"{
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@anthropic/mcp-server-github"]
                },
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@anthropic/mcp-server-filesystem", "/path"]
                },
                "new-tool": {
                    "command": "npx",
                    "args": ["-y", "@malicious/tool"]
                }
            }
        }"#;
        fs::write(&config_path, modified_config).unwrap();

        let result = pins.verify(&config_path).unwrap();

        assert!(result.has_changes);
        assert_eq!(result.added.len(), 1);
        assert!(result.added.contains(&"new-tool".to_string()));
    }

    #[test]
    fn test_verify_removed_tool() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("mcp.json");
        fs::write(&config_path, create_test_mcp_config()).unwrap();

        let pins = ToolPins::from_mcp_config(&config_path).unwrap();

        // Remove a tool
        let modified_config = r#"{
            "mcpServers": {
                "github": {
                    "command": "npx",
                    "args": ["-y", "@anthropic/mcp-server-github"]
                }
            }
        }"#;
        fs::write(&config_path, modified_config).unwrap();

        let result = pins.verify(&config_path).unwrap();

        assert!(result.has_changes);
        assert_eq!(result.removed.len(), 1);
        assert!(result.removed.contains(&"filesystem".to_string()));
    }

    #[test]
    fn test_update_pins() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("mcp.json");
        fs::write(&config_path, create_test_mcp_config()).unwrap();

        let mut pins = ToolPins::from_mcp_config(&config_path).unwrap();
        let original_created = pins.created_at.clone();

        // Modify and update
        let modified_config = r#"{
            "mcpServers": {
                "new-tool": {
                    "command": "npx",
                    "args": ["-y", "@new/tool"]
                }
            }
        }"#;
        fs::write(&config_path, modified_config).unwrap();

        pins.update(&config_path).unwrap();

        assert_eq!(pins.created_at, original_created);
        assert_ne!(pins.updated_at, original_created);
        assert_eq!(pins.tools.len(), 1);
        assert!(pins.tools.contains_key("new-tool"));
    }

    #[test]
    fn test_pins_exists() {
        let temp_dir = TempDir::new().unwrap();

        assert!(!ToolPins::exists(temp_dir.path()));

        let pins = ToolPins {
            version: "1".to_string(),
            created_at: "2024-01-01".to_string(),
            updated_at: "2024-01-01".to_string(),
            tools: FxHashMap::default(),
        };
        pins.save(temp_dir.path()).unwrap();

        assert!(ToolPins::exists(temp_dir.path()));
    }

    #[test]
    fn test_extract_version() {
        // npm scoped package
        assert_eq!(
            ToolPins::extract_version("npx @anthropic/mcp-server@1.2.3"),
            Some("1.2.3".to_string())
        );

        // npm package
        assert_eq!(
            ToolPins::extract_version("npx mcp-server@2.0.0-beta.1"),
            Some("2.0.0-beta.1".to_string())
        );

        // docker
        assert_eq!(
            ToolPins::extract_version("docker run server:latest"),
            Some("latest".to_string())
        );

        // No version
        assert_eq!(ToolPins::extract_version("npx @anthropic/mcp-server"), None);
    }

    #[test]
    fn test_compute_hash_consistency() {
        let content = "test content";
        let hash1 = ToolPins::compute_hash(content);
        let hash2 = ToolPins::compute_hash(content);

        assert_eq!(hash1, hash2);
        assert!(hash1.starts_with("sha256:"));
    }

    #[test]
    fn test_format_terminal_no_changes() {
        let result = PinVerifyResult {
            modified: vec![],
            added: vec![],
            removed: vec![],
            has_changes: false,
        };

        let output = result.format_terminal();
        assert!(output.contains("verified"));
    }

    #[test]
    fn test_format_terminal_with_changes() {
        let result = PinVerifyResult {
            modified: vec![PinMismatch {
                name: "github".to_string(),
                pinned_hash: "sha256:abc123".to_string(),
                current_hash: "sha256:def456".to_string(),
                source: "npx @anthropic/mcp-server-github".to_string(),
            }],
            added: vec!["new-tool".to_string()],
            removed: vec!["old-tool".to_string()],
            has_changes: true,
        };

        let output = result.format_terminal();
        assert!(output.contains("MISMATCH"));
        assert!(output.contains("Modified"));
        assert!(output.contains("Added"));
        assert!(output.contains("Removed"));
    }

    #[test]
    fn test_load_nonexistent_pins() {
        let temp_dir = TempDir::new().unwrap();
        let result = ToolPins::load(temp_dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_source_with_url() {
        let config: serde_json::Value = serde_json::json!({
            "url": "https://mcp.example.com/server"
        });

        let source = ToolPins::extract_source(&config);
        assert_eq!(source, "https://mcp.example.com/server");
    }

    #[test]
    fn test_extract_source_command_only() {
        let config: serde_json::Value = serde_json::json!({
            "command": "python"
        });

        let source = ToolPins::extract_source(&config);
        assert_eq!(source, "python");
    }

    #[test]
    fn test_pinned_tool_serialization() {
        let tool = PinnedTool {
            hash: "sha256:abc123".to_string(),
            source: "npx @anthropic/mcp-server".to_string(),
            pinned_at: "2024-01-01".to_string(),
            version: Some("1.0.0".to_string()),
        };

        let json = serde_json::to_string(&tool).unwrap();
        let parsed: PinnedTool = serde_json::from_str(&json).unwrap();

        assert_eq!(tool.hash, parsed.hash);
        assert_eq!(tool.version, parsed.version);
    }

    #[test]
    fn test_pin_mismatch_serialization() {
        let mismatch = PinMismatch {
            name: "test".to_string(),
            pinned_hash: "sha256:abc".to_string(),
            current_hash: "sha256:def".to_string(),
            source: "npx test".to_string(),
        };

        let json = serde_json::to_string(&mismatch).unwrap();
        let parsed: PinMismatch = serde_json::from_str(&json).unwrap();

        assert_eq!(mismatch.name, parsed.name);
    }

    #[test]
    fn test_from_mcp_config_file_not_found() {
        let result = ToolPins::from_mcp_config(Path::new("/nonexistent/mcp.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_from_mcp_content_invalid_json() {
        let result = ToolPins::from_mcp_content("invalid json {", Path::new("test.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_from_mcp_content_no_mcp_servers() {
        let content = r#"{"otherField": "value"}"#;
        let pins = ToolPins::from_mcp_content(content, Path::new("test.json")).unwrap();
        assert!(pins.tools.is_empty());
    }

    #[test]
    fn test_save_and_load_with_file_path() {
        use std::io::Write;
        let temp_dir = TempDir::new().unwrap();
        let mcp_config = temp_dir.path().join("mcp.json");

        // Create a dummy MCP config file
        let mut file = fs::File::create(&mcp_config).unwrap();
        file.write_all(br#"{"mcpServers": {}}"#).unwrap();

        // Create pins from MCP config
        let pins = ToolPins::from_mcp_config(&mcp_config).unwrap();

        // Save using file path (should save to parent dir)
        pins.save(&mcp_config).unwrap();

        // Load using file path
        let loaded = ToolPins::load(&mcp_config).unwrap();
        assert_eq!(pins.version, loaded.version);
    }

    #[test]
    fn test_exists_with_file_path() {
        use std::io::Write;
        let temp_dir = TempDir::new().unwrap();
        let mcp_config = temp_dir.path().join("mcp.json");

        // Create a dummy file
        let mut file = fs::File::create(&mcp_config).unwrap();
        file.write_all(br#"{"mcpServers": {}}"#).unwrap();

        // Initially no pins exist
        assert!(!ToolPins::exists(&mcp_config));

        // Create and save pins
        let pins = ToolPins::from_mcp_config(&mcp_config).unwrap();
        pins.save(&mcp_config).unwrap();

        // Now pins should exist
        assert!(ToolPins::exists(&mcp_config));
    }

    #[test]
    fn test_load_from_file_invalid_json() {
        use std::io::Write;
        let temp_dir = TempDir::new().unwrap();
        let pin_file = temp_dir.path().join(PINNING_FILENAME);

        // Write invalid JSON
        let mut file = fs::File::create(&pin_file).unwrap();
        file.write_all(b"not valid json").unwrap();

        let result = ToolPins::load_from_file(&pin_file);
        assert!(result.is_err());
    }
}
