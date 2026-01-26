//! Scanner implementations for the detection engine (L5).
//!
//! This module contains the security scanner implementations that analyze
//! files and directories for security issues.
//!
//! Available scanners:
//! - `SkillScanner` - Scans SKILL.md and CLAUDE.md files
//! - `CommandScanner` - Scans command/slash command files
//! - `McpScanner` - Scans MCP server configurations
//! - `HookScanner` - Scans Git hook configurations
//! - `PluginScanner` - Scans plugin configurations
//! - `DockerScanner` - Scans Dockerfiles
//! - `DependencyScanner` - Scans dependency manifests
//! - `SubagentScanner` - Scans subagent configurations
//! - `RulesDirScanner` - Scans custom rules directories

// Macros must be declared first to be available in other modules
#[macro_use]
pub mod macros;

pub mod command;
pub mod dependency;
pub mod dockerfile;
pub mod error;
pub mod hook;
pub mod manifest;
pub mod mcp;
pub mod plugin;
pub mod rules_dir;
pub mod skill;
pub mod subagent;
pub mod walker;

// Re-export all scanner types
pub use command::CommandScanner;
pub use dependency::DependencyScanner;
pub use dockerfile::DockerScanner;
pub use error::{ScanError, ScanResult};
pub use hook::HookScanner;
pub use manifest::{ManifestScanner, scan_manifest_directory};
pub use mcp::McpScanner;
pub use plugin::PluginScanner;
pub use rules_dir::RulesDirScanner;
pub use skill::{FrontmatterParser, SkillFileFilter, SkillScanner};
pub use subagent::SubagentScanner;
pub use walker::{DirectoryWalker, WalkConfig};
