//! External integrations (横断層).
//!
//! This module provides external integrations:
//! - Remote repository operations (git clone, GitHub API)
//! - Git hooks installation
//! - MCP server for IDE integration
//! - File watching for continuous scanning
//! - Auto-fix capabilities
//! - Tool pinning verification
//! - Trusted domain management
//!
//! These modules are cross-cutting concerns that integrate
//! with external systems and tools.

// Re-export from existing modules (will be moved here in Phase 10)
pub use crate::fix::{AutoFixer, Fix, FixResult};
pub use crate::hooks::{HookError, HookInstaller};
pub use crate::mcp_server::McpServer;
pub use crate::pinning::{PinMismatch, PinVerifyResult, PinnedTool, ToolPins};
pub use crate::remote::{ClonedRepo, GitCloner, RemoteError, parse_github_url};
pub use crate::trusted_domains::{TrustedDomain, TrustedDomainMatcher};
pub use crate::watch::FileWatcher;
