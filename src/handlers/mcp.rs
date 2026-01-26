//! MCP server handler.

use crate::McpServer;
use std::process::ExitCode;

/// Handle --mcp-server command.
pub fn handle_mcp_server() -> ExitCode {
    let server = McpServer::new();
    match server.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("MCP server error: {}", e);
            ExitCode::from(2)
        }
    }
}
