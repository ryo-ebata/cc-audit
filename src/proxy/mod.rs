//! Proxy module for runtime MCP message interception.
//!
//! This module provides a TCP/TLS proxy that sits between clients and MCP servers,
//! intercepting JSON-RPC messages for security analysis.

pub mod config;
pub mod interceptor;
pub mod logger;
pub mod server;

pub use config::ProxyConfig;
pub use interceptor::{InterceptAction, MessageInterceptor};
pub use logger::{ProxyLog, ProxyLogger};
pub use server::ProxyServer;
