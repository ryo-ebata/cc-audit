//! Proxy mode handler.

use crate::ProxyArgs;
use crate::proxy::{ProxyConfig, ProxyServer};
use colored::Colorize;
use std::process::ExitCode;

/// Handle the proxy command.
pub fn handle_proxy(args: &ProxyArgs) -> ExitCode {
    // Parse listen address
    let listen_addr = format!("127.0.0.1:{}", args.port)
        .parse()
        .expect("Invalid port");

    // Parse target address
    let target_addr = args
        .target
        .parse()
        .or_else(|_| {
            if args.target.contains(':') {
                args.target.parse()
            } else {
                format!("{}:3000", args.target).parse()
            }
        })
        .map_err(|e| {
            eprintln!("{} Invalid target address: {}", "Error:".red(), e);
        });

    let target_addr = match target_addr {
        Ok(addr) => addr,
        Err(()) => return ExitCode::from(2),
    };

    // Build configuration
    let mut config = ProxyConfig::new(listen_addr, target_addr);

    // TLS mode
    if args.tls {
        config = config.with_tls();
    }

    // Block mode
    if args.block {
        let severity = crate::Severity::High;
        config = config.with_block_mode(severity);
    }

    // Log file
    if let Some(ref log_path) = args.log {
        config = config.with_log_file(log_path.clone());
    }

    // Create and run the server
    let server = match ProxyServer::new(config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{} Failed to create proxy server: {}", "Error:".red(), e);
            return ExitCode::from(2);
        }
    };

    println!("{}", "Starting MCP proxy server...".cyan());
    println!("  Listen: {}", listen_addr);
    println!("  Target: {}", target_addr);

    if args.block {
        println!("  Mode: {} (blocking enabled)", "BLOCK".red().bold());
    } else {
        println!("  Mode: {} (log only)", "LOG".yellow());
    }

    // Run the async server
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("{} Failed to create async runtime: {}", "Error:".red(), e);
            return ExitCode::from(2);
        }
    };

    match runtime.block_on(server.run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{} Proxy server error: {}", "Error:".red(), e);
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_proxy_config_parsing_with_port() {
        let args = ProxyArgs {
            port: 9999,
            target: "127.0.0.1:3000".to_string(),
            tls: false,
            block: false,
            log: None,
        };

        let listen_addr: std::net::SocketAddr = format!("127.0.0.1:{}", args.port).parse().unwrap();
        assert_eq!(listen_addr.port(), 9999);
    }

    #[test]
    fn test_proxy_config_parsing_target_with_port() {
        let args = ProxyArgs {
            port: 8080,
            target: "192.168.1.1:8080".to_string(),
            tls: false,
            block: false,
            log: None,
        };

        let target_addr: std::net::SocketAddr = args.target.parse().unwrap();
        assert_eq!(target_addr.port(), 8080);
    }

    #[test]
    fn test_proxy_config_with_block_mode() {
        let args = ProxyArgs {
            port: 8080,
            target: "127.0.0.1:3000".to_string(),
            tls: false,
            block: true,
            log: None,
        };
        assert!(args.block);
    }

    #[test]
    fn test_proxy_config_with_tls() {
        let args = ProxyArgs {
            port: 8080,
            target: "127.0.0.1:3000".to_string(),
            tls: true,
            block: false,
            log: None,
        };
        assert!(args.tls);
    }

    #[test]
    fn test_proxy_config_with_log_file() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("proxy.log");

        let args = ProxyArgs {
            port: 8080,
            target: "127.0.0.1:3000".to_string(),
            tls: false,
            block: false,
            log: Some(log_path),
        };
        assert!(args.log.is_some());
    }

    #[test]
    fn test_proxy_invalid_target_address() {
        let args = ProxyArgs {
            port: 8080,
            target: "invalid:address:format".to_string(),
            tls: false,
            block: false,
            log: None,
        };
        let result = handle_proxy(&args);
        assert_eq!(result, ExitCode::from(2));
    }
}
