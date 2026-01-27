//! Proxy mode handler.

use crate::proxy::{ProxyConfig, ProxyServer};
use crate::run::EffectiveConfig;
use crate::{Cli, Config};
use colored::Colorize;
use std::process::ExitCode;

/// Handle the --proxy command.
pub fn handle_proxy(cli: &Cli) -> ExitCode {
    // Load config from current directory to get effective settings
    let project_root = cli.paths.first().and_then(|p| {
        if p.is_dir() {
            Some(p.as_path())
        } else {
            p.parent()
        }
    });
    let config = Config::load(project_root);
    let effective = EffectiveConfig::from_cli_and_config(cli, &config);
    // Parse listen address
    let listen_addr = match &cli.proxy_port {
        Some(port) => format!("127.0.0.1:{}", port).parse(),
        None => "127.0.0.1:8080".parse(),
    };

    let listen_addr = match listen_addr {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("{} Invalid listen address: {}", "Error:".red(), e);
            return ExitCode::from(2);
        }
    };

    // Parse target address
    let target_addr = match &cli.proxy_target {
        Some(target) => {
            // Try to parse as SocketAddr, if fails try as host:port
            target.parse().or_else(|_| {
                if target.contains(':') {
                    target.parse()
                } else {
                    format!("{}:3000", target).parse()
                }
            })
        }
        None => {
            eprintln!("{} --proxy-target is required", "Error:".red());
            return ExitCode::from(2);
        }
    };

    let target_addr = match target_addr {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("{} Invalid target address: {}", "Error:".red(), e);
            return ExitCode::from(2);
        }
    };

    // Build configuration
    let mut config = ProxyConfig::new(listen_addr, target_addr);

    // TLS mode
    if cli.proxy_tls {
        config = config.with_tls();
    }

    // Block mode
    if cli.proxy_block {
        let severity = effective.min_severity.unwrap_or(crate::Severity::High);
        config = config.with_block_mode(severity);
    }

    // Log file
    if let Some(ref log_path) = cli.proxy_log {
        config = config.with_log_file(log_path.clone());
    }

    // Verbose (use effective config)
    if effective.verbose {
        config = config.with_verbose();
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

    if cli.proxy_block {
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
    use clap::Parser;
    use tempfile::TempDir;

    fn create_test_cli(args: &[&str]) -> Cli {
        let mut full_args = vec!["cc-audit"];
        full_args.extend(args);
        Cli::parse_from(full_args)
    }

    #[test]
    fn test_proxy_missing_target() {
        let cli = create_test_cli(&["--proxy", "."]);
        let result = handle_proxy(&cli);

        assert_eq!(result, ExitCode::from(2));
    }

    #[test]
    fn test_proxy_config_parsing_with_port() {
        // Test port parsing (won't actually run server, just tests config parsing)
        let cli = create_test_cli(&[
            "--proxy",
            "--proxy-port",
            "9999",
            "--proxy-target",
            "127.0.0.1:3000",
            ".",
        ]);

        // Parse listen address
        let listen_addr: std::net::SocketAddr = format!("127.0.0.1:{}", cli.proxy_port.unwrap())
            .parse()
            .unwrap();
        assert_eq!(listen_addr.port(), 9999);
    }

    #[test]
    fn test_proxy_config_parsing_target_with_port() {
        let cli = create_test_cli(&["--proxy", "--proxy-target", "192.168.1.1:8080", "."]);

        let target = cli.proxy_target.as_ref().unwrap();
        let target_addr: std::net::SocketAddr = target.parse().unwrap();
        assert_eq!(target_addr.port(), 8080);
    }

    #[test]
    fn test_proxy_config_with_block_mode() {
        let cli = create_test_cli(&[
            "--proxy",
            "--proxy-target",
            "127.0.0.1:3000",
            "--proxy-block",
            ".",
        ]);
        assert!(cli.proxy_block);
    }

    #[test]
    fn test_proxy_config_with_tls() {
        let cli = create_test_cli(&[
            "--proxy",
            "--proxy-target",
            "127.0.0.1:3000",
            "--proxy-tls",
            ".",
        ]);
        assert!(cli.proxy_tls);
    }

    #[test]
    fn test_proxy_config_with_log_file() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("proxy.log");
        let log_path_str = log_path.to_str().unwrap();

        let cli = create_test_cli(&[
            "--proxy",
            "--proxy-target",
            "127.0.0.1:3000",
            "--proxy-log",
            log_path_str,
            ".",
        ]);
        assert!(cli.proxy_log.is_some());
    }

    #[test]
    fn test_proxy_config_with_verbose() {
        let cli = create_test_cli(&["--proxy", "--proxy-target", "127.0.0.1:3000", "-v", "."]);
        assert!(cli.verbose);
    }

    #[test]
    fn test_proxy_invalid_target_address() {
        // Test with an invalid target address format
        let cli = create_test_cli(&["--proxy", "--proxy-target", "invalid:address:format", "."]);
        let result = handle_proxy(&cli);
        assert_eq!(result, ExitCode::from(2));
    }
}
