//! Proxy configuration.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Configuration for the proxy server.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    /// Address to listen on
    pub listen_addr: SocketAddr,

    /// Target MCP server address
    pub target_addr: SocketAddr,

    /// Enable TLS termination
    pub tls_enabled: bool,

    /// TLS certificate file (optional, will generate self-signed if not provided)
    pub tls_cert_file: Option<PathBuf>,

    /// TLS key file (optional)
    pub tls_key_file: Option<PathBuf>,

    /// Block mode: if true, block messages with findings; if false, log only
    pub block_mode: bool,

    /// Log file path for JSONL output
    pub log_file: Option<PathBuf>,

    /// Minimum severity to trigger blocking (when block_mode is true)
    pub min_block_severity: crate::Severity,

    /// Verbose logging
    pub verbose: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            target_addr: "127.0.0.1:3000".parse().unwrap(),
            tls_enabled: false,
            tls_cert_file: None,
            tls_key_file: None,
            block_mode: false,
            log_file: None,
            min_block_severity: crate::Severity::High,
            verbose: false,
        }
    }
}

impl ProxyConfig {
    /// Create a new proxy config with the given listen and target addresses.
    pub fn new(listen_addr: SocketAddr, target_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            target_addr,
            ..Default::default()
        }
    }

    /// Enable TLS with auto-generated self-signed certificate.
    pub fn with_tls(mut self) -> Self {
        self.tls_enabled = true;
        self
    }

    /// Enable TLS with custom certificate files.
    pub fn with_tls_files(mut self, cert: PathBuf, key: PathBuf) -> Self {
        self.tls_enabled = true;
        self.tls_cert_file = Some(cert);
        self.tls_key_file = Some(key);
        self
    }

    /// Enable block mode.
    pub fn with_block_mode(mut self, min_severity: crate::Severity) -> Self {
        self.block_mode = true;
        self.min_block_severity = min_severity;
        self
    }

    /// Set log file path.
    pub fn with_log_file(mut self, path: PathBuf) -> Self {
        self.log_file = Some(path);
        self
    }

    /// Enable verbose logging.
    pub fn with_verbose(mut self) -> Self {
        self.verbose = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_default_config() {
        let config = ProxyConfig::default();
        assert_eq!(config.listen_addr.port(), 8080);
        assert!(!config.tls_enabled);
        assert!(!config.block_mode);
    }

    #[test]
    fn test_config_builder() {
        let config = ProxyConfig::new(
            "0.0.0.0:9000".parse().unwrap(),
            "127.0.0.1:3000".parse().unwrap(),
        )
        .with_tls()
        .with_block_mode(crate::Severity::Critical)
        .with_verbose();

        assert_eq!(config.listen_addr.port(), 9000);
        assert!(config.tls_enabled);
        assert!(config.block_mode);
        assert_eq!(config.min_block_severity, crate::Severity::Critical);
        assert!(config.verbose);
    }

    #[test]
    fn test_with_tls_files() {
        let config = ProxyConfig::default().with_tls_files(
            PathBuf::from("/path/to/cert.pem"),
            PathBuf::from("/path/to/key.pem"),
        );

        assert!(config.tls_enabled);
        assert_eq!(
            config.tls_cert_file,
            Some(PathBuf::from("/path/to/cert.pem"))
        );
        assert_eq!(config.tls_key_file, Some(PathBuf::from("/path/to/key.pem")));
    }

    #[test]
    fn test_with_log_file() {
        let config = ProxyConfig::default().with_log_file(PathBuf::from("/var/log/proxy.jsonl"));

        assert_eq!(config.log_file, Some(PathBuf::from("/var/log/proxy.jsonl")));
    }

    #[test]
    fn test_default_severity() {
        let config = ProxyConfig::default();
        assert_eq!(config.min_block_severity, crate::Severity::High);
    }

    #[test]
    fn test_config_clone() {
        let config = ProxyConfig::default()
            .with_tls()
            .with_block_mode(crate::Severity::Medium)
            .with_verbose();

        let cloned = config.clone();

        assert_eq!(cloned.listen_addr, config.listen_addr);
        assert_eq!(cloned.target_addr, config.target_addr);
        assert_eq!(cloned.tls_enabled, config.tls_enabled);
        assert_eq!(cloned.block_mode, config.block_mode);
        assert_eq!(cloned.min_block_severity, config.min_block_severity);
        assert_eq!(cloned.verbose, config.verbose);
    }

    #[test]
    fn test_config_debug() {
        let config = ProxyConfig::default();
        let debug_str = format!("{:?}", config);

        assert!(debug_str.contains("ProxyConfig"));
        assert!(debug_str.contains("listen_addr"));
        assert!(debug_str.contains("target_addr"));
    }

    #[test]
    fn test_new_with_specific_addresses() {
        let config = ProxyConfig::new(
            "192.168.1.1:8888".parse().unwrap(),
            "10.0.0.1:3333".parse().unwrap(),
        );

        assert_eq!(config.listen_addr.ip().to_string(), "192.168.1.1");
        assert_eq!(config.listen_addr.port(), 8888);
        assert_eq!(config.target_addr.ip().to_string(), "10.0.0.1");
        assert_eq!(config.target_addr.port(), 3333);
    }

    #[test]
    fn test_chained_builder() {
        let log_path = PathBuf::from("/tmp/test.log");
        let cert_path = PathBuf::from("/tmp/cert.pem");
        let key_path = PathBuf::from("/tmp/key.pem");

        let config = ProxyConfig::default()
            .with_tls_files(cert_path.clone(), key_path.clone())
            .with_block_mode(crate::Severity::Low)
            .with_log_file(log_path.clone())
            .with_verbose();

        assert!(config.tls_enabled);
        assert_eq!(config.tls_cert_file, Some(cert_path));
        assert_eq!(config.tls_key_file, Some(key_path));
        assert!(config.block_mode);
        assert_eq!(config.min_block_severity, crate::Severity::Low);
        assert_eq!(config.log_file, Some(log_path));
        assert!(config.verbose);
    }
}
