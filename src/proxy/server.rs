//! Async TCP proxy server for MCP message interception.

use super::{InterceptAction, MessageInterceptor, ProxyConfig, ProxyLogger};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// TCP proxy server for MCP message interception.
pub struct ProxyServer {
    config: ProxyConfig,
    interceptor: Arc<MessageInterceptor>,
    logger: Arc<ProxyLogger>,
}

impl ProxyServer {
    /// Create a new proxy server with the given configuration.
    pub fn new(config: ProxyConfig) -> std::io::Result<Self> {
        let interceptor = Arc::new(MessageInterceptor::new(
            config.block_mode,
            config.min_block_severity,
        ));

        let logger = Arc::new(ProxyLogger::new(
            config.log_file.as_deref(),
            config.verbose,
        )?);

        Ok(Self {
            config,
            interceptor,
            logger,
        })
    }

    /// Run the proxy server.
    pub async fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr).await?;

        eprintln!(
            "Proxy listening on {} -> {}",
            self.config.listen_addr, self.config.target_addr
        );

        if self.config.block_mode {
            eprintln!(
                "Block mode enabled (min severity: {:?})",
                self.config.min_block_severity
            );
        } else {
            eprintln!("Log-only mode (no blocking)");
        }

        loop {
            let (client_stream, client_addr) = listener.accept().await?;

            let target_addr = self.config.target_addr;
            let interceptor = Arc::clone(&self.interceptor);
            let logger = Arc::clone(&self.logger);
            let block_mode = self.config.block_mode;

            tokio::spawn(async move {
                if let Err(e) = handle_connection(
                    client_stream,
                    target_addr,
                    interceptor,
                    logger,
                    block_mode,
                    client_addr.to_string(),
                )
                .await
                {
                    eprintln!("Connection error: {}", e);
                }
            });
        }
    }
}

/// Handle a single client connection.
async fn handle_connection(
    client: TcpStream,
    target_addr: std::net::SocketAddr,
    interceptor: Arc<MessageInterceptor>,
    logger: Arc<ProxyLogger>,
    block_mode: bool,
    client_addr: String,
) -> std::io::Result<()> {
    // Connect to target
    let target = TcpStream::connect(target_addr).await?;

    // Split into owned halves
    let (client_read, client_write) = client.into_split();
    let (target_read, target_write) = target.into_split();

    let interceptor_req = Arc::clone(&interceptor);
    let interceptor_resp = Arc::clone(&interceptor);
    let logger_req = Arc::clone(&logger);
    let logger_resp = Arc::clone(&logger);
    let client_addr_req = client_addr.clone();
    let client_addr_resp = client_addr;

    // Wrap writes in Arc<Mutex> for shared access
    let client_write = Arc::new(tokio::sync::Mutex::new(client_write));
    let target_write = Arc::new(tokio::sync::Mutex::new(target_write));

    let client_write_clone = Arc::clone(&client_write);

    // Forward client -> target
    let client_to_target = async move {
        let mut client_read = client_read;
        let mut buf = vec![0u8; 65536];
        loop {
            let n = client_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }

            let data = &buf[..n];

            // Intercept and analyze
            let action = interceptor_req.intercept(data);
            let method = extract_method(data);

            match &action {
                InterceptAction::Allow => {
                    target_write.lock().await.write_all(data).await?;
                }
                InterceptAction::Log(findings) => {
                    logger_req.log_request(
                        method.as_deref(),
                        findings,
                        "logged",
                        Some(&client_addr_req),
                        n,
                    );
                    target_write.lock().await.write_all(data).await?;
                }
                InterceptAction::Block(findings) => {
                    logger_req.log_request(
                        method.as_deref(),
                        findings,
                        "blocked",
                        Some(&client_addr_req),
                        n,
                    );

                    if block_mode {
                        // Send error response to client
                        let error_response = create_error_response(findings);
                        client_write
                            .lock()
                            .await
                            .write_all(error_response.as_bytes())
                            .await?;
                        break;
                    } else {
                        target_write.lock().await.write_all(data).await?;
                    }
                }
            }
        }
        Ok::<_, std::io::Error>(())
    };

    // Forward target -> client
    let target_to_client = async move {
        let mut target_read = target_read;
        let mut buf = vec![0u8; 65536];
        loop {
            let n = target_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }

            let data = &buf[..n];

            // Intercept and analyze response
            let action = interceptor_resp.intercept(data);
            let method = extract_method(data);

            match &action {
                InterceptAction::Allow => {
                    client_write_clone.lock().await.write_all(data).await?;
                }
                InterceptAction::Log(findings) => {
                    logger_resp.log_response(
                        method.as_deref(),
                        findings,
                        "logged",
                        Some(&client_addr_resp),
                        n,
                    );
                    client_write_clone.lock().await.write_all(data).await?;
                }
                InterceptAction::Block(findings) => {
                    logger_resp.log_response(
                        method.as_deref(),
                        findings,
                        "blocked",
                        Some(&client_addr_resp),
                        n,
                    );

                    if block_mode {
                        // Don't forward blocked response
                        let error_response = create_error_response(findings);
                        client_write_clone
                            .lock()
                            .await
                            .write_all(error_response.as_bytes())
                            .await?;
                        break;
                    } else {
                        client_write_clone.lock().await.write_all(data).await?;
                    }
                }
            }
        }
        Ok::<_, std::io::Error>(())
    };

    // Run both directions concurrently
    tokio::select! {
        result = client_to_target => result?,
        result = target_to_client => result?,
    }

    Ok(())
}

/// Extract the JSON-RPC method from a message.
fn extract_method(data: &[u8]) -> Option<String> {
    let json: serde_json::Value = serde_json::from_slice(data).ok()?;
    json.get("method")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string())
}

/// Create a JSON-RPC error response for blocked messages.
fn create_error_response(findings: &[crate::rules::Finding]) -> String {
    let messages: Vec<String> = findings.iter().map(|f| f.message.clone()).collect();
    let error_msg = if messages.is_empty() {
        "Request blocked by security policy".to_string()
    } else {
        format!("Request blocked: {}", messages.join("; "))
    };

    serde_json::json!({
        "jsonrpc": "2.0",
        "error": {
            "code": -32600,
            "message": error_msg
        },
        "id": null
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::ProxyConfig;
    use crate::test_utils::fixtures::create_finding;

    #[test]
    fn test_extract_method() {
        let data = br#"{"jsonrpc":"2.0","method":"tools/call","id":1}"#;
        let method = extract_method(data);
        assert_eq!(method, Some("tools/call".to_string()));
    }

    #[test]
    fn test_extract_method_no_method() {
        let data = br#"{"jsonrpc":"2.0","result":{},"id":1}"#;
        let method = extract_method(data);
        assert!(method.is_none());
    }

    #[test]
    fn test_extract_method_invalid_json() {
        let data = b"not valid json";
        let method = extract_method(data);
        assert!(method.is_none());
    }

    #[test]
    fn test_extract_method_method_not_string() {
        let data = br#"{"jsonrpc":"2.0","method":123,"id":1}"#;
        let method = extract_method(data);
        assert!(method.is_none());
    }

    #[test]
    fn test_create_error_response() {
        let findings = vec![];
        let response = create_error_response(&findings);

        assert!(response.contains("blocked by security policy"));
        assert!(response.contains("-32600"));
    }

    #[test]
    fn test_create_error_response_with_findings() {
        use crate::rules::{Category, Severity};

        let findings = vec![
            create_finding(
                "EX-001",
                Severity::High,
                Category::Exfiltration,
                "test",
                "test.md",
                1,
            ),
            create_finding(
                "PI-001",
                Severity::Medium,
                Category::PromptInjection,
                "test2",
                "test.md",
                2,
            ),
        ];

        let response = create_error_response(&findings);

        assert!(response.contains("Request blocked:"));
        assert!(response.contains("test message"));
        assert!(response.contains("-32600"));
    }

    #[test]
    fn test_proxy_server_new() {
        let config = ProxyConfig::default();
        let server = ProxyServer::new(config);

        assert!(server.is_ok());
    }

    #[test]
    fn test_proxy_server_new_with_verbose() {
        let config = ProxyConfig::default().with_verbose();
        let server = ProxyServer::new(config);

        assert!(server.is_ok());
    }

    #[test]
    fn test_proxy_server_new_with_log_file() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("proxy.log");

        let config = ProxyConfig::default().with_log_file(log_path);
        let server = ProxyServer::new(config);

        assert!(server.is_ok());
    }

    #[test]
    fn test_proxy_server_new_with_block_mode() {
        use crate::Severity;

        let config = ProxyConfig::default().with_block_mode(Severity::High);
        let server = ProxyServer::new(config);

        assert!(server.is_ok());
    }
}
