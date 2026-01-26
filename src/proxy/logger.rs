//! JSONL logger for proxy traffic.

use crate::rules::Finding;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;

/// Direction of the proxied message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageDirection {
    /// Request from client to server
    Request,
    /// Response from server to client
    Response,
}

/// Log entry for a proxied message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyLog {
    /// Timestamp of the log entry
    pub timestamp: String,

    /// Direction of the message
    pub direction: MessageDirection,

    /// JSON-RPC method (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,

    /// Findings from security analysis
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<FindingSummary>,

    /// Action taken
    pub action: String,

    /// Client address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_addr: Option<String>,

    /// Message size in bytes
    pub size: usize,
}

/// Summary of a finding for logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    /// Rule ID
    pub id: String,
    /// Severity level
    pub severity: String,
    /// Message
    pub message: String,
}

impl From<&Finding> for FindingSummary {
    fn from(f: &Finding) -> Self {
        Self {
            id: f.id.clone(),
            severity: format!("{:?}", f.severity).to_lowercase(),
            message: f.message.clone(),
        }
    }
}

/// Logger for proxy traffic.
#[derive(Default)]
pub struct ProxyLogger {
    /// File writer (if logging to file)
    writer: Option<Mutex<BufWriter<File>>>,

    /// Verbose mode (log to stderr)
    verbose: bool,
}

impl ProxyLogger {
    /// Create a new logger with optional file output.
    pub fn new(log_path: Option<&Path>, verbose: bool) -> std::io::Result<Self> {
        let writer = if let Some(path) = log_path {
            let file = OpenOptions::new().create(true).append(true).open(path)?;
            Some(Mutex::new(BufWriter::new(file)))
        } else {
            None
        };

        Ok(Self { writer, verbose })
    }

    /// Log a message.
    pub fn log(&self, entry: &ProxyLog) {
        // Serialize to JSON
        let json = match serde_json::to_string(entry) {
            Ok(j) => j,
            Err(e) => {
                eprintln!("Failed to serialize log entry: {}", e);
                return;
            }
        };

        // Write to file if configured
        if let Some(ref writer) = self.writer
            && let Ok(mut w) = writer.lock()
        {
            let _ = writeln!(w, "{}", json);
            let _ = w.flush();
        }

        // Print to stderr in verbose mode
        if self.verbose {
            eprintln!("[PROXY] {}", json);
        }
    }

    /// Log a request.
    pub fn log_request(
        &self,
        method: Option<&str>,
        findings: &[Finding],
        action: &str,
        client_addr: Option<&str>,
        size: usize,
    ) {
        let entry = ProxyLog {
            timestamp: chrono::Utc::now().to_rfc3339(),
            direction: MessageDirection::Request,
            method: method.map(|s| s.to_string()),
            findings: findings.iter().map(FindingSummary::from).collect(),
            action: action.to_string(),
            client_addr: client_addr.map(|s| s.to_string()),
            size,
        };

        self.log(&entry);
    }

    /// Log a response.
    pub fn log_response(
        &self,
        method: Option<&str>,
        findings: &[Finding],
        action: &str,
        client_addr: Option<&str>,
        size: usize,
    ) {
        let entry = ProxyLog {
            timestamp: chrono::Utc::now().to_rfc3339(),
            direction: MessageDirection::Response,
            method: method.map(|s| s.to_string()),
            findings: findings.iter().map(FindingSummary::from).collect(),
            action: action.to_string(),
            client_addr: client_addr.map(|s| s.to_string()),
            size,
        };

        self.log(&entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_log_to_file() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("proxy.jsonl");

        let logger = ProxyLogger::new(Some(&log_path), false).unwrap();

        logger.log_request(
            Some("tools/call"),
            &[],
            "allowed",
            Some("127.0.0.1:12345"),
            100,
        );

        // Read the file
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("tools/call"));
        assert!(content.contains("allowed"));
        assert!(content.contains("request"));
    }

    #[test]
    fn test_finding_summary() {
        use crate::rules::{Category, Severity};
        use crate::test_utils::fixtures::create_finding;

        let finding = create_finding(
            "EX-001",
            Severity::High,
            Category::Exfiltration,
            "Test finding",
            "test.md",
            1,
        );

        let summary = FindingSummary::from(&finding);

        assert_eq!(summary.id, "EX-001");
        assert_eq!(summary.severity, "high");
        assert!(summary.message.contains("test message"));
    }

    #[test]
    fn test_default_logger() {
        let logger = ProxyLogger::default();

        // Should not panic
        logger.log_request(None, &[], "allowed", None, 0);
    }

    #[test]
    fn test_log_response() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("proxy.jsonl");

        let logger = ProxyLogger::new(Some(&log_path), false).unwrap();

        logger.log_response(
            Some("tools/call"),
            &[],
            "allowed",
            Some("127.0.0.1:12345"),
            100,
        );

        // Read the file
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("tools/call"));
        assert!(content.contains("allowed"));
        assert!(content.contains("response"));
    }

    #[test]
    fn test_log_with_findings() {
        use crate::rules::{Category, Severity};
        use crate::test_utils::fixtures::create_finding;

        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("proxy.jsonl");

        let logger = ProxyLogger::new(Some(&log_path), false).unwrap();

        let finding = create_finding(
            "EX-001",
            Severity::High,
            Category::Exfiltration,
            "test",
            "test.md",
            1,
        );

        logger.log_request(
            Some("tools/call"),
            &[finding],
            "blocked",
            Some("127.0.0.1:12345"),
            100,
        );

        // Read the file
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("EX-001"));
        assert!(content.contains("blocked"));
    }

    #[test]
    fn test_log_without_method() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("proxy.jsonl");

        let logger = ProxyLogger::new(Some(&log_path), false).unwrap();

        logger.log_request(None, &[], "allowed", Some("127.0.0.1:12345"), 100);

        // Read the file
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("request"));
        assert!(!content.contains("method"));
    }

    #[test]
    fn test_log_without_client_addr() {
        let temp_dir = TempDir::new().unwrap();
        let log_path = temp_dir.path().join("proxy.jsonl");

        let logger = ProxyLogger::new(Some(&log_path), false).unwrap();

        logger.log_request(Some("test"), &[], "allowed", None, 100);

        // Read the file
        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(content.contains("test"));
        assert!(!content.contains("client_addr"));
    }

    #[test]
    fn test_message_direction_serialization() {
        let request_json = serde_json::to_string(&MessageDirection::Request).unwrap();
        assert_eq!(request_json, "\"request\"");

        let response_json = serde_json::to_string(&MessageDirection::Response).unwrap();
        assert_eq!(response_json, "\"response\"");
    }

    #[test]
    fn test_message_direction_deserialization() {
        let request: MessageDirection = serde_json::from_str("\"request\"").unwrap();
        assert_eq!(request, MessageDirection::Request);

        let response: MessageDirection = serde_json::from_str("\"response\"").unwrap();
        assert_eq!(response, MessageDirection::Response);
    }

    #[test]
    fn test_proxy_log_serialization() {
        let log = ProxyLog {
            timestamp: "2024-01-01T00:00:00Z".to_string(),
            direction: MessageDirection::Request,
            method: Some("test".to_string()),
            findings: vec![],
            action: "allowed".to_string(),
            client_addr: Some("127.0.0.1:8080".to_string()),
            size: 100,
        };

        let json = serde_json::to_string(&log).unwrap();
        assert!(json.contains("2024-01-01"));
        assert!(json.contains("request"));
        assert!(json.contains("test"));
        assert!(json.contains("allowed"));
    }

    #[test]
    fn test_proxy_log_deserialization() {
        let json = r#"{
            "timestamp": "2024-01-01T00:00:00Z",
            "direction": "response",
            "method": "tools/call",
            "findings": [],
            "action": "logged",
            "client_addr": "127.0.0.1:9999",
            "size": 200
        }"#;

        let log: ProxyLog = serde_json::from_str(json).unwrap();
        assert_eq!(log.timestamp, "2024-01-01T00:00:00Z");
        assert_eq!(log.direction, MessageDirection::Response);
        assert_eq!(log.method, Some("tools/call".to_string()));
        assert_eq!(log.action, "logged");
        assert_eq!(log.size, 200);
    }

    #[test]
    fn test_finding_summary_serialization() {
        let summary = FindingSummary {
            id: "TEST-001".to_string(),
            severity: "high".to_string(),
            message: "Test message".to_string(),
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("TEST-001"));
        assert!(json.contains("high"));
        assert!(json.contains("Test message"));
    }
}
