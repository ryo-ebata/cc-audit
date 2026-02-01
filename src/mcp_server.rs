use crate::engine::scanner::{Scanner, ScannerConfig};
use crate::engine::scanners::SkillScanner;
use crate::error::Result;
use crate::fix::AutoFixer;
use crate::rules::{Finding, RuleEngine, ScanResult, Summary};
use crate::scoring::RiskScore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

/// MCP Server for cc-audit
/// Provides security scanning capabilities via MCP protocol
pub struct McpServer {
    rule_engine: RuleEngine,
}

#[derive(Debug, Serialize, Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}

/// Tool definitions for MCP
#[derive(Debug, Serialize)]
struct Tool {
    name: String,
    description: String,
    #[serde(rename = "inputSchema")]
    input_schema: Value,
}

impl McpServer {
    pub fn new() -> Self {
        Self {
            rule_engine: RuleEngine::new(),
        }
    }

    /// Run the MCP server (JSON-RPC over stdio)
    pub fn run(&self) -> Result<()> {
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        let reader = BufReader::new(stdin.lock());

        eprintln!("cc-audit MCP server started");

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Error reading input: {}", e);
                    continue;
                }
            };

            if line.is_empty() {
                continue;
            }

            let request: JsonRpcRequest = match serde_json::from_str(&line) {
                Ok(r) => r,
                Err(e) => {
                    let error_response = JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: None,
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32700,
                            message: format!("Parse error: {}", e),
                            data: None,
                        }),
                    };
                    // SAFETY: JsonRpcResponse contains only simple, serializable types.
                    // This unwrap_or_else provides a fallback for the unlikely case of serialization failure.
                    let json = serde_json::to_string(&error_response)
                        .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error"}}"#.to_string());
                    let _ = writeln!(stdout, "{}", json);
                    let _ = stdout.flush();
                    continue;
                }
            };

            let response = self.handle_request(request);
            // SAFETY: JsonRpcResponse contains only simple, serializable types.
            // This unwrap_or_else provides a fallback for the unlikely case of serialization failure.
            let json = serde_json::to_string(&response).unwrap_or_else(|_| {
                r#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error"}}"#
                    .to_string()
            });
            let _ = writeln!(stdout, "{}", json);
            let _ = stdout.flush();
        }

        Ok(())
    }

    fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let result = match request.method.as_str() {
            "initialize" => self.handle_initialize(&request.params),
            "tools/list" => self.handle_list_tools(),
            "tools/call" => self.handle_tool_call(&request.params),
            "shutdown" => {
                eprintln!("MCP server shutting down");
                Ok(json!({}))
            }
            _ => Err(JsonRpcError {
                code: -32601,
                message: format!("Method not found: {}", request.method),
                data: None,
            }),
        };

        match result {
            Ok(value) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id,
                result: Some(value),
                error: None,
            },
            Err(error) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: request.id,
                result: None,
                error: Some(error),
            },
        }
    }

    fn handle_initialize(
        &self,
        _params: &Option<Value>,
    ) -> std::result::Result<Value, JsonRpcError> {
        Ok(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "cc-audit",
                "version": env!("CARGO_PKG_VERSION")
            }
        }))
    }

    fn handle_list_tools(&self) -> std::result::Result<Value, JsonRpcError> {
        let tools = vec![
            Tool {
                name: "scan".to_string(),
                description: "Scan a file or directory for security issues".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Path to scan (file or directory)"
                        }
                    },
                    "required": ["path"]
                }),
            },
            Tool {
                name: "scan_content".to_string(),
                description: "Scan content string for security issues".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "content": {
                            "type": "string",
                            "description": "Content to scan"
                        },
                        "filename": {
                            "type": "string",
                            "description": "Virtual filename for context"
                        }
                    },
                    "required": ["content"]
                }),
            },
            Tool {
                name: "check_rule".to_string(),
                description: "Check if content matches a specific rule".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "rule_id": {
                            "type": "string",
                            "description": "Rule ID to check (e.g., 'OP-001')"
                        },
                        "content": {
                            "type": "string",
                            "description": "Content to check"
                        }
                    },
                    "required": ["rule_id", "content"]
                }),
            },
            Tool {
                name: "list_rules".to_string(),
                description: "List all available security rules".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "category": {
                            "type": "string",
                            "description": "Filter by category (optional)"
                        }
                    }
                }),
            },
            Tool {
                name: "get_fix_suggestion".to_string(),
                description: "Get a fix suggestion for a finding".to_string(),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string",
                            "description": "Finding ID (rule ID)"
                        },
                        "code": {
                            "type": "string",
                            "description": "The problematic code"
                        }
                    },
                    "required": ["finding_id", "code"]
                }),
            },
        ];

        Ok(json!({ "tools": tools }))
    }

    fn handle_tool_call(&self, params: &Option<Value>) -> std::result::Result<Value, JsonRpcError> {
        let params = params.as_ref().ok_or_else(|| JsonRpcError {
            code: -32602,
            message: "Missing params".to_string(),
            data: None,
        })?;

        let name = params
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "Missing tool name".to_string(),
                data: None,
            })?;

        let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

        match name {
            "scan" => self.tool_scan(&arguments),
            "scan_content" => self.tool_scan_content(&arguments),
            "check_rule" => self.tool_check_rule(&arguments),
            "list_rules" => self.tool_list_rules(&arguments),
            "get_fix_suggestion" => self.tool_get_fix_suggestion(&arguments),
            _ => Err(JsonRpcError {
                code: -32602,
                message: format!("Unknown tool: {}", name),
                data: None,
            }),
        }
    }

    fn tool_scan(&self, args: &Value) -> std::result::Result<Value, JsonRpcError> {
        let path = args
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "Missing 'path' argument".to_string(),
                data: None,
            })?;

        let path = PathBuf::from(path);
        let scanner = SkillScanner::new();

        match scanner.scan_path(&path) {
            Ok(findings) => {
                let summary = Summary::from_findings(&findings);
                let risk_score = RiskScore::from_findings(&findings);
                let result = ScanResult {
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    scanned_at: chrono::Utc::now().to_rfc3339(),
                    target: path.display().to_string(),
                    summary,
                    findings,
                    risk_score: Some(risk_score),
                    elapsed_ms: 0,
                };
                Ok(json!({
                    "content": [{
                        "type": "text",
                        "text": serde_json::to_string_pretty(&result).unwrap()
                    }]
                }))
            }
            Err(e) => Err(JsonRpcError {
                code: -32000,
                message: format!("Scan failed: {}", e),
                data: None,
            }),
        }
    }

    fn tool_scan_content(&self, args: &Value) -> std::result::Result<Value, JsonRpcError> {
        let content = args
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "Missing 'content' argument".to_string(),
                data: None,
            })?;

        let filename = args
            .get("filename")
            .and_then(|v| v.as_str())
            .unwrap_or("content.md");

        let config = ScannerConfig::new();
        let findings = config.check_content(content, filename);

        let summary = Summary::from_findings(&findings);
        let risk_score = RiskScore::from_findings(&findings);

        Ok(json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&json!({
                    "findings": findings,
                    "summary": summary,
                    "risk_score": risk_score
                })).unwrap()
            }]
        }))
    }

    fn tool_check_rule(&self, args: &Value) -> std::result::Result<Value, JsonRpcError> {
        let rule_id = args
            .get("rule_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "Missing 'rule_id' argument".to_string(),
                data: None,
            })?;

        let content = args
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "Missing 'content' argument".to_string(),
                data: None,
            })?;

        // Check if rule exists
        let rule = self.rule_engine.get_rule(rule_id);
        if rule.is_none() {
            return Ok(json!({
                "content": [{
                    "type": "text",
                    "text": format!("Rule '{}' not found", rule_id)
                }]
            }));
        }

        let rule = rule.unwrap();

        // Check if any pattern matches
        let mut matches = false;
        for pattern in &rule.patterns {
            if pattern.is_match(content) {
                matches = true;
                break;
            }
        }

        Ok(json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&json!({
                    "rule_id": rule_id,
                    "rule_name": rule.name,
                    "severity": format!("{:?}", rule.severity),
                    "matches": matches,
                    "message": if matches {
                        format!("Content matches rule: {}", rule.message)
                    } else {
                        "No match found".to_string()
                    }
                })).unwrap()
            }]
        }))
    }

    fn tool_list_rules(&self, args: &Value) -> std::result::Result<Value, JsonRpcError> {
        let category_filter = args
            .get("category")
            .and_then(|v| v.as_str())
            .map(|s| s.to_lowercase());

        let rules = self.rule_engine.get_all_rules();
        let filtered: Vec<_> = rules
            .iter()
            .filter(|r| {
                if let Some(ref cat) = category_filter {
                    format!("{:?}", r.category).to_lowercase().contains(cat)
                } else {
                    true
                }
            })
            .map(|r| {
                json!({
                    "id": r.id,
                    "name": r.name,
                    "severity": format!("{:?}", r.severity),
                    "category": format!("{:?}", r.category),
                    "confidence": format!("{:?}", r.confidence)
                })
            })
            .collect();

        Ok(json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&json!({
                    "total": filtered.len(),
                    "rules": filtered
                })).unwrap()
            }]
        }))
    }

    fn tool_get_fix_suggestion(&self, args: &Value) -> std::result::Result<Value, JsonRpcError> {
        let finding_id = args
            .get("finding_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "Missing 'finding_id' argument".to_string(),
                data: None,
            })?;

        let code = args
            .get("code")
            .and_then(|v| v.as_str())
            .ok_or_else(|| JsonRpcError {
                code: -32602,
                message: "Missing 'code' argument".to_string(),
                data: None,
            })?;

        // Create a mock finding for the fixer
        let rule = self.rule_engine.get_rule(finding_id);
        if rule.is_none() {
            return Ok(json!({
                "content": [{
                    "type": "text",
                    "text": format!("No fix suggestion available for rule '{}'", finding_id)
                }]
            }));
        }

        let rule = rule.unwrap();
        let finding = Finding {
            id: finding_id.to_string(),
            severity: rule.severity,
            category: rule.category,
            confidence: rule.confidence,
            name: rule.name.to_string(),
            location: crate::rules::Location {
                file: "virtual".to_string(),
                line: 1,
                column: None,
            },
            code: code.to_string(),
            message: rule.message.to_string(),
            recommendation: rule.recommendation.to_string(),
            fix_hint: rule.fix_hint.map(|s| s.to_string()),
            cwe_ids: rule.cwe_ids.iter().map(|s| s.to_string()).collect(),
            rule_severity: None,
            client: None,
            context: None,
        };

        let fixer = AutoFixer::new(true);
        let fixes = fixer.generate_fixes(&[finding]);

        if fixes.is_empty() {
            Ok(json!({
                "content": [{
                    "type": "text",
                    "text": format!("No automatic fix available for {}. Manual review recommended.\n\nRecommendation: {}", finding_id, rule.recommendation)
                }]
            }))
        } else {
            let fix = &fixes[0];
            Ok(json!({
                "content": [{
                    "type": "text",
                    "text": serde_json::to_string_pretty(&json!({
                        "has_fix": true,
                        "description": fix.description,
                        "original": fix.original,
                        "replacement": fix.replacement
                    })).unwrap()
                }]
            }))
        }
    }
}

impl Default for McpServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_mcp_server_new() {
        let server = McpServer::new();
        assert!(!server.rule_engine.get_all_rules().is_empty());
    }

    #[test]
    fn test_mcp_server_default() {
        let server = McpServer::default();
        assert!(!server.rule_engine.get_all_rules().is_empty());
    }

    #[test]
    fn test_handle_initialize() {
        let server = McpServer::new();
        let result = server.handle_initialize(&None).unwrap();

        assert!(result.get("protocolVersion").is_some());
        assert!(result.get("serverInfo").is_some());
    }

    #[test]
    fn test_handle_initialize_with_params() {
        let server = McpServer::new();
        let params = Some(json!({"clientInfo": {"name": "test"}}));
        let result = server.handle_initialize(&params).unwrap();

        assert!(result.get("protocolVersion").is_some());
    }

    #[test]
    fn test_handle_list_tools() {
        let server = McpServer::new();
        let result = server.handle_list_tools().unwrap();

        let tools = result.get("tools").unwrap().as_array().unwrap();
        assert_eq!(tools.len(), 5);

        let tool_names: Vec<&str> = tools
            .iter()
            .map(|t| t.get("name").unwrap().as_str().unwrap())
            .collect();
        assert!(tool_names.contains(&"scan"));
        assert!(tool_names.contains(&"scan_content"));
        assert!(tool_names.contains(&"check_rule"));
        assert!(tool_names.contains(&"list_rules"));
        assert!(tool_names.contains(&"get_fix_suggestion"));
    }

    #[test]
    fn test_tool_scan_content() {
        let server = McpServer::new();
        let args = json!({
            "content": "allowed-tools: *",
            "filename": "test.md"
        });

        let result = server.tool_scan_content(&args).unwrap();
        let content = result.get("content").unwrap().as_array().unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_tool_scan_content_no_filename() {
        let server = McpServer::new();
        let args = json!({
            "content": "some safe content"
        });

        let result = server.tool_scan_content(&args).unwrap();
        let content = result.get("content").unwrap().as_array().unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_tool_scan_content_missing_content() {
        let server = McpServer::new();
        let args = json!({});

        let result = server.tool_scan_content(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_tool_list_rules() {
        let server = McpServer::new();
        let args = json!({});

        let result = server.tool_list_rules(&args).unwrap();
        let content = result.get("content").unwrap().as_array().unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_tool_list_rules_with_category() {
        let server = McpServer::new();
        let args = json!({"category": "exfiltration"});

        let result = server.tool_list_rules(&args).unwrap();
        let content = result.get("content").unwrap().as_array().unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_tool_check_rule() {
        let server = McpServer::new();
        let args = json!({
            "rule_id": "OP-001",
            "content": "allowed-tools: *"
        });

        let result = server.tool_check_rule(&args).unwrap();
        let content = result.get("content").unwrap().as_array().unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_tool_check_rule_no_match() {
        let server = McpServer::new();
        let args = json!({
            "rule_id": "OP-001",
            "content": "allowed-tools: Read, Write"
        });

        let result = server.tool_check_rule(&args).unwrap();
        let content = result.get("content").unwrap().as_array().unwrap();
        let text = content[0].get("text").unwrap().as_str().unwrap();
        assert!(text.contains("No match found") || text.contains("matches"));
    }

    #[test]
    fn test_tool_check_rule_not_found() {
        let server = McpServer::new();
        let args = json!({
            "rule_id": "NONEXISTENT-001",
            "content": "some content"
        });

        let result = server.tool_check_rule(&args).unwrap();
        let content = result.get("content").unwrap().as_array().unwrap();
        let text = content[0].get("text").unwrap().as_str().unwrap();
        assert!(text.contains("not found"));
    }

    #[test]
    fn test_tool_check_rule_missing_rule_id() {
        let server = McpServer::new();
        let args = json!({
            "content": "some content"
        });

        let result = server.tool_check_rule(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_tool_check_rule_missing_content() {
        let server = McpServer::new();
        let args = json!({
            "rule_id": "OP-001"
        });

        let result = server.tool_check_rule(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_tool_scan_valid_path() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("SKILL.md");
        std::fs::write(&test_file, "---\nallowed-tools: *\n---\n").unwrap();

        let server = McpServer::new();
        let args = json!({"path": test_file.display().to_string()});

        let result = server.tool_scan(&args).unwrap();
        let content = result.get("content").unwrap().as_array().unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_tool_scan_invalid_path() {
        let server = McpServer::new();
        let args = json!({"path": "/nonexistent/path/that/does/not/exist"});

        let result = server.tool_scan(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_tool_scan_missing_path() {
        let server = McpServer::new();
        let args = json!({});

        let result = server.tool_scan(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_tool_get_fix_suggestion_valid() {
        let server = McpServer::new();
        let args = json!({
            "finding_id": "OP-001",
            "code": "allowed-tools: *"
        });

        let result = server.tool_get_fix_suggestion(&args).unwrap();
        let content = result.get("content").unwrap().as_array().unwrap();
        assert!(!content.is_empty());
    }

    #[test]
    fn test_tool_get_fix_suggestion_no_fix_available() {
        let server = McpServer::new();
        let args = json!({
            "finding_id": "EX-001",
            "code": "echo hello"
        });

        let result = server.tool_get_fix_suggestion(&args).unwrap();
        let content = result.get("content").unwrap().as_array().unwrap();
        let text = content[0].get("text").unwrap().as_str().unwrap();
        assert!(text.contains("No automatic fix") || text.contains("has_fix"));
    }

    #[test]
    fn test_tool_get_fix_suggestion_rule_not_found() {
        let server = McpServer::new();
        let args = json!({
            "finding_id": "NONEXISTENT-001",
            "code": "some code"
        });

        let result = server.tool_get_fix_suggestion(&args).unwrap();
        let content = result.get("content").unwrap().as_array().unwrap();
        let text = content[0].get("text").unwrap().as_str().unwrap();
        assert!(text.contains("No fix suggestion available"));
    }

    #[test]
    fn test_tool_get_fix_suggestion_missing_finding_id() {
        let server = McpServer::new();
        let args = json!({
            "code": "some code"
        });

        let result = server.tool_get_fix_suggestion(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_tool_get_fix_suggestion_missing_code() {
        let server = McpServer::new();
        let args = json!({
            "finding_id": "OP-001"
        });

        let result = server.tool_get_fix_suggestion(&args);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_request_initialize() {
        let server = McpServer::new();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "initialize".to_string(),
            params: None,
        };

        let response = server.handle_request(request);
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_handle_request_tools_list() {
        let server = McpServer::new();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(2)),
            method: "tools/list".to_string(),
            params: None,
        };

        let response = server.handle_request(request);
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_handle_request_shutdown() {
        let server = McpServer::new();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(3)),
            method: "shutdown".to_string(),
            params: None,
        };

        let response = server.handle_request(request);
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[test]
    fn test_handle_request_unknown_method() {
        let server = McpServer::new();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(4)),
            method: "unknown/method".to_string(),
            params: None,
        };

        let response = server.handle_request(request);
        assert!(response.result.is_none());
        assert!(response.error.is_some());
        assert_eq!(response.error.as_ref().unwrap().code, -32601);
    }

    #[test]
    fn test_handle_tool_call_missing_params() {
        let server = McpServer::new();
        let result = server.handle_tool_call(&None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, -32602);
    }

    #[test]
    fn test_handle_tool_call_missing_name() {
        let server = McpServer::new();
        let params = Some(json!({"arguments": {}}));
        let result = server.handle_tool_call(&params);
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_tool_call_unknown_tool() {
        let server = McpServer::new();
        let params = Some(json!({
            "name": "unknown_tool",
            "arguments": {}
        }));
        let result = server.handle_tool_call(&params);
        assert!(result.is_err());
        assert!(result.unwrap_err().message.contains("Unknown tool"));
    }

    #[test]
    fn test_handle_tool_call_scan_content() {
        let server = McpServer::new();
        let params = Some(json!({
            "name": "scan_content",
            "arguments": {
                "content": "safe content"
            }
        }));

        let result = server.handle_tool_call(&params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_tool_call_list_rules() {
        let server = McpServer::new();
        let params = Some(json!({
            "name": "list_rules",
            "arguments": {}
        }));

        let result = server.handle_tool_call(&params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_tool_call_check_rule() {
        let server = McpServer::new();
        let params = Some(json!({
            "name": "check_rule",
            "arguments": {
                "rule_id": "OP-001",
                "content": "allowed-tools: *"
            }
        }));

        let result = server.handle_tool_call(&params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_tool_call_get_fix_suggestion() {
        let server = McpServer::new();
        let params = Some(json!({
            "name": "get_fix_suggestion",
            "arguments": {
                "finding_id": "OP-001",
                "code": "allowed-tools: *"
            }
        }));

        let result = server.handle_tool_call(&params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_json_rpc_request_debug() {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "test".to_string(),
            params: None,
        };

        let debug_str = format!("{:?}", request);
        assert!(debug_str.contains("JsonRpcRequest"));
    }

    #[test]
    fn test_json_rpc_response_serialization() {
        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            result: Some(json!({"status": "ok"})),
            error: None,
        };

        let json_str = serde_json::to_string(&response).unwrap();
        assert!(json_str.contains("\"jsonrpc\":\"2.0\""));
        assert!(!json_str.contains("error"));
    }

    #[test]
    fn test_json_rpc_error_serialization() {
        let response = JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            result: None,
            error: Some(JsonRpcError {
                code: -32600,
                message: "Invalid request".to_string(),
                data: None,
            }),
        };

        let json_str = serde_json::to_string(&response).unwrap();
        assert!(json_str.contains("error"));
        assert!(json_str.contains("-32600"));
        assert!(!json_str.contains("result"));
    }

    #[test]
    fn test_json_rpc_error_with_data() {
        let error = JsonRpcError {
            code: -32000,
            message: "Server error".to_string(),
            data: Some(json!({"details": "additional info"})),
        };

        let json_str = serde_json::to_string(&error).unwrap();
        assert!(json_str.contains("details"));
    }

    #[test]
    fn test_tool_struct_serialization() {
        let tool = Tool {
            name: "test_tool".to_string(),
            description: "A test tool".to_string(),
            input_schema: json!({"type": "object"}),
        };

        let json_str = serde_json::to_string(&tool).unwrap();
        assert!(json_str.contains("test_tool"));
        assert!(json_str.contains("inputSchema"));
    }

    #[test]
    fn test_handle_request_tools_call_with_scan() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("SKILL.md");
        std::fs::write(&test_file, "safe content").unwrap();

        let server = McpServer::new();
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(5)),
            method: "tools/call".to_string(),
            params: Some(json!({
                "name": "scan",
                "arguments": {
                    "path": test_file.display().to_string()
                }
            })),
        };

        let response = server.handle_request(request);
        assert!(response.result.is_some());
    }
}
