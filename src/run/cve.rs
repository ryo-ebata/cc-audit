//! CVE database scanning for dependency vulnerabilities.

use crate::{CveDatabase, DirectoryWalker, Finding, WalkConfig};
use std::fs;
use std::path::Path;
use tracing::{debug, info};

/// Files that may contain version information for CVE checking.
const CVE_RELEVANT_FILES: &[&str] = &[
    "package.json",
    "package-lock.json",
    "extensions.json",
    "mcp.json",
    "mcp_config.json",
];

/// Scan a path for CVE vulnerabilities in dependencies.
pub fn scan_path_with_cve_db(path: &Path, db: &CveDatabase) -> Vec<Finding> {
    let mut findings = Vec::new();

    if path.is_file() {
        if let Some(name) = path.file_name().and_then(|n| n.to_str())
            && CVE_RELEVANT_FILES.contains(&name)
            && let Ok(content) = fs::read_to_string(path)
        {
            debug!(path = %path.display(), "Checking file for CVE vulnerabilities");
            findings.extend(check_content_for_cves(&content, path, db));
        }
    } else if path.is_dir() {
        debug!(path = %path.display(), "Scanning directory for CVE vulnerabilities");
        let walker = DirectoryWalker::new(WalkConfig::default());
        for file_path in walker.walk_single(path) {
            if let Some(name) = file_path.file_name().and_then(|n| n.to_str())
                && CVE_RELEVANT_FILES.contains(&name)
                && let Ok(content) = fs::read_to_string(&file_path)
            {
                findings.extend(check_content_for_cves(&content, &file_path, db));
            }
        }
    }

    findings
}

/// Check file content for known CVEs.
fn check_content_for_cves(content: &str, path: &Path, db: &CveDatabase) -> Vec<Finding> {
    let mut findings = Vec::new();
    let path_str = path.display().to_string();

    // Try to parse as JSON for structured version extraction
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        // Check for npm packages in dependencies
        for dep_key in ["dependencies", "devDependencies", "peerDependencies"] {
            if let Some(deps) = json.get(dep_key).and_then(|d| d.as_object()) {
                for (package, version_val) in deps {
                    if let Some(version) = version_val.as_str() {
                        // Extract version number (remove ^, ~, etc.)
                        let clean_version =
                            version.trim_start_matches(|c: char| !c.is_ascii_digit());

                        // Check for known vulnerable packages
                        // mcp-inspector -> anthropic/mcp-inspector
                        if package == "mcp-inspector" || package == "@anthropic/mcp-inspector" {
                            findings.extend(db.create_findings(
                                "anthropic",
                                "mcp-inspector",
                                clean_version,
                                &path_str,
                                1,
                            ));
                        }
                        // mcp-remote -> geelen/mcp-remote
                        if package == "mcp-remote" || package == "@geelen/mcp-remote" {
                            findings.extend(db.create_findings(
                                "geelen",
                                "mcp-remote",
                                clean_version,
                                &path_str,
                                1,
                            ));
                        }
                    }
                }
            }
        }

        // Check for VS Code extensions (in extensions.json)
        if path.file_name().and_then(|n| n.to_str()) == Some("extensions.json")
            && let Some(recommendations) = json.get("recommendations").and_then(|r| r.as_array())
        {
            for ext in recommendations {
                if let Some(ext_id) = ext.as_str() {
                    // claude-code extension: anthropic.claude-code
                    if ext_id.to_lowercase().contains("claude-code") {
                        // For extension recommendations, we can't get version easily
                        // Just warn that this extension may be affected
                        info!(
                            path = %path_str,
                            "Claude Code extension detected. Please ensure it's updated to v1.5.0+"
                        );
                    }
                }
            }
        }

        // Check for MCP server configurations that might reference known packages
        if let Some(servers) = json.get("mcpServers").and_then(|s| s.as_object()) {
            for (server_name, server_config) in servers {
                // Check for mcp-remote usage
                if let Some(command) = server_config.get("command").and_then(|c| c.as_str())
                    && (command.contains("mcp-remote") || command.contains("npx mcp-remote"))
                {
                    // Try to find version from args or assume latest
                    findings.extend(db.create_findings(
                        "geelen",
                        "mcp-remote",
                        "0.0.0", // Unknown version - will match all affected
                        &path_str,
                        1,
                    ));
                }

                // Check if server_name suggests mcp-inspector usage
                if server_name.contains("inspector")
                    || server_config
                        .get("command")
                        .and_then(|c| c.as_str())
                        .is_some_and(|c| c.contains("mcp-inspector"))
                {
                    findings.extend(db.create_findings(
                        "anthropic",
                        "mcp-inspector",
                        "0.0.0", // Unknown version
                        &path_str,
                        1,
                    ));
                }
            }
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_scan_path_with_cve_db_empty() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "Not a relevant file").unwrap();

        let db = CveDatabase::default();
        let findings = scan_path_with_cve_db(&file_path, &db);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_path_with_cve_db_package_json() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("package.json");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            r#"{{
            "dependencies": {{
                "express": "^4.0.0"
            }}
        }}"#
        )
        .unwrap();

        let db = CveDatabase::default();
        let findings = scan_path_with_cve_db(&file_path, &db);
        // No CVEs for express in our database
        assert!(findings.is_empty());
    }

    #[test]
    fn test_cve_relevant_files() {
        assert!(CVE_RELEVANT_FILES.contains(&"package.json"));
        assert!(CVE_RELEVANT_FILES.contains(&"package-lock.json"));
        assert!(CVE_RELEVANT_FILES.contains(&"extensions.json"));
        assert!(CVE_RELEVANT_FILES.contains(&"mcp.json"));
        assert!(CVE_RELEVANT_FILES.contains(&"mcp_config.json"));
    }
}
