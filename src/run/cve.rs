//! CVE database scanning for dependency vulnerabilities.

use crate::{CveDatabase, DirectoryWalker, Finding, IgnoreFilter, WalkConfig};
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
///
/// The `ignore_filter` parameter is used to skip files/directories that match
/// the ignore patterns configured in `.cc-audit.yaml`.
pub fn scan_path_with_cve_db(
    path: &Path,
    db: &CveDatabase,
    ignore_filter: &IgnoreFilter,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    if path.is_file() {
        if !ignore_filter.is_ignored(path)
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
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
            if !ignore_filter.is_ignored(&file_path)
                && let Some(name) = file_path.file_name().and_then(|n| n.to_str())
                && CVE_RELEVANT_FILES.contains(&name)
                && let Ok(content) = fs::read_to_string(&file_path)
            {
                findings.extend(check_content_for_cves(&content, &file_path, db));
            }
        }
    }

    findings
}

/// Map a known npm package name + version to CVE findings.
///
/// The shipped CVE database records both flagship MCP packages under the
/// `modelcontextprotocol` vendor (issue #149); historical vendor strings
/// (`geelen`/`anthropic`) never matched. Centralizing the mapping means every
/// extraction path (package.json ranges, lockfile `packages`, lockfile v1
/// object deps, mcpServers) shares one correct implementation.
fn check_npm_package(
    db: &CveDatabase,
    package: &str,
    version: &str,
    path_str: &str,
) -> Vec<Finding> {
    // Extract version number (remove ^, ~, etc.).
    let clean_version = version.trim_start_matches(|c: char| !c.is_ascii_digit());

    // Normalize scoped aliases to the canonical product name recorded in the DB,
    // then match by product name across any vendor (issue #149).
    let product = match package {
        "@anthropic/mcp-inspector" => "mcp-inspector",
        "@geelen/mcp-remote" => "mcp-remote",
        other => other,
    };

    db.create_findings_by_product(product, clean_version, path_str, 1)
}

/// Extract a version string from a dependency value that may be either a bare
/// version string (`package.json`, lockfile v1 shorthand) or an object carrying
/// a `version` field (lockfile v1 `dependencies`, lockfile v2/3 `packages`).
fn dependency_version(value: &serde_json::Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.get("version").and_then(|v| v.as_str()))
}

/// Check file content for known CVEs.
fn check_content_for_cves(content: &str, path: &Path, db: &CveDatabase) -> Vec<Finding> {
    let mut findings = Vec::new();
    let path_str = path.display().to_string();

    // Try to parse as JSON for structured version extraction
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
        // Check for npm packages in dependencies. Values may be strings
        // (package.json ranges) or objects (lockfileVersion 1 tree), so extract
        // the version from either shape (issue #153).
        for dep_key in ["dependencies", "devDependencies", "peerDependencies"] {
            if let Some(deps) = json.get(dep_key).and_then(|d| d.as_object()) {
                for (package, version_val) in deps {
                    if let Some(version) = dependency_version(version_val) {
                        findings.extend(check_npm_package(db, package, version, &path_str));
                    }
                }
            }
        }

        // lockfileVersion 2/3 has no top-level `dependencies`; the resolved tree
        // lives under `packages`, keyed by `node_modules/<name>` (issue #153).
        if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
            for (pkg_path, meta) in packages {
                // Derive the package name from the last `node_modules/` segment;
                // skip the root entry (empty key).
                if let Some((_, name)) = pkg_path.rsplit_once("node_modules/")
                    && let Some(version) = meta.get("version").and_then(|v| v.as_str())
                {
                    findings.extend(check_npm_package(db, name, version, &path_str));
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
                    findings.extend(db.create_findings_by_product(
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
                    findings.extend(db.create_findings_by_product(
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
    use crate::config::IgnoreConfig;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_default_filter(_path: &Path) -> IgnoreFilter {
        IgnoreFilter::from_config(&IgnoreConfig::default())
    }

    #[test]
    fn test_scan_path_with_cve_db_empty() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "Not a relevant file").unwrap();

        let db = CveDatabase::default();
        let filter = create_default_filter(temp_dir.path());
        let findings = scan_path_with_cve_db(&file_path, &db, &filter);
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
        let filter = create_default_filter(temp_dir.path());
        let findings = scan_path_with_cve_db(&file_path, &db, &filter);
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

    #[test]
    fn test_scan_with_mcp_inspector_package() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("package.json");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            r#"{{
            "dependencies": {{
                "mcp-inspector": "0.1.0"
            }}
        }}"#
        )
        .unwrap();

        let db = CveDatabase::default();
        let filter = create_default_filter(temp_dir.path());
        // This tests the mcp-inspector code path
        let _findings = scan_path_with_cve_db(&file_path, &db, &filter);
    }

    #[test]
    fn test_scan_with_mcp_remote_package() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("package.json");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            r#"{{
            "devDependencies": {{
                "@geelen/mcp-remote": "0.0.1"
            }}
        }}"#
        )
        .unwrap();

        let db = CveDatabase::default();
        let filter = create_default_filter(temp_dir.path());
        let findings = scan_path_with_cve_db(&file_path, &db, &filter);
        // mcp-remote 0.0.1 is < 0.3.0 (CVE-2025-6514), so a finding is required.
        assert!(
            findings.iter().any(|f| f.id == "CVE-2025-6514"),
            "mcp-remote 0.0.1 must be flagged as CVE-2025-6514"
        );
    }

    #[test]
    fn test_scan_with_anthropic_mcp_inspector() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("package.json");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            r#"{{
            "peerDependencies": {{
                "@anthropic/mcp-inspector": "0.2.0"
            }}
        }}"#
        )
        .unwrap();

        let db = CveDatabase::default();
        let filter = create_default_filter(temp_dir.path());
        let findings = scan_path_with_cve_db(&file_path, &db, &filter);
        // mcp-inspector 0.2.0 is < 0.5.0 (CVE-2025-49596), so a finding is required.
        assert!(
            findings.iter().any(|f| f.id == "CVE-2025-49596"),
            "mcp-inspector 0.2.0 must be flagged as CVE-2025-49596"
        );
    }

    #[test]
    fn test_scan_package_json_bare_mcp_remote() {
        // Issue #149: the bare (unscoped) package name must match too.
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("package.json");
        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, r#"{{"dependencies": {{"mcp-remote": "0.0.1"}}}}"#).unwrap();

        let db = CveDatabase::default();
        let filter = create_default_filter(temp_dir.path());
        let findings = scan_path_with_cve_db(&file_path, &db, &filter);
        assert!(
            findings.iter().any(|f| f.id == "CVE-2025-6514"),
            "bare mcp-remote 0.0.1 must be flagged"
        );
    }

    #[test]
    fn test_scan_lockfile_v3_packages() {
        // Issue #153: lockfileVersion 3 has no top-level `dependencies`; the tree
        // lives under `packages` keyed by node_modules/<name>, value an object.
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("package-lock.json");
        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            r#"{{
              "name": "t",
              "version": "1.0.0",
              "lockfileVersion": 3,
              "packages": {{
                "": {{ "name": "t", "version": "1.0.0" }},
                "node_modules/mcp-remote": {{ "version": "0.0.1", "resolved": "x", "integrity": "y" }}
              }}
            }}"#
        )
        .unwrap();

        let db = CveDatabase::default();
        let filter = create_default_filter(temp_dir.path());
        let findings = scan_path_with_cve_db(&file_path, &db, &filter);
        assert!(
            findings.iter().any(|f| f.id == "CVE-2025-6514"),
            "lockfileVersion 3 packages[node_modules/mcp-remote].version must be checked"
        );
    }

    #[test]
    fn test_scan_lockfile_v1_object_deps() {
        // Issue #153: lockfileVersion 1 has top-level `dependencies` whose values
        // are objects ({"version": …}), not strings.
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("package-lock.json");
        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            r#"{{
              "name": "t",
              "version": "1.0.0",
              "lockfileVersion": 1,
              "dependencies": {{
                "mcp-remote": {{ "version": "0.0.1", "resolved": "x", "integrity": "y" }}
              }}
            }}"#
        )
        .unwrap();

        let db = CveDatabase::default();
        let filter = create_default_filter(temp_dir.path());
        let findings = scan_path_with_cve_db(&file_path, &db, &filter);
        assert!(
            findings.iter().any(|f| f.id == "CVE-2025-6514"),
            "lockfileVersion 1 object-valued dependencies must be checked"
        );
    }

    #[test]
    fn test_scan_lockfile_patched_no_finding() {
        // A lockfile pinning a fixed version must not produce a finding.
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("package-lock.json");
        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            r#"{{
              "lockfileVersion": 3,
              "packages": {{
                "node_modules/mcp-remote": {{ "version": "0.3.0" }}
              }}
            }}"#
        )
        .unwrap();

        let db = CveDatabase::default();
        let filter = create_default_filter(temp_dir.path());
        let findings = scan_path_with_cve_db(&file_path, &db, &filter);
        assert!(
            !findings.iter().any(|f| f.id == "CVE-2025-6514"),
            "mcp-remote 0.3.0 is patched and must not be flagged"
        );
    }

    #[test]
    fn test_scan_extensions_json() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("extensions.json");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            r#"{{
            "recommendations": [
                "anthropic.claude-code",
                "ms-python.python"
            ]
        }}"#
        )
        .unwrap();

        let db = CveDatabase::default();
        let filter = create_default_filter(temp_dir.path());
        let findings = scan_path_with_cve_db(&file_path, &db, &filter);
        // Should handle extensions.json
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_mcp_config_with_servers() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("mcp.json");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            r#"{{
            "mcpServers": {{
                "my-remote": {{
                    "command": "npx mcp-remote"
                }}
            }}
        }}"#
        )
        .unwrap();

        let db = CveDatabase::default();
        let filter = create_default_filter(temp_dir.path());
        let findings = scan_path_with_cve_db(&file_path, &db, &filter);
        // mcpServers referencing mcp-remote is checked with version 0.0.0, which
        // is < 0.3.0, so CVE-2025-6514 must fire.
        assert!(
            findings.iter().any(|f| f.id == "CVE-2025-6514"),
            "mcp-remote referenced in mcpServers must be flagged"
        );
    }

    #[test]
    fn test_scan_mcp_config_with_inspector() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("mcp_config.json");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            r#"{{
            "mcpServers": {{
                "inspector": {{
                    "command": "node mcp-inspector"
                }}
            }}
        }}"#
        )
        .unwrap();

        let db = CveDatabase::default();
        let filter = create_default_filter(temp_dir.path());
        let findings = scan_path_with_cve_db(&file_path, &db, &filter);
        // mcpServers referencing mcp-inspector is checked with version 0.0.0,
        // which is < 0.5.0, so CVE-2025-49596 must fire.
        assert!(
            findings.iter().any(|f| f.id == "CVE-2025-49596"),
            "mcp-inspector referenced in mcpServers must be flagged"
        );
    }

    #[test]
    fn test_scan_directory() {
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
        let filter = create_default_filter(temp_dir.path());
        // Scan the directory instead of the file
        let findings = scan_path_with_cve_db(temp_dir.path(), &db, &filter);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_nonexistent_path() {
        let temp_dir = TempDir::new().unwrap();
        let db = CveDatabase::default();
        let filter = create_default_filter(temp_dir.path());
        let findings = scan_path_with_cve_db(Path::new("/nonexistent/path"), &db, &filter);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_path_respects_ignore_patterns() {
        let temp_dir = TempDir::new().unwrap();

        // Create a package.json in an ignored directory
        let ignored_dir = temp_dir.path().join("node_modules").join("some-pkg");
        fs::create_dir_all(&ignored_dir).unwrap();
        let ignored_file = ignored_dir.join("package.json");
        let mut file = fs::File::create(&ignored_file).unwrap();
        writeln!(
            file,
            r#"{{
            "dependencies": {{
                "mcp-inspector": "0.1.0"
            }}
        }}"#
        )
        .unwrap();

        // Configure the filter to ignore node_modules (the default IgnoreConfig
        // carries no patterns; real usage loads them from .cc-audit.yaml).
        let filter = IgnoreFilter::from_config(&IgnoreConfig {
            patterns: vec!["**/node_modules/**".to_string()],
        });

        let db = CveDatabase::default();
        let findings = scan_path_with_cve_db(temp_dir.path(), &db, &filter);

        // mcp-inspector 0.1.0 would otherwise be flagged (CVE-2025-49596); it
        // must be skipped because the file lives under an ignored node_modules.
        assert!(
            findings.is_empty(),
            "files under ignored node_modules must not be scanned"
        );
    }

    #[test]
    fn test_check_content_for_cves_invalid_json() {
        let db = CveDatabase::default();
        let findings = check_content_for_cves("not valid json", Path::new("test.json"), &db);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_check_content_with_non_string_version() {
        let db = CveDatabase::default();
        let content = r#"{
            "dependencies": {
                "some-package": 123
            }
        }"#;
        let findings = check_content_for_cves(content, Path::new("package.json"), &db);
        assert!(findings.is_empty());
    }
}
