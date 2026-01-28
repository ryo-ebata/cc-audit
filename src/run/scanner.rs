//! Core scanning functionality.

use crate::{
    Cli, CommandScanner, Config, CustomRuleLoader, CveDatabase, Deobfuscator, DependencyScanner,
    DirectoryWalker, DockerScanner, DynamicRule, Finding, HookScanner, IgnoreFilter,
    MalwareDatabase, McpScanner, PluginScanner, RiskScore, RuleSeverity, RulesDirScanner,
    ScanResult, ScanType, Scanner, SkillScanner, SubagentScanner, Summary, WalkConfig,
};
use chrono::Utc;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use super::client::{detect_client_for_path, resolve_scan_paths};
use super::config::{EffectiveConfig, load_custom_rules_from_effective};
use super::cve::scan_path_with_cve_db;
use super::malware::scan_path_with_malware_db;
use super::text_file::is_text_file;

/// Run a scan using CLI settings.
pub fn run_scan(cli: &Cli) -> Option<ScanResult> {
    run_scan_internal(cli, None)
}

/// Run scan with pre-loaded config (for testing).
pub fn run_scan_with_config(cli: &Cli, config: Config) -> Option<ScanResult> {
    run_scan_internal(cli, Some(config))
}

fn run_scan_internal(cli: &Cli, preloaded_config: Option<Config>) -> Option<ScanResult> {
    let mut all_findings = Vec::new();
    let mut targets = Vec::new();

    // Resolve paths based on scan mode (client scan or path scan)
    let scan_paths: Vec<PathBuf> = resolve_scan_paths(cli);

    if scan_paths.is_empty() {
        eprintln!("No paths to scan");
        return None;
    }

    // Determine project root for config loading
    let project_root = scan_paths.first().and_then(|p| {
        if p.is_dir() {
            Some(p.as_path())
        } else {
            p.parent()
        }
    });

    // Load config from project root or global config (or use preloaded)
    let config = preloaded_config.unwrap_or_else(|| Config::load(project_root));

    // Load profile if specified
    let mut config = config;
    if let Some(ref profile_name) = cli.profile {
        match crate::Profile::load(profile_name) {
            Ok(profile) => {
                profile.apply_to_config(&mut config.scan);
                info!(profile = %profile_name, "Using profile");
                eprintln!("Using profile: {}", profile_name);
            }
            Err(e) => {
                warn!(profile = %profile_name, error = %e, "Failed to load profile");
                eprintln!("Warning: Failed to load profile '{}': {}", profile_name, e);
            }
        }
    }

    // Merge CLI options with config file settings
    let effective = EffectiveConfig::from_cli_and_config(cli, &config);

    // Load custom rules: merge effective config rules with config file inline rules
    let mut custom_rules = load_custom_rules_from_effective(&effective);

    // Add rules from config file (inline rules section)
    if !config.rules.is_empty() {
        match CustomRuleLoader::convert_yaml_rules(config.rules.clone()) {
            Ok(config_rules) => {
                let config_rules_count = config_rules.len();
                custom_rules.extend(config_rules);
                if config_rules_count > 0 {
                    debug!(
                        count = config_rules_count,
                        "Loaded custom rules from config file"
                    );
                    eprintln!(
                        "Loaded {} custom rule(s) from config file",
                        config_rules_count
                    );
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to load rules from config file");
                eprintln!("Warning: Failed to load rules from config file: {}", e);
            }
        }
    }

    // Load malware database if enabled (using effective config)
    let malware_db = load_malware_database(&effective, &config);

    // Load CVE database if enabled (using effective config)
    let cve_db = load_cve_database(&effective);

    // Create ignore filter from config, then apply CLI overrides
    let create_ignore_filter = |path: &Path| {
        let mut filter = IgnoreFilter::from_config(path, &config.ignore);
        // CLI flags override config settings if explicitly set
        if cli.include_tests {
            filter = filter.with_include_tests(true);
        }
        if cli.include_node_modules {
            filter = filter.with_include_node_modules(true);
        }
        if cli.include_vendor {
            filter = filter.with_include_vendor(true);
        }
        filter
    };

    for path in &scan_paths {
        // Use effective scan_type from merged config
        let result = run_scanner_for_type(
            &effective.scan_type,
            path,
            &create_ignore_filter,
            effective.skip_comments,
            effective.strict_secrets,
            effective.recursive,
            &custom_rules,
        );

        match result {
            Ok(findings) => {
                all_findings.extend(findings);
                targets.push(path.display().to_string());
            }
            Err(e) => {
                eprintln!("Error scanning {}: {}", path.display(), e);
                return None;
            }
        }

        // Run malware database scan on files
        if let Some(ref db) = malware_db {
            let ignore_filter = create_ignore_filter(path);
            let malware_findings = scan_path_with_malware_db(path, db, &ignore_filter);
            all_findings.extend(malware_findings);
        }

        // Run deep scan with deobfuscation if enabled
        if effective.deep_scan {
            let ignore_filter = create_ignore_filter(path);
            let deep_findings = run_deep_scan(path, &ignore_filter);
            all_findings.extend(deep_findings);
        }

        // Run CVE database scan on dependency files
        if let Some(ref db) = cve_db {
            let ignore_filter = create_ignore_filter(path);
            let cve_findings = scan_path_with_cve_db(path, db, &ignore_filter);
            all_findings.extend(cve_findings);
        }
    }

    // Filter and process findings
    let filtered_findings = filter_and_process_findings(all_findings, cli, &config, &effective);

    let summary = Summary::from_findings_with_rule_severity(&filtered_findings);
    let risk_score = RiskScore::from_findings(&filtered_findings);
    Some(ScanResult {
        version: env!("CARGO_PKG_VERSION").to_string(),
        scanned_at: Utc::now().to_rfc3339(),
        target: targets.join(", "),
        summary,
        findings: filtered_findings,
        risk_score: Some(risk_score),
    })
}

/// Run the appropriate scanner based on scan type.
fn run_scanner_for_type<F>(
    scan_type: &ScanType,
    path: &Path,
    create_ignore_filter: &F,
    skip_comments: bool,
    strict_secrets: bool,
    recursive: bool,
    custom_rules: &[DynamicRule],
) -> crate::error::Result<Vec<Finding>>
where
    F: Fn(&Path) -> IgnoreFilter,
{
    match scan_type {
        ScanType::Skill => {
            let ignore_filter = create_ignore_filter(path);
            let scanner = SkillScanner::new()
                .with_ignore_filter(ignore_filter)
                .with_skip_comments(skip_comments)
                .with_strict_secrets(strict_secrets)
                .with_recursive(recursive)
                .with_dynamic_rules(custom_rules.to_vec());
            scanner.scan_path(path)
        }
        ScanType::Hook => {
            let scanner = HookScanner::new()
                .with_skip_comments(skip_comments)
                .with_strict_secrets(strict_secrets)
                .with_recursive(recursive)
                .with_dynamic_rules(custom_rules.to_vec());
            scanner.scan_path(path)
        }
        ScanType::Mcp => {
            let scanner = McpScanner::new()
                .with_skip_comments(skip_comments)
                .with_strict_secrets(strict_secrets)
                .with_recursive(recursive)
                .with_dynamic_rules(custom_rules.to_vec());
            scanner.scan_path(path)
        }
        ScanType::Command => {
            let scanner = CommandScanner::new()
                .with_skip_comments(skip_comments)
                .with_strict_secrets(strict_secrets)
                .with_recursive(recursive)
                .with_dynamic_rules(custom_rules.to_vec());
            scanner.scan_path(path)
        }
        ScanType::Rules => {
            let scanner = RulesDirScanner::new()
                .with_skip_comments(skip_comments)
                .with_strict_secrets(strict_secrets)
                .with_recursive(recursive)
                .with_dynamic_rules(custom_rules.to_vec());
            scanner.scan_path(path)
        }
        ScanType::Docker => {
            let ignore_filter = create_ignore_filter(path);
            let scanner = DockerScanner::new()
                .with_ignore_filter(ignore_filter)
                .with_skip_comments(skip_comments)
                .with_strict_secrets(strict_secrets)
                .with_recursive(recursive)
                .with_dynamic_rules(custom_rules.to_vec());
            scanner.scan_path(path)
        }
        ScanType::Dependency => {
            let scanner = DependencyScanner::new()
                .with_skip_comments(skip_comments)
                .with_strict_secrets(strict_secrets)
                .with_recursive(recursive)
                .with_dynamic_rules(custom_rules.to_vec());
            scanner.scan_path(path)
        }
        ScanType::Subagent => {
            let scanner = SubagentScanner::new()
                .with_skip_comments(skip_comments)
                .with_strict_secrets(strict_secrets)
                .with_recursive(recursive)
                .with_dynamic_rules(custom_rules.to_vec());
            scanner.scan_path(path)
        }
        ScanType::Plugin => {
            let scanner = PluginScanner::new()
                .with_skip_comments(skip_comments)
                .with_strict_secrets(strict_secrets)
                .with_recursive(recursive)
                .with_dynamic_rules(custom_rules.to_vec());
            scanner.scan_path(path)
        }
    }
}

/// Load malware database based on effective config.
fn load_malware_database(effective: &EffectiveConfig, config: &Config) -> Option<MalwareDatabase> {
    if effective.no_malware_scan {
        return None;
    }

    let mut db = match &effective.malware_db {
        Some(path_str) => {
            let path = Path::new(path_str);
            match MalwareDatabase::from_file(path) {
                Ok(db) => db,
                Err(e) => {
                    eprintln!("Warning: Failed to load custom malware database: {}", e);
                    eprintln!("Falling back to built-in database.");
                    MalwareDatabase::default()
                }
            }
        }
        None => MalwareDatabase::default(),
    };

    // Add malware signatures from config file (inline signatures section)
    if !config.malware_signatures.is_empty() {
        let sig_count = config.malware_signatures.len();
        if let Err(e) = db.add_signatures(config.malware_signatures.clone()) {
            eprintln!(
                "Warning: Failed to load malware signatures from config file: {}",
                e
            );
        } else {
            eprintln!("Loaded {} malware signature(s) from config file", sig_count);
        }
    }

    Some(db)
}

/// Load CVE database based on effective config.
fn load_cve_database(effective: &EffectiveConfig) -> Option<CveDatabase> {
    if effective.no_cve_scan {
        return None;
    }

    match &effective.cve_db {
        Some(path_str) => {
            let path = Path::new(path_str);
            match CveDatabase::from_file(path) {
                Ok(db) => {
                    eprintln!(
                        "Loaded CVE database v{} ({} entries) from {}",
                        db.version(),
                        db.len(),
                        path_str
                    );
                    Some(db)
                }
                Err(e) => {
                    eprintln!("Warning: Failed to load custom CVE database: {}", e);
                    eprintln!("Falling back to built-in database.");
                    Some(CveDatabase::default())
                }
            }
        }
        None => Some(CveDatabase::default()),
    }
}

/// Filter findings by confidence, severity, and disabled rules.
fn filter_and_process_findings(
    all_findings: Vec<Finding>,
    cli: &Cli,
    config: &Config,
    effective: &EffectiveConfig,
) -> Vec<Finding> {
    let mut filtered_findings: Vec<_> = all_findings
        .into_iter()
        .filter(|f| f.confidence >= effective.min_confidence)
        // Filter out disabled rules (from disabled_rules AND severity.ignore)
        .filter(|f| !config.is_rule_disabled(&f.id))
        // Filter by min_severity if specified
        .filter(|f| {
            if let Some(min_sev) = effective.min_severity {
                f.severity >= min_sev
            } else {
                true
            }
        })
        .collect();

    // Apply RuleSeverity and client attribution to each finding
    let is_client_scan = cli.all_clients || cli.client.is_some();
    for finding in &mut filtered_findings {
        // Set rule severity
        let rule_severity = if effective.warn_only {
            // --warn-only: treat all findings as warnings
            RuleSeverity::Warn
        } else if let Some(severity) = config.get_rule_severity(&finding.id) {
            severity
        } else {
            RuleSeverity::Error
        };
        finding.rule_severity = Some(rule_severity);

        // Set client attribution for client scans
        if is_client_scan && finding.client.is_none() {
            finding.client = detect_client_for_path(&finding.location.file);
        }
    }

    // Filter by min_rule_severity if specified
    // This filters out findings with rule_severity below the threshold
    // (e.g., --min-rule-severity=error will exclude warnings)
    if let Some(min_rule_sev) = effective.min_rule_severity {
        filtered_findings.retain(|f| f.rule_severity.map(|rs| rs >= min_rule_sev).unwrap_or(true));
    }

    filtered_findings
}

/// Run deep scan with deobfuscation on a path.
///
/// The `ignore_filter` parameter is used to skip files/directories that match
/// the ignore patterns configured in `.cc-audit.yaml`.
pub(crate) fn run_deep_scan(path: &Path, ignore_filter: &IgnoreFilter) -> Vec<Finding> {
    let mut findings = Vec::new();
    let deobfuscator = Deobfuscator::new();

    if path.is_file() {
        if !ignore_filter.is_ignored(path)
            && is_text_file(path)
            && let Ok(content) = fs::read_to_string(path)
        {
            debug!(path = %path.display(), "Running deep scan on file");
            findings.extend(deobfuscator.deep_scan(&content, &path.display().to_string()));
        }
    } else if path.is_dir() {
        debug!(path = %path.display(), "Running deep scan on directory");
        let walker = DirectoryWalker::new(WalkConfig::default());
        for file_path in walker.walk_single(path) {
            if !ignore_filter.is_ignored(&file_path)
                && is_text_file(&file_path)
                && let Ok(content) = fs::read_to_string(&file_path)
            {
                findings.extend(deobfuscator.deep_scan(&content, &file_path.display().to_string()));
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

    fn create_test_cli(paths: Vec<PathBuf>) -> Cli {
        Cli {
            paths,
            scan_type: ScanType::Skill,
            ..Default::default()
        }
    }

    #[test]
    fn test_run_scan_empty_paths() {
        let cli = Cli {
            paths: vec![],
            all_clients: false,
            client: None,
            ..Default::default()
        };
        // This will default to current directory, which should work
        let result = run_scan(&cli);
        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_with_valid_path() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("SKILL.md");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            "---\nname: test\ndescription: Test skill\n---\n# Test"
        )
        .unwrap();

        let cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        let result = run_scan(&cli);
        assert!(result.is_some());
    }

    #[test]
    fn test_run_deep_scan_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.md");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "# Normal content without obfuscation").unwrap();

        let filter = IgnoreFilter::from_config(temp_dir.path(), &Default::default());
        let findings = run_deep_scan(&file_path, &filter);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_run_deep_scan_directory() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.md");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "# Normal content").unwrap();

        let filter = IgnoreFilter::from_config(temp_dir.path(), &Default::default());
        let findings = run_deep_scan(temp_dir.path(), &filter);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_run_scan_with_config() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("SKILL.md");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            "---\nname: test\ndescription: Test skill\n---\n# Test"
        )
        .unwrap();

        let cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        let config = Config::default();
        let result = run_scan_with_config(&cli, config);
        assert!(result.is_some());
    }

    #[test]
    fn test_run_scanner_for_type_hook() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("hooks.json");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            r#"{{
            "hooks": []
        }}"#
        )
        .unwrap();

        let ignore_fn = |path: &Path| IgnoreFilter::from_config(path, &Default::default());
        let result = run_scanner_for_type(
            &ScanType::Hook,
            &file_path,
            &ignore_fn,
            false,
            false,
            false,
            &[],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_scanner_for_type_mcp() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("mcp.json");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            r#"{{
            "mcpServers": {{}}
        }}"#
        )
        .unwrap();

        let ignore_fn = |path: &Path| IgnoreFilter::from_config(path, &Default::default());
        let result = run_scanner_for_type(
            &ScanType::Mcp,
            &file_path,
            &ignore_fn,
            false,
            false,
            false,
            &[],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_scanner_for_type_command() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("commands.md");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "# Commands\nRun this command").unwrap();

        let ignore_fn = |path: &Path| IgnoreFilter::from_config(path, &Default::default());
        let result = run_scanner_for_type(
            &ScanType::Command,
            &file_path,
            &ignore_fn,
            false,
            false,
            false,
            &[],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_scanner_for_type_docker() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("Dockerfile");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "FROM ubuntu:latest").unwrap();

        let ignore_fn = |path: &Path| IgnoreFilter::from_config(path, &Default::default());
        let result = run_scanner_for_type(
            &ScanType::Docker,
            &file_path,
            &ignore_fn,
            false,
            false,
            false,
            &[],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_scanner_for_type_dependency() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("package.json");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            r#"{{
            "dependencies": {{}}
        }}"#
        )
        .unwrap();

        let ignore_fn = |path: &Path| IgnoreFilter::from_config(path, &Default::default());
        let result = run_scanner_for_type(
            &ScanType::Dependency,
            &file_path,
            &ignore_fn,
            false,
            false,
            false,
            &[],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_scanner_for_type_subagent() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("subagent.yaml");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "name: test").unwrap();

        let ignore_fn = |path: &Path| IgnoreFilter::from_config(path, &Default::default());
        let result = run_scanner_for_type(
            &ScanType::Subagent,
            &file_path,
            &ignore_fn,
            false,
            false,
            false,
            &[],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_scanner_for_type_plugin() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("plugin.json");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(
            file,
            r#"{{
            "name": "test-plugin"
        }}"#
        )
        .unwrap();

        let ignore_fn = |path: &Path| IgnoreFilter::from_config(path, &Default::default());
        let result = run_scanner_for_type(
            &ScanType::Plugin,
            &file_path,
            &ignore_fn,
            false,
            false,
            false,
            &[],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_scanner_for_type_rules() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("rules.yaml");

        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "rules: []").unwrap();

        let ignore_fn = |path: &Path| IgnoreFilter::from_config(path, &Default::default());
        let result = run_scanner_for_type(
            &ScanType::Rules,
            &file_path,
            &ignore_fn,
            false,
            false,
            false,
            &[],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_load_malware_database_disabled() {
        let cli = Cli {
            no_malware_scan: true,
            ..Default::default()
        };
        let config = Config::default();
        let effective = EffectiveConfig::from_cli_and_config(&cli, &config);
        let db = load_malware_database(&effective, &config);
        assert!(db.is_none());
    }

    #[test]
    fn test_load_malware_database_default() {
        let cli = Cli::default();
        let config = Config::default();
        let effective = EffectiveConfig::from_cli_and_config(&cli, &config);
        let db = load_malware_database(&effective, &config);
        assert!(db.is_some());
    }

    #[test]
    fn test_load_cve_database_disabled() {
        let cli = Cli {
            no_cve_scan: true,
            ..Default::default()
        };
        let config = Config::default();
        let effective = EffectiveConfig::from_cli_and_config(&cli, &config);
        let db = load_cve_database(&effective);
        assert!(db.is_none());
    }

    #[test]
    fn test_load_cve_database_default() {
        let cli = Cli::default();
        let config = Config::default();
        let effective = EffectiveConfig::from_cli_and_config(&cli, &config);
        let db = load_cve_database(&effective);
        assert!(db.is_some());
    }

    #[test]
    fn test_filter_and_process_findings_empty() {
        let cli = Cli::default();
        let config = Config::default();
        let effective = EffectiveConfig::from_cli_and_config(&cli, &config);

        let filtered = filter_and_process_findings(vec![], &cli, &config, &effective);
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_run_deep_scan_nonexistent_path() {
        let temp_dir = TempDir::new().unwrap();
        let filter = IgnoreFilter::from_config(temp_dir.path(), &Default::default());
        let findings = run_deep_scan(Path::new("/nonexistent/path"), &filter);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_run_deep_scan_respects_ignore_patterns() {
        let temp_dir = TempDir::new().unwrap();

        // Create a file in an ignored directory
        let ignored_dir = temp_dir.path().join("node_modules");
        fs::create_dir_all(&ignored_dir).unwrap();
        let ignored_file = ignored_dir.join("test.md");
        let mut file = fs::File::create(&ignored_file).unwrap();
        // Write base64 encoded content that would normally trigger a finding
        writeln!(file, "eval(atob('bWFsaWNpb3VzIGNvZGU='))").unwrap();

        // Default config ignores node_modules
        let filter = IgnoreFilter::from_config(temp_dir.path(), &Default::default());
        let findings = run_deep_scan(temp_dir.path(), &filter);

        // Should be empty because node_modules is ignored
        assert!(findings.is_empty());
    }

    #[test]
    fn test_filter_and_process_findings_min_rule_severity() {
        use crate::rules::{Category, Confidence, Location, Severity};

        let cli = Cli {
            min_rule_severity: Some(RuleSeverity::Error),
            ..Default::default()
        };
        let mut config = Config::default();
        // Set EX-001 to warn level
        config.severity.warn.insert("EX-001".to_string());

        let effective = EffectiveConfig::from_cli_and_config(&cli, &config);

        // Create a finding that will be assigned Warn severity
        let finding = Finding {
            id: "EX-001".to_string(),
            severity: Severity::Critical,
            category: Category::Exfiltration,
            confidence: Confidence::Firm,
            name: "Test".to_string(),
            location: Location {
                file: "test.sh".to_string(),
                line: 1,
                column: None,
            },
            code: "curl $SECRET".to_string(),
            message: "Test".to_string(),
            recommendation: "Test".to_string(),
            fix_hint: None,
            cwe_ids: vec![],
            rule_severity: None,
            client: None,
            context: None,
        };

        let filtered =
            filter_and_process_findings(vec![finding.clone()], &cli, &config, &effective);

        // With min_rule_severity=Error, warnings should be filtered out
        assert!(
            filtered.is_empty(),
            "Findings with Warn rule_severity should be filtered when min_rule_severity=Error"
        );

        // Without min_rule_severity filter, warning should be included
        let cli_no_filter = Cli::default();
        let effective_no_filter = EffectiveConfig::from_cli_and_config(&cli_no_filter, &config);
        let filtered_no_filter = filter_and_process_findings(
            vec![finding],
            &cli_no_filter,
            &config,
            &effective_no_filter,
        );
        assert_eq!(
            filtered_no_filter.len(),
            1,
            "Without min_rule_severity filter, warning should be included"
        );
    }
}
