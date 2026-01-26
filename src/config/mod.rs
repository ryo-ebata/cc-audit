//! Configuration layer (L2) for cc-audit.
//!
//! This module provides configuration loading, merging, and management for the auditor.
//!
//! ## Layers
//! - `types`: Configuration type definitions
//! - `loading`: File loading logic
//! - `severity`: Severity configuration
//! - `effective`: CLI + config + profile merging (from run/config.rs)
//! - `profile`: Profile management (from profile.rs)

mod error;
mod loading;
mod severity;
mod template;
mod types;

// Re-export all public types
pub use error::ConfigError;
pub use severity::SeverityConfig;
pub use types::{BaselineConfig, Config, IgnoreConfig, ScanConfig, TextFilesConfig, WatchConfig};

// Re-export from other modules (will be moved here in Phase 10)
pub use crate::profile::{Profile, profile_from_cli};
pub use crate::run::config::{
    EffectiveConfig, load_custom_rules_from_effective, parse_badge_format, parse_client_type,
    parse_confidence, parse_output_format, parse_scan_type,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.watch.debounce_ms, 300);
        assert_eq!(config.watch.poll_interval_ms, 500);
        assert!(config.text_files.extensions.contains("md"));
        assert!(config.text_files.extensions.contains("py"));
    }

    #[test]
    fn test_is_text_file_by_extension() {
        let config = TextFilesConfig::default();
        assert!(config.is_text_file(Path::new("test.md")));
        assert!(config.is_text_file(Path::new("test.py")));
        assert!(config.is_text_file(Path::new("test.rs")));
        assert!(config.is_text_file(Path::new("test.json")));
        assert!(!config.is_text_file(Path::new("test.exe")));
        assert!(!config.is_text_file(Path::new("test.bin")));
    }

    #[test]
    fn test_is_text_file_by_name() {
        let config = TextFilesConfig::default();
        assert!(config.is_text_file(Path::new("Dockerfile")));
        assert!(config.is_text_file(Path::new("Makefile")));
        assert!(config.is_text_file(Path::new("LICENSE")));
        assert!(!config.is_text_file(Path::new("unknown_file")));
    }

    #[test]
    fn test_is_text_file_case_insensitive_extension() {
        let config = TextFilesConfig::default();
        assert!(config.is_text_file(Path::new("test.MD")));
        assert!(config.is_text_file(Path::new("test.PY")));
        assert!(config.is_text_file(Path::new("test.Json")));
    }

    #[test]
    fn test_load_yaml_config() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
watch:
  debounce_ms: 500
  poll_interval_ms: 1000
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.watch.debounce_ms, 500);
        assert_eq!(config.watch.poll_interval_ms, 1000);
    }

    #[test]
    fn test_load_json_config() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.json");
        fs::write(
            &config_path,
            r#"{"watch": {"debounce_ms": 200, "poll_interval_ms": 400}}"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.watch.debounce_ms, 200);
        assert_eq!(config.watch.poll_interval_ms, 400);
    }

    #[test]
    fn test_load_toml_config() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.toml");
        fs::write(
            &config_path,
            r#"
[watch]
debounce_ms = 600
poll_interval_ms = 800
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.watch.debounce_ms, 600);
        assert_eq!(config.watch.poll_interval_ms, 800);
    }

    #[test]
    fn test_load_with_project_config() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
watch:
  debounce_ms: 100
"#,
        )
        .unwrap();

        let config = Config::load(Some(dir.path()));
        assert_eq!(config.watch.debounce_ms, 100);
    }

    #[test]
    fn test_load_fallback_to_default() {
        let dir = TempDir::new().unwrap();
        let config = Config::load(Some(dir.path()));
        assert_eq!(config.watch.debounce_ms, 300); // Default value
    }

    #[test]
    fn test_unsupported_format_error() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.xml");
        fs::write(&config_path, "<config></config>").unwrap();

        let result = Config::from_file(&config_path);
        assert!(matches!(result, Err(ConfigError::UnsupportedFormat(_, _))));
    }

    #[test]
    fn test_partial_config_with_defaults() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
watch:
  debounce_ms: 999
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.watch.debounce_ms, 999);
        // poll_interval_ms should use default
        assert_eq!(config.watch.poll_interval_ms, 500);
    }

    #[test]
    fn test_config_error_read_file() {
        let result = Config::from_file(Path::new("/nonexistent/config.yaml"));
        assert!(matches!(result, Err(ConfigError::ReadFile { .. })));
    }

    #[test]
    fn test_custom_text_extensions() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
text_files:
  extensions:
    - custom
    - special
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert!(config.text_files.extensions.contains("custom"));
        assert!(config.text_files.extensions.contains("special"));
    }

    #[test]
    fn test_config_with_rules() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
rules:
  - id: "CUSTOM-001"
    name: "Test Rule"
    severity: "high"
    category: "exfiltration"
    patterns:
      - 'test_pattern'
    message: "Test message"
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].id, "CUSTOM-001");
        assert_eq!(config.rules[0].name, "Test Rule");
        assert_eq!(config.rules[0].severity, "high");
    }

    #[test]
    fn test_config_with_malware_signatures() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
malware_signatures:
  - id: "MW-CUSTOM-001"
    name: "Custom Malware"
    description: "Test malware pattern"
    pattern: "evil_pattern"
    severity: "critical"
    category: "exfiltration"
    confidence: "firm"
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.malware_signatures.len(), 1);
        assert_eq!(config.malware_signatures[0].id, "MW-CUSTOM-001");
        assert_eq!(config.malware_signatures[0].name, "Custom Malware");
        assert_eq!(config.malware_signatures[0].severity, "critical");
    }

    #[test]
    fn test_config_with_rules_and_malware_signatures() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
watch:
  debounce_ms: 100

rules:
  - id: "CUSTOM-001"
    name: "Test Rule"
    severity: "high"
    category: "exfiltration"
    patterns:
      - 'test_pattern'
    message: "Test message"

malware_signatures:
  - id: "MW-CUSTOM-001"
    name: "Custom Malware"
    description: "Test malware pattern"
    pattern: "evil_pattern"
    severity: "critical"
    category: "exfiltration"
    confidence: "firm"
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.watch.debounce_ms, 100);
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.malware_signatures.len(), 1);
    }

    #[test]
    fn test_default_config_has_empty_rules() {
        let config = Config::default();
        assert!(config.rules.is_empty());
        assert!(config.malware_signatures.is_empty());
    }

    #[test]
    fn test_parse_yaml_error() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(&config_path, "invalid: yaml: content: [").unwrap();

        let result = Config::from_file(&config_path);
        assert!(matches!(result, Err(ConfigError::ParseYaml { .. })));
    }

    #[test]
    fn test_parse_json_error() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.json");
        fs::write(&config_path, "{invalid json}").unwrap();

        let result = Config::from_file(&config_path);
        assert!(matches!(result, Err(ConfigError::ParseJson { .. })));
    }

    #[test]
    fn test_parse_toml_error() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.toml");
        fs::write(&config_path, "[invalid toml\nkey = ").unwrap();

        let result = Config::from_file(&config_path);
        assert!(matches!(result, Err(ConfigError::ParseToml { .. })));
    }

    #[test]
    fn test_load_with_invalid_config_falls_back() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        // Write invalid YAML that will fail to parse
        fs::write(&config_path, "invalid: yaml: [").unwrap();

        // Should fall back to default
        let config = Config::load(Some(dir.path()));
        assert_eq!(config.watch.debounce_ms, 300);
    }

    #[test]
    fn test_is_text_file_returns_false_for_unknown() {
        let config = TextFilesConfig::default();
        // No extension, not a special name
        assert!(!config.is_text_file(Path::new("somefile")));
        assert!(!config.is_text_file(Path::new("random_binary")));
    }

    #[test]
    fn test_ignore_config_default() {
        let config = IgnoreConfig::default();
        // Check that common directories are in the default ignore list
        assert!(config.directories.contains("node_modules"));
        assert!(config.directories.contains("target"));
        assert!(config.directories.contains(".git"));
        assert!(config.directories.contains("dist"));
        assert!(config.directories.contains("build"));
        // Default flags
        assert!(!config.include_tests);
        assert!(!config.include_node_modules);
        assert!(!config.include_vendor);
        // No custom patterns by default
        assert!(config.patterns.is_empty());
    }

    #[test]
    fn test_config_with_ignore_settings() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
ignore:
  directories:
    - custom_dir
    - my_cache
  patterns:
    - "*.log"
    - "temp/**"
  include_tests: true
  include_node_modules: false
  include_vendor: true
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert!(config.ignore.directories.contains("custom_dir"));
        assert!(config.ignore.directories.contains("my_cache"));
        assert_eq!(config.ignore.patterns.len(), 2);
        assert!(config.ignore.patterns.contains(&"*.log".to_string()));
        assert!(config.ignore.patterns.contains(&"temp/**".to_string()));
        assert!(config.ignore.include_tests);
        assert!(!config.ignore.include_node_modules);
        assert!(config.ignore.include_vendor);
    }

    #[test]
    fn test_config_with_disabled_rules() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
disabled_rules:
  - "PE-001"
  - "EX-002"
  - "CUSTOM-RULE"
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.disabled_rules.len(), 3);
        assert!(config.disabled_rules.contains("PE-001"));
        assert!(config.disabled_rules.contains("EX-002"));
        assert!(config.disabled_rules.contains("CUSTOM-RULE"));
    }

    #[test]
    fn test_default_config_has_empty_disabled_rules() {
        let config = Config::default();
        assert!(config.disabled_rules.is_empty());
    }

    #[test]
    fn test_config_ignore_default_when_partial() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
ignore:
  include_tests: true
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        // include_tests is set to true
        assert!(config.ignore.include_tests);
        // Other values should be default
        assert!(!config.ignore.include_node_modules);
        assert!(!config.ignore.include_vendor);
    }

    #[test]
    fn test_scan_config_default() {
        let config = ScanConfig::default();
        assert!(config.format.is_none());
        assert!(!config.strict);
        assert!(config.scan_type.is_none());
        assert!(!config.recursive);
        assert!(!config.ci);
        assert!(!config.verbose);
        assert!(config.min_confidence.is_none());
        assert!(!config.skip_comments);
        assert!(!config.fix_hint);
        assert!(!config.no_malware_scan);
        // New fields
        assert!(!config.watch);
        assert!(config.malware_db.is_none());
        assert!(config.custom_rules.is_none());
        assert!(config.output.is_none());
        assert!(!config.deep_scan);
        assert!(!config.fix);
        assert!(!config.fix_dry_run);
    }

    #[test]
    fn test_config_with_scan_settings() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
scan:
  format: json
  strict: true
  scan_type: docker
  recursive: true
  ci: true
  verbose: true
  min_confidence: firm
  skip_comments: true
  fix_hint: true
  no_malware_scan: true
  watch: true
  malware_db: ./custom-malware.json
  custom_rules: ./custom-rules.yaml
  output: ./report.html
  deep_scan: true
  fix: true
  fix_dry_run: true
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.scan.format, Some("json".to_string()));
        assert!(config.scan.strict);
        assert_eq!(config.scan.scan_type, Some("docker".to_string()));
        assert!(config.scan.recursive);
        assert!(config.scan.ci);
        assert!(config.scan.verbose);
        assert_eq!(config.scan.min_confidence, Some("firm".to_string()));
        assert!(config.scan.skip_comments);
        assert!(config.scan.fix_hint);
        assert!(config.scan.no_malware_scan);
        // New fields
        assert!(config.scan.watch);
        assert_eq!(
            config.scan.malware_db,
            Some("./custom-malware.json".to_string())
        );
        assert_eq!(
            config.scan.custom_rules,
            Some("./custom-rules.yaml".to_string())
        );
        assert_eq!(config.scan.output, Some("./report.html".to_string()));
        assert!(config.scan.deep_scan);
        assert!(config.scan.fix);
        assert!(config.scan.fix_dry_run);
    }

    #[test]
    fn test_config_with_partial_scan_settings() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
scan:
  strict: true
  verbose: true
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        // Set values
        assert!(config.scan.strict);
        assert!(config.scan.verbose);
        // Default values
        assert!(config.scan.format.is_none());
        assert!(config.scan.scan_type.is_none());
        assert!(!config.scan.recursive);
        assert!(!config.scan.ci);
        assert!(config.scan.min_confidence.is_none());
        assert!(!config.scan.skip_comments);
        assert!(!config.scan.fix_hint);
        assert!(!config.scan.no_malware_scan);
    }

    #[test]
    fn test_default_config_has_default_scan() {
        let config = Config::default();
        assert!(!config.scan.strict);
        assert!(!config.scan.verbose);
        assert!(config.scan.format.is_none());
    }

    #[test]
    fn test_generate_template() {
        let template = Config::generate_template();
        // Check that template contains key sections
        assert!(template.contains("# cc-audit Configuration File"));
        assert!(template.contains("severity:"));
        assert!(template.contains("default: error"));
        assert!(template.contains("scan:"));
        assert!(template.contains("watch:"));
        assert!(template.contains("ignore:"));
        assert!(template.contains("# disabled_rules:"));
        assert!(template.contains("# rules:"));
        assert!(template.contains("# malware_signatures:"));
    }

    #[test]
    fn test_generate_template_is_valid_yaml() {
        let template = Config::generate_template();
        // The template should be parseable as YAML (comments are ignored)
        let result: Result<Config, _> = serde_yaml::from_str(&template);
        assert!(result.is_ok(), "Template should be valid YAML");
    }

    // ========== SeverityConfig Tests ==========

    #[test]
    fn test_severity_config_default() {
        let config = SeverityConfig::default();
        assert_eq!(config.default, crate::rules::RuleSeverity::Error);
        assert!(config.warn.is_empty());
        assert!(config.ignore.is_empty());
    }

    #[test]
    fn test_severity_config_get_rule_severity_default() {
        let config = SeverityConfig::default();
        assert_eq!(
            config.get_rule_severity("EX-001"),
            Some(crate::rules::RuleSeverity::Error)
        );
    }

    #[test]
    fn test_severity_config_get_rule_severity_warn() {
        let mut config = SeverityConfig::default();
        config.warn.insert("PI-001".to_string());

        assert_eq!(
            config.get_rule_severity("PI-001"),
            Some(crate::rules::RuleSeverity::Warn)
        );
        assert_eq!(
            config.get_rule_severity("EX-001"),
            Some(crate::rules::RuleSeverity::Error)
        );
    }

    #[test]
    fn test_severity_config_get_rule_severity_ignore() {
        let mut config = SeverityConfig::default();
        config.ignore.insert("OP-001".to_string());

        assert_eq!(config.get_rule_severity("OP-001"), None);
        assert_eq!(
            config.get_rule_severity("EX-001"),
            Some(crate::rules::RuleSeverity::Error)
        );
    }

    #[test]
    fn test_severity_config_priority_ignore_over_warn() {
        let mut config = SeverityConfig::default();
        config.warn.insert("RULE-001".to_string());
        config.ignore.insert("RULE-001".to_string());

        // ignore takes priority over warn
        assert_eq!(config.get_rule_severity("RULE-001"), None);
    }

    #[test]
    fn test_config_severity_parsing() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
severity:
  default: warn
  warn:
    - PI-001
    - PI-002
  ignore:
    - OP-001
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.severity.default, crate::rules::RuleSeverity::Warn);
        assert!(config.severity.warn.contains("PI-001"));
        assert!(config.severity.warn.contains("PI-002"));
        assert!(config.severity.ignore.contains("OP-001"));
    }

    #[test]
    fn test_config_effective_disabled_rules() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
disabled_rules:
  - RULE-A
  - RULE-B
severity:
  ignore:
    - RULE-C
    - RULE-D
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        let effective = config.effective_disabled_rules();

        // Both disabled_rules and severity.ignore should be merged
        assert!(effective.contains("RULE-A"));
        assert!(effective.contains("RULE-B"));
        assert!(effective.contains("RULE-C"));
        assert!(effective.contains("RULE-D"));
        assert_eq!(effective.len(), 4);
    }

    #[test]
    fn test_config_is_rule_disabled() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
disabled_rules:
  - RULE-A
severity:
  ignore:
    - RULE-B
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert!(config.is_rule_disabled("RULE-A"));
        assert!(config.is_rule_disabled("RULE-B"));
        assert!(!config.is_rule_disabled("RULE-C"));
    }

    #[test]
    fn test_config_get_rule_severity() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
disabled_rules:
  - RULE-A
severity:
  default: error
  warn:
    - RULE-B
  ignore:
    - RULE-C
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();

        // RULE-A is in disabled_rules
        assert_eq!(config.get_rule_severity("RULE-A"), None);

        // RULE-B is in severity.warn
        assert_eq!(
            config.get_rule_severity("RULE-B"),
            Some(crate::rules::RuleSeverity::Warn)
        );

        // RULE-C is in severity.ignore
        assert_eq!(config.get_rule_severity("RULE-C"), None);

        // RULE-D uses default (error)
        assert_eq!(
            config.get_rule_severity("RULE-D"),
            Some(crate::rules::RuleSeverity::Error)
        );
    }

    // ========== BaselineConfig Tests ==========

    #[test]
    fn test_baseline_config_default() {
        let config = BaselineConfig::default();
        assert!(!config.enabled);
        assert!(!config.check_drift);
        assert!(config.save_to.is_none());
        assert!(config.compare_with.is_none());
    }

    #[test]
    fn test_config_with_baseline_settings() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
baseline:
  enabled: true
  check_drift: true
  save_to: ./.cc-audit-baseline.json
  compare_with: ./previous-baseline.json
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert!(config.baseline.enabled);
        assert!(config.baseline.check_drift);
        assert_eq!(
            config.baseline.save_to,
            Some("./.cc-audit-baseline.json".to_string())
        );
        assert_eq!(
            config.baseline.compare_with,
            Some("./previous-baseline.json".to_string())
        );
    }

    #[test]
    fn test_default_config_has_default_baseline() {
        let config = Config::default();
        assert!(!config.baseline.enabled);
        assert!(!config.baseline.check_drift);
        assert!(config.baseline.save_to.is_none());
        assert!(config.baseline.compare_with.is_none());
    }

    #[test]
    fn test_generate_template_contains_new_sections() {
        let template = Config::generate_template();
        // Check that template contains new sections
        assert!(template.contains("baseline:"));
        assert!(template.contains("deep_scan:"));
        assert!(template.contains("fix:"));
        assert!(template.contains("fix_dry_run:"));
        assert!(template.contains("malware_db:"));
        assert!(template.contains("custom_rules:"));
        assert!(template.contains("output:"));
        assert!(template.contains("subagent"));
        assert!(template.contains("plugin"));
    }

    // ========== v1.1.0 Options Tests ==========

    #[test]
    fn test_scan_config_v110_defaults() {
        let config = ScanConfig::default();
        // Remote options
        assert!(config.remote.is_none());
        assert!(config.git_ref.is_none());
        assert!(config.remote_auth.is_none());
        assert!(config.parallel_clones.is_none());
        // Badge options
        assert!(!config.badge);
        assert!(config.badge_format.is_none());
        assert!(!config.summary);
        // Client options
        assert!(!config.all_clients);
        assert!(config.client.is_none());
    }

    #[test]
    fn test_config_with_remote_settings() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
scan:
  remote: https://github.com/user/repo
  git_ref: main
  remote_auth: ghp_token123
  parallel_clones: 8
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(
            config.scan.remote,
            Some("https://github.com/user/repo".to_string())
        );
        assert_eq!(config.scan.git_ref, Some("main".to_string()));
        assert_eq!(config.scan.remote_auth, Some("ghp_token123".to_string()));
        assert_eq!(config.scan.parallel_clones, Some(8));
    }

    #[test]
    fn test_config_with_badge_settings() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
scan:
  badge: true
  badge_format: html
  summary: true
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert!(config.scan.badge);
        assert_eq!(config.scan.badge_format, Some("html".to_string()));
        assert!(config.scan.summary);
    }

    #[test]
    fn test_config_with_client_settings() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".cc-audit.yaml");
        fs::write(
            &config_path,
            r#"
scan:
  all_clients: true
  client: cursor
"#,
        )
        .unwrap();

        let config = Config::from_file(&config_path).unwrap();
        assert!(config.scan.all_clients);
        assert_eq!(config.scan.client, Some("cursor".to_string()));
    }

    #[test]
    fn test_generate_template_contains_v110_sections() {
        let template = Config::generate_template();
        // Check v1.1.0 sections
        assert!(template.contains("Remote Scanning Options"));
        assert!(template.contains("remote:"));
        assert!(template.contains("git_ref:"));
        assert!(template.contains("parallel_clones:"));
        assert!(template.contains("Badge Options"));
        assert!(template.contains("badge:"));
        assert!(template.contains("badge_format:"));
        assert!(template.contains("summary:"));
        assert!(template.contains("Client Scan Options"));
        assert!(template.contains("all_clients:"));
        assert!(template.contains("client:"));
    }
}
