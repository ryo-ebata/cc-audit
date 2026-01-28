//! SBOM generation handler.

use crate::run::EffectiveConfig;
use crate::sbom::{SbomBuilder, SbomFormat};
use crate::{CheckArgs, Config};
use colored::Colorize;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

/// Handle the --sbom command.
pub fn handle_sbom(args: &CheckArgs) -> ExitCode {
    let path = args
        .paths
        .first()
        .cloned()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| ".".into()));

    if !path.exists() {
        eprintln!("{} Path does not exist: {}", "Error:".red(), path.display());
        return ExitCode::from(2);
    }

    // Load config to get effective settings
    let project_root = if path.is_dir() {
        Some(path.as_path())
    } else {
        path.parent()
    };
    let config = Config::load(project_root);
    let effective = EffectiveConfig::from_check_args_and_config(args, &config);

    // Determine format (effective config includes merged CLI and config file)
    let format = effective
        .sbom_format
        .as_ref()
        .and_then(|f| f.parse::<SbomFormat>().ok())
        .unwrap_or(SbomFormat::CycloneDx);

    // Build SBOM using effective config
    let mut builder = SbomBuilder::new()
        .with_format(format)
        .with_npm(effective.sbom_npm)
        .with_cargo(effective.sbom_cargo);

    if let Err(e) = builder.build_from_path(&path) {
        eprintln!("{} Failed to extract dependencies: {}", "Error:".red(), e);
        return ExitCode::from(2);
    }

    // Generate output
    let output = match builder.to_json() {
        Ok(json) => json,
        Err(e) => {
            eprintln!("{} Failed to generate SBOM: {}", "Error:".red(), e);
            return ExitCode::from(2);
        }
    };

    // Output to file or stdout (use effective config for output path)
    let effective_output: Option<PathBuf> = effective.output.as_ref().map(PathBuf::from);
    if let Some(ref output_path) = effective_output {
        if let Err(e) = fs::write(output_path, &output) {
            eprintln!(
                "{} Failed to write SBOM to {}: {}",
                "Error:".red(),
                output_path.display(),
                e
            );
            return ExitCode::from(2);
        }
        println!("{} SBOM written to {}", "✓".green(), output_path.display());
        println!(
            "  {} components, {} services",
            builder
                .components()
                .iter()
                .filter(|c| !matches!(
                    c.component_type,
                    crate::sbom::ComponentType::McpServer | crate::sbom::ComponentType::Service
                ))
                .count(),
            builder
                .components()
                .iter()
                .filter(|c| matches!(
                    c.component_type,
                    crate::sbom::ComponentType::McpServer | crate::sbom::ComponentType::Service
                ))
                .count()
        );
    } else {
        println!("{}", output);
    }

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CheckArgs;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_check_args(path: PathBuf) -> CheckArgs {
        CheckArgs {
            paths: vec![path],
            config: None,
            remote: None,
            git_ref: "HEAD".to_string(),
            remote_auth: None,
            remote_list: None,
            awesome_claude_code: false,
            parallel_clones: 4,
            badge: false,
            badge_format: crate::BadgeFormat::Markdown,
            summary: false,
            format: crate::OutputFormat::Terminal,
            strict: false,
            warn_only: false,
            min_severity: None,
            min_rule_severity: None,
            scan_type: crate::ScanType::Skill,
            no_recursive: false,
            ci: false,
            min_confidence: None,
            watch: false,
            skip_comments: false,
            strict_secrets: false,
            fix_hint: false,
            compact: false,
            no_malware_scan: false,
            cve_db: None,
            no_cve_scan: false,
            malware_db: None,
            custom_rules: None,
            baseline: false,
            check_drift: false,
            output: None,
            save_baseline: None,
            baseline_file: None,
            compare: None,
            fix: false,
            fix_dry_run: false,
            pin: false,
            pin_verify: false,
            pin_update: false,
            pin_force: false,
            ignore_pin: false,
            deep_scan: false,
            profile: None,
            save_profile: None,
            all_clients: false,
            client: None,
            report_fp: false,
            report_fp_dry_run: false,
            report_fp_endpoint: None,
            no_telemetry: false,
            sbom: true,
            sbom_format: None,
            sbom_npm: false,
            sbom_cargo: false,
            hook_mode: false,
        }
    }

    #[test]
    fn test_handle_sbom_empty_dir() {
        let temp_dir = TempDir::new().unwrap();
        let args = create_test_check_args(temp_dir.path().to_path_buf());

        let result = handle_sbom(&args);
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_handle_sbom_with_mcp_json() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(
            temp_dir.path().join("mcp.json"),
            r#"{"mcpServers": {"test-server": {"command": "npx"}}}"#,
        )
        .unwrap();

        let args = create_test_check_args(temp_dir.path().to_path_buf());
        let result = handle_sbom(&args);

        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_handle_sbom_with_output() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("sbom.json");

        let mut args = create_test_check_args(temp_dir.path().to_path_buf());
        args.output = Some(output_path.clone());

        let result = handle_sbom(&args);

        assert_eq!(result, ExitCode::SUCCESS);
        assert!(output_path.exists());

        let content = fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("CycloneDX"));
    }

    #[test]
    fn test_handle_sbom_nonexistent_path() {
        let args = create_test_check_args(PathBuf::from("/nonexistent/path/12345"));
        let result = handle_sbom(&args);

        assert_eq!(result, ExitCode::from(2));
    }

    #[test]
    fn test_handle_sbom_with_npm_deps() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(
            temp_dir.path().join("package.json"),
            r#"{"dependencies": {"express": "^4.18.0"}}"#,
        )
        .unwrap();

        let mut args = create_test_check_args(temp_dir.path().to_path_buf());
        args.sbom_npm = true;
        let result = handle_sbom(&args);

        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_handle_sbom_with_cargo_deps() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(
            temp_dir.path().join("Cargo.toml"),
            r#"[dependencies]
serde = "1.0"
"#,
        )
        .unwrap();

        let mut args = create_test_check_args(temp_dir.path().to_path_buf());
        args.sbom_cargo = true;
        let result = handle_sbom(&args);

        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_handle_sbom_with_cyclonedx_format() {
        let temp_dir = TempDir::new().unwrap();
        let mut args = create_test_check_args(temp_dir.path().to_path_buf());
        args.sbom_format = Some("cyclonedx".to_string());

        let result = handle_sbom(&args);
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_handle_sbom_with_invalid_format() {
        let temp_dir = TempDir::new().unwrap();
        let mut args = create_test_check_args(temp_dir.path().to_path_buf());
        args.sbom_format = Some("invalid".to_string());

        // Should fallback to CycloneDX
        let result = handle_sbom(&args);
        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_handle_sbom_with_skills() {
        let temp_dir = TempDir::new().unwrap();
        let skills_dir = temp_dir.path().join(".claude").join("skills");
        fs::create_dir_all(&skills_dir).unwrap();
        fs::write(
            skills_dir.join("test-skill.md"),
            r#"---
description: Test skill
---
# Content
"#,
        )
        .unwrap();

        let args = create_test_check_args(temp_dir.path().to_path_buf());
        let result = handle_sbom(&args);

        assert_eq!(result, ExitCode::SUCCESS);
    }

    #[test]
    fn test_handle_sbom_default_path() {
        // When paths provided as ".", should use current directory
        let args = create_test_check_args(PathBuf::from("."));
        // This test just verifies the default path logic doesn't panic
        // Result depends on whether current dir exists
        let _ = handle_sbom(&args);
    }
}
