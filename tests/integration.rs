use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use std::path::PathBuf;

fn fixtures_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn cmd() -> assert_cmd::Command {
    cargo_bin_cmd!("cc-audit")
}

mod malicious_skills {
    use super::*;

    #[test]
    fn test_detect_data_exfiltration() {
        let skill_path = fixtures_path().join("malicious/data-exfil");

        cmd()
            .arg(skill_path)
            .assert()
            .failure()
            .code(1)
            .stdout(predicate::str::contains("EX-001"))
            .stdout(predicate::str::contains("CRITICAL"));
    }

    #[test]
    fn test_detect_privilege_escalation() {
        let skill_path = fixtures_path().join("malicious/privilege-escalation");

        cmd()
            .arg(skill_path)
            .assert()
            .failure()
            .code(1)
            .stdout(predicate::str::contains("PE-001"))
            .stdout(predicate::str::contains("sudo"));
    }

    #[test]
    fn test_detect_persistence() {
        let skill_path = fixtures_path().join("malicious/persistence");

        cmd()
            .arg(skill_path)
            .assert()
            .failure()
            .code(1)
            .stdout(predicate::str::contains("PS-001").or(predicate::str::contains("PS-005")));
    }

    #[test]
    fn test_detect_prompt_injection() {
        let skill_path = fixtures_path().join("malicious/prompt-injection");

        cmd()
            .arg(skill_path)
            .assert()
            .failure()
            .code(1)
            .stdout(predicate::str::contains("PI-001").or(predicate::str::contains("PI-002")))
            .stdout(predicate::str::contains("OP-001"));
    }
}

mod benign_skills {
    use super::*;

    #[test]
    fn test_simple_skill_passes() {
        let skill_path = fixtures_path().join("benign/simple-skill");

        cmd()
            .arg(skill_path)
            .assert()
            .success()
            .code(0)
            .stdout(predicate::str::contains("PASS"));
    }

    #[test]
    fn test_complex_skill_passes() {
        let skill_path = fixtures_path().join("benign/complex-skill");

        cmd()
            .arg(skill_path)
            .assert()
            .success()
            .code(0)
            .stdout(predicate::str::contains("PASS"));
    }
}

mod cli_options {
    use super::*;

    #[test]
    fn test_json_output() {
        let skill_path = fixtures_path().join("benign/simple-skill");

        let output = cmd()
            .arg("--format")
            .arg("json")
            .arg(skill_path)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["version"], "0.2.0");
        assert!(json["summary"]["passed"].as_bool().unwrap());
    }

    #[test]
    fn test_json_output_with_findings() {
        let skill_path = fixtures_path().join("malicious/data-exfil");

        let output = cmd()
            .arg("--format")
            .arg("json")
            .arg(skill_path)
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert!(!json["summary"]["passed"].as_bool().unwrap());
        assert!(json["summary"]["critical"].as_u64().unwrap() > 0);
        assert!(!json["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_strict_mode() {
        let skill_path = fixtures_path().join("benign/simple-skill");

        cmd().arg("--strict").arg(skill_path).assert().success();
    }

    #[test]
    fn test_verbose_mode() {
        let skill_path = fixtures_path().join("malicious/data-exfil");

        cmd()
            .arg("--verbose")
            .arg(skill_path)
            .assert()
            .failure()
            .stdout(predicate::str::contains("Recommendation:"));
    }

    #[test]
    fn test_multiple_paths() {
        let skill1 = fixtures_path().join("benign/simple-skill");
        let skill2 = fixtures_path().join("malicious/data-exfil");

        cmd().arg(&skill1).arg(&skill2).assert().failure().code(1);
    }

    #[test]
    fn test_nonexistent_path() {
        cmd()
            .arg("/nonexistent/path")
            .assert()
            .failure()
            .code(2)
            .stderr(predicate::str::contains("Error"));
    }

    #[test]
    fn test_version_flag() {
        cmd()
            .arg("--version")
            .assert()
            .success()
            .stdout(predicate::str::contains("0.2.0"));
    }

    #[test]
    fn test_help_flag() {
        cmd()
            .arg("--help")
            .assert()
            .success()
            .stdout(predicate::str::contains("security vulnerabilities"));
    }
}

mod hooks {
    use super::*;

    #[test]
    fn test_benign_hook_passes() {
        let hook_path = fixtures_path().join("hooks/benign");

        cmd()
            .arg("--type")
            .arg("hook")
            .arg(hook_path)
            .assert()
            .success()
            .code(0)
            .stdout(predicate::str::contains("PASS"));
    }

    #[test]
    fn test_malicious_hook_fails() {
        let hook_path = fixtures_path().join("hooks/malicious");

        cmd()
            .arg("--type")
            .arg("hook")
            .arg(hook_path)
            .assert()
            .failure()
            .code(1)
            .stdout(predicate::str::contains("EX-001"))
            .stdout(predicate::str::contains("PE-001"));
    }

    #[test]
    fn test_hook_json_output() {
        let hook_path = fixtures_path().join("hooks/malicious");

        let output = cmd()
            .arg("--type")
            .arg("hook")
            .arg("--format")
            .arg("json")
            .arg(hook_path)
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert!(!json["summary"]["passed"].as_bool().unwrap());
        assert!(!json["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_hook_sarif_output() {
        let hook_path = fixtures_path().join("hooks/malicious");

        let output = cmd()
            .arg("--type")
            .arg("hook")
            .arg("--format")
            .arg("sarif")
            .arg(hook_path)
            .assert()
            .failure()
            .get_output()
            .stdout
            .clone();

        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["version"], "2.1.0");
        assert!(!json["runs"][0]["results"].as_array().unwrap().is_empty());
    }
}

mod edge_cases {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_empty_skill_directory() {
        let dir = TempDir::new().unwrap();

        cmd()
            .arg(dir.path())
            .assert()
            .success()
            .stdout(predicate::str::contains("PASS"));
    }

    #[test]
    fn test_skill_with_only_skill_md() {
        let dir = TempDir::new().unwrap();
        let skill_md = dir.path().join("SKILL.md");
        fs::write(
            &skill_md,
            r#"---
name: minimal
allowed-tools: Read
---
# Minimal Skill
"#,
        )
        .unwrap();

        cmd().arg(dir.path()).assert().success();
    }

    #[test]
    fn test_scan_single_file() {
        let skill_path = fixtures_path().join("benign/simple-skill/SKILL.md");

        cmd().arg(skill_path).assert().success();
    }
}
