//! Baseline management handlers.

use crate::{Baseline, CheckArgs, RiskScore, ScanResult, Summary};
use colored::Colorize;
use rustc_hash::FxHashMap;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Handle baseline command.
pub fn handle_baseline(paths: &[PathBuf]) -> ExitCode {
    for path in paths {
        match Baseline::from_directory(path) {
            Ok(baseline) => {
                if let Err(e) = baseline.save(path) {
                    eprintln!("Failed to save baseline for {}: {}", path.display(), e);
                    return ExitCode::from(2);
                }
                println!(
                    "Baseline created for {} ({} files)",
                    path.display(),
                    baseline.file_count
                );
            }
            Err(e) => {
                eprintln!("Failed to create baseline for {}: {}", path.display(), e);
                return ExitCode::from(2);
            }
        }
    }
    println!("\nBaseline saved. Use --check-drift to detect changes.");
    ExitCode::SUCCESS
}

/// Handle save-baseline command.
pub fn handle_save_baseline(paths: &[PathBuf], baseline_path: &Path) -> ExitCode {
    // Single path case: use relative paths (compatible with check_drift)
    // Multiple paths case: use prefixed paths to distinguish sources
    let single_path = paths.len() == 1;

    let mut combined_hashes = FxHashMap::default();

    for path in paths {
        match Baseline::from_directory(path) {
            Ok(baseline) => {
                for (file_path, hash) in baseline.file_hashes {
                    // For single path, use relative path directly
                    // For multiple paths, prefix with path to distinguish
                    let key = if single_path {
                        file_path
                    } else {
                        format!("{}:{}", path.display(), file_path)
                    };
                    combined_hashes.insert(key, hash);
                }
            }
            Err(e) => {
                eprintln!("Failed to create baseline for {}: {}", path.display(), e);
                return ExitCode::from(2);
            }
        }
    }

    let baseline = Baseline {
        version: env!("CARGO_PKG_VERSION").to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        file_count: combined_hashes.len(),
        file_hashes: combined_hashes,
    };

    if let Err(e) = baseline.save_to_file(baseline_path) {
        eprintln!(
            "Failed to save baseline to {}: {}",
            baseline_path.display(),
            e
        );
        return ExitCode::from(2);
    }

    println!(
        "Baseline saved to {} ({} files)",
        baseline_path.display(),
        baseline.file_count
    );
    ExitCode::SUCCESS
}

/// Handle check-drift command.
pub fn handle_check_drift(args: &CheckArgs) -> ExitCode {
    let mut has_any_drift = false;

    // If --baseline-file is specified, load from that file
    if let Some(ref baseline_file) = args.baseline_file {
        let baseline = match Baseline::load_from_file(baseline_file) {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "Failed to load baseline from {}: {}",
                    baseline_file.display(),
                    e
                );
                return ExitCode::from(2);
            }
        };

        for path in &args.paths {
            match baseline.check_drift(path) {
                Ok(report) => {
                    println!("Checking drift for: {}\n", path.display());
                    println!("{}", report.format_terminal());
                    if report.has_drift {
                        has_any_drift = true;
                    }
                }
                Err(e) => {
                    eprintln!("Failed to check drift for {}: {}", path.display(), e);
                    return ExitCode::from(2);
                }
            }
        }
    } else {
        // Load baseline from each path's default location
        for path in &args.paths {
            match Baseline::load(path) {
                Ok(baseline) => match baseline.check_drift(path) {
                    Ok(report) => {
                        println!("Checking drift for: {}\n", path.display());
                        println!("{}", report.format_terminal());
                        if report.has_drift {
                            has_any_drift = true;
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to check drift for {}: {}", path.display(), e);
                        return ExitCode::from(2);
                    }
                },
                Err(e) => {
                    eprintln!(
                        "No baseline found for {}. Run with --baseline first.\nError: {}",
                        path.display(),
                        e
                    );
                    return ExitCode::from(2);
                }
            }
        }
    }

    if has_any_drift {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Filter scan results against a baseline file.
pub fn filter_against_baseline(mut result: ScanResult, baseline_path: &Path) -> ScanResult {
    // Load the baseline scan result
    let baseline_result = match fs::read_to_string(baseline_path) {
        Ok(content) => match serde_json::from_str::<ScanResult>(&content) {
            Ok(r) => r,
            Err(e) => {
                eprintln!(
                    "{} Failed to parse baseline file: {}",
                    "Warning:".yellow(),
                    e
                );
                return result;
            }
        },
        Err(e) => {
            eprintln!(
                "{} Failed to read baseline file: {}",
                "Warning:".yellow(),
                e
            );
            return result;
        }
    };

    // Create a set of baseline finding signatures (id + file + line combo)
    let baseline_signatures: HashSet<String> = baseline_result
        .findings
        .iter()
        .map(|f| format!("{}:{}:{}", f.id, f.location.file, f.location.line))
        .collect();

    // Filter out findings that exist in baseline
    let original_count = result.findings.len();
    result.findings.retain(|f| {
        let sig = format!("{}:{}:{}", f.id, f.location.file, f.location.line);
        !baseline_signatures.contains(&sig)
    });

    let filtered_count = original_count - result.findings.len();
    if filtered_count > 0 {
        eprintln!(
            "{} {} findings filtered (already in baseline)",
            "Info:".cyan(),
            filtered_count
        );
    }

    // Recalculate summary (preserve rule_severity information)
    result.summary = Summary::from_findings_with_rule_severity(&result.findings);
    if let Some(ref mut risk_score) = result.risk_score {
        *risk_score = RiskScore::from_findings(&result.findings);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::types::{Category, Location};
    use crate::{Finding, Summary};
    use tempfile::TempDir;

    fn create_test_finding(id: &str, file: &str, line: usize) -> Finding {
        Finding {
            id: id.to_string(),
            name: id.to_string(),
            message: format!("テスト finding: {}", id),
            severity: crate::rules::Severity::High,
            category: Category::Exfiltration,
            confidence: crate::rules::Confidence::Firm,
            location: Location {
                file: file.to_string(),
                line,
                column: None,
            },
            code: String::new(),
            recommendation: String::new(),
            fix_hint: None,
            cwe_ids: vec![],
            rule_severity: None,
            client: None,
            context: None,
        }
    }

    fn create_test_scan_result(findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            version: env!("CARGO_PKG_VERSION").to_string(),
            scanned_at: String::new(),
            target: String::new(),
            summary: Summary::from_findings(&findings),
            findings,
            risk_score: None,
            elapsed_ms: 0,
        }
    }

    #[test]
    fn test_handle_save_baseline_single_path() {
        let tmp = TempDir::new().unwrap();
        let scan_dir = tmp.path().join("scan");
        fs::create_dir_all(&scan_dir).unwrap();
        fs::write(scan_dir.join("file1.md"), "# Test").unwrap();
        fs::write(scan_dir.join("file2.md"), "# Test 2").unwrap();

        let baseline_path = tmp.path().join("baseline.json");
        let result = handle_save_baseline(&[scan_dir], &baseline_path);
        assert_eq!(result, ExitCode::SUCCESS);
        assert!(baseline_path.exists());

        let content = fs::read_to_string(&baseline_path).unwrap();
        let baseline: Baseline = serde_json::from_str(&content).unwrap();
        assert_eq!(baseline.file_count, 2);
    }

    #[test]
    fn test_handle_save_baseline_multiple_paths() {
        let tmp = TempDir::new().unwrap();
        let dir1 = tmp.path().join("dir1");
        let dir2 = tmp.path().join("dir2");
        fs::create_dir_all(&dir1).unwrap();
        fs::create_dir_all(&dir2).unwrap();
        fs::write(dir1.join("a.md"), "A").unwrap();
        fs::write(dir2.join("b.md"), "B").unwrap();

        let baseline_path = tmp.path().join("baseline.json");
        let result = handle_save_baseline(&[dir1, dir2], &baseline_path);
        assert_eq!(result, ExitCode::SUCCESS);

        let content = fs::read_to_string(&baseline_path).unwrap();
        let baseline: Baseline = serde_json::from_str(&content).unwrap();
        assert_eq!(baseline.file_count, 2);
    }

    #[test]
    fn test_handle_check_drift_no_baseline() {
        let tmp = TempDir::new().unwrap();
        let args = CheckArgs {
            paths: vec![tmp.path().to_path_buf()],
            ..Default::default()
        };
        let result = handle_check_drift(&args);
        assert_eq!(result, ExitCode::from(2));
    }

    #[test]
    fn test_filter_against_baseline_removes_known() {
        let tmp = TempDir::new().unwrap();
        let baseline_path = tmp.path().join("baseline.json");

        // ベースラインに1つの finding を保存
        let baseline_result =
            create_test_scan_result(vec![create_test_finding("RULE-001", "file.md", 10)]);
        fs::write(
            &baseline_path,
            serde_json::to_string(&baseline_result).unwrap(),
        )
        .unwrap();

        // 新しい結果にはベースラインの finding + 新しい finding
        let result = create_test_scan_result(vec![
            create_test_finding("RULE-001", "file.md", 10),
            create_test_finding("RULE-002", "file.md", 20),
        ]);

        let filtered = filter_against_baseline(result, &baseline_path);
        assert_eq!(filtered.findings.len(), 1);
        assert_eq!(filtered.findings[0].id, "RULE-002");
    }

    #[test]
    fn test_filter_against_baseline_invalid_file() {
        let tmp = TempDir::new().unwrap();
        let baseline_path = tmp.path().join("nonexistent.json");

        let result = create_test_scan_result(vec![create_test_finding("RULE-001", "file.md", 10)]);

        // 無効なファイルの場合は元の結果がそのまま返る
        let filtered = filter_against_baseline(result, &baseline_path);
        assert_eq!(filtered.findings.len(), 1);
    }
}
