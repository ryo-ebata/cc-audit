//! Compare handler for comparing scan results between directories.

use crate::run::EffectiveConfig;
use crate::{CheckArgs, Config, run_scan_with_check_args};
use colored::Colorize;
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::ExitCode;

/// Handle --compare command.
pub fn handle_compare(args: &CheckArgs, paths: &[PathBuf]) -> ExitCode {
    if paths.len() != 2 {
        eprintln!("Error: --compare requires exactly 2 paths");
        return ExitCode::from(2);
    }

    let path1 = &paths[0];
    let path2 = &paths[1];

    println!("Comparing {} vs {}\n", path1.display(), path2.display());

    // Load config from first path to get effective settings
    let project_root = if path1.is_dir() {
        Some(path1.as_path())
    } else {
        path1.parent()
    };
    let config = Config::load(project_root);
    let effective = EffectiveConfig::from_check_args_and_config(args, &config);

    // Scan both paths
    let args1 = args.for_scan(vec![path1.clone()], &effective);
    let result1 = match run_scan_with_check_args(&args1) {
        Some(r) => r,
        None => {
            eprintln!("Failed to scan {}", path1.display());
            return ExitCode::from(2);
        }
    };

    let args2 = args.for_scan(vec![path2.clone()], &effective);
    let result2 = match run_scan_with_check_args(&args2) {
        Some(r) => r,
        None => {
            eprintln!("Failed to scan {}", path2.display());
            return ExitCode::from(2);
        }
    };

    // Compare findings
    let findings1: HashSet<_> = result1
        .findings
        .iter()
        .map(|f| (&f.id, &f.message))
        .collect();
    let findings2: HashSet<_> = result2
        .findings
        .iter()
        .map(|f| (&f.id, &f.message))
        .collect();

    let only_in_1: Vec<_> = result1
        .findings
        .iter()
        .filter(|f| !findings2.contains(&(&f.id, &f.message)))
        .collect();
    let only_in_2: Vec<_> = result2
        .findings
        .iter()
        .filter(|f| !findings1.contains(&(&f.id, &f.message)))
        .collect();

    if only_in_1.is_empty() && only_in_2.is_empty() {
        println!("{}", "No differences found.".green());
        return ExitCode::SUCCESS;
    }

    if !only_in_1.is_empty() {
        println!(
            "{}",
            format!(
                "Only in {} ({} findings):",
                path1.display(),
                only_in_1.len()
            )
            .yellow()
            .bold()
        );
        for f in &only_in_1 {
            println!("  {} [{}] {}", "-".red(), f.id, f.message);
        }
        println!();
    }

    if !only_in_2.is_empty() {
        println!(
            "{}",
            format!(
                "Only in {} ({} findings):",
                path2.display(),
                only_in_2.len()
            )
            .yellow()
            .bold()
        );
        for f in &only_in_2 {
            println!("  {} [{}] {}", "+".green(), f.id, f.message);
        }
        println!();
    }

    println!(
        "Summary: {} removed, {} added",
        only_in_1.len(),
        only_in_2.len()
    );

    ExitCode::from(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_compare_wrong_path_count_zero() {
        let args = CheckArgs::default();
        let paths: Vec<PathBuf> = vec![];
        assert_eq!(handle_compare(&args, &paths), ExitCode::from(2));
    }

    #[test]
    fn test_handle_compare_wrong_path_count_one() {
        let args = CheckArgs::default();
        let paths = vec![PathBuf::from("/tmp/path1")];
        assert_eq!(handle_compare(&args, &paths), ExitCode::from(2));
    }

    #[test]
    fn test_handle_compare_wrong_path_count_three() {
        let args = CheckArgs::default();
        let paths = vec![
            PathBuf::from("/tmp/a"),
            PathBuf::from("/tmp/b"),
            PathBuf::from("/tmp/c"),
        ];
        assert_eq!(handle_compare(&args, &paths), ExitCode::from(2));
    }

    #[test]
    fn test_handle_compare_identical_dirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_path_buf();
        // 空ディレクトリ同士の比較は finding が無いため差分なし
        let args = CheckArgs::default();
        let result = handle_compare(&args, &[dir.clone(), dir]);
        assert_eq!(result, ExitCode::SUCCESS);
    }
}
