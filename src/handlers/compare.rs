//! Compare handler for comparing scan results between directories.

use crate::run::EffectiveConfig;
use crate::{CheckArgs, Config, run_scan_with_check_args};
use colored::Colorize;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FindingIdentity {
    id: String,
    message: String,
    file: String,
    line: usize,
    column: Option<usize>,
    code: String,
}

fn normalize_lexically(path: &std::path::Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() && !path.is_absolute() {
                    normalized.push(component.as_os_str());
                }
            }
            _ => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn logical_file(input: &std::path::Path, finding_file: &str) -> String {
    if input.is_file() {
        return "<single-file>".to_string();
    }

    let root = std::fs::canonicalize(input).unwrap_or_else(|_| normalize_lexically(input));
    let candidate = std::path::Path::new(finding_file);
    let candidate_paths = if candidate.is_absolute() {
        vec![
            std::fs::canonicalize(candidate)
                .ok()
                .unwrap_or_else(|| normalize_lexically(candidate)),
        ]
    } else {
        // Finding paths are normally absolute, but relative paths emitted by
        // scanners are relative to the process cwd. Try that contract first;
        // the root-relative fallback is only for callers that construct
        // findings manually.
        let mut paths = Vec::new();
        if let Ok(path) = std::fs::canonicalize(candidate) {
            paths.push(path);
        }
        paths.push(normalize_lexically(candidate));
        if let Ok(path) = std::fs::canonicalize(root.join(candidate)) {
            paths.push(path);
        }
        paths.push(normalize_lexically(&root.join(candidate)));
        paths
    };

    let relative = candidate_paths.iter().find_map(|path| {
        path.strip_prefix(&root)
            .ok()
            .map(|relative| relative.to_path_buf())
            .or_else(|| {
                path.strip_prefix(normalize_lexically(input))
                    .ok()
                    .map(|relative| relative.to_path_buf())
            })
    });

    if let Some(path) = relative {
        // Keep the platform-native separator: on Unix, `a\\b.md` is a valid
        // filename and must not collide with the distinct path `a/b.md`.
        return path.to_string_lossy().into_owned();
    }

    // Keep an unmappable location distinct without putting an absolute path in
    // the comparison key. The original location remains available for display.
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    finding_file.hash(&mut hasher);
    format!("<unmapped:{:016x}>", hasher.finish())
}

fn finding_identity(input: &std::path::Path, finding: &crate::rules::Finding) -> FindingIdentity {
    FindingIdentity {
        id: finding.id.clone(),
        message: finding.message.clone(),
        file: logical_file(input, &finding.location.file),
        line: finding.location.line,
        column: finding.location.column,
        code: finding.code.clone(),
    }
}

fn finding_for_display(
    input: &std::path::Path,
    finding: &crate::rules::Finding,
) -> crate::rules::Finding {
    let mut displayed = finding.clone();
    let logical = logical_file(input, &finding.location.file);
    if !input.is_file() && !logical.starts_with("<unmapped:") {
        displayed.location.file = logical;
    }
    displayed
}

fn diff_findings(
    input1: &std::path::Path,
    findings1: &[crate::rules::Finding],
    input2: &std::path::Path,
    findings2: &[crate::rules::Finding],
) -> (Vec<crate::rules::Finding>, Vec<crate::rules::Finding>) {
    let mut right_counts = HashMap::new();
    for finding in findings2 {
        *right_counts
            .entry(finding_identity(input2, finding))
            .or_insert(0usize) += 1;
    }

    let mut only_in_1 = Vec::new();
    for finding in findings1 {
        let count = right_counts
            .entry(finding_identity(input1, finding))
            .or_insert(0);
        if *count == 0 {
            only_in_1.push(finding_for_display(input1, finding));
        } else {
            *count -= 1;
        }
    }

    let mut left_counts = HashMap::new();
    for finding in findings1 {
        *left_counts
            .entry(finding_identity(input1, finding))
            .or_insert(0usize) += 1;
    }

    let mut only_in_2 = Vec::new();
    for finding in findings2 {
        let count = left_counts
            .entry(finding_identity(input2, finding))
            .or_insert(0);
        if *count == 0 {
            only_in_2.push(finding_for_display(input2, finding));
        } else {
            *count -= 1;
        }
    }

    (only_in_1, only_in_2)
}

fn print_finding(prefix: &str, finding: &crate::rules::Finding) {
    let marker = if prefix == "+" {
        prefix.green()
    } else {
        prefix.red()
    };
    println!(
        "  {} [{}] {}:{} {}",
        marker, finding.id, finding.location.file, finding.location.line, finding.message
    );
}

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

    // Compare normalized finding occurrences, preserving duplicate counts.
    let (only_in_1, only_in_2) = diff_findings(path1, &result1.findings, path2, &result2.findings);

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
            print_finding("-", f);
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
            print_finding("+", f);
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
    use crate::rules::{Category, Severity};
    use crate::test_utils::fixtures::create_finding;
    use tempfile::TempDir;

    fn finding(file: &str, line: usize) -> crate::rules::Finding {
        create_finding(
            "PE-001",
            Severity::Critical,
            Category::PrivilegeEscalation,
            "Sudo execution",
            file,
            line,
        )
    }

    #[test]
    fn identical_directory_trees_under_distinct_roots_have_no_diff() {
        let root1 = TempDir::new().unwrap();
        let root2 = TempDir::new().unwrap();
        let file1 = root1.path().join("SKILL.md");
        let file2 = root2.path().join("SKILL.md");
        let findings1 = vec![finding(&file1.display().to_string(), 1)];
        let findings2 = vec![finding(&file2.display().to_string(), 1)];
        assert_eq!(
            finding_identity(root1.path(), &findings1[0]),
            finding_identity(root2.path(), &findings2[0])
        );

        let (only_in_1, only_in_2) =
            diff_findings(root1.path(), &findings1, root2.path(), &findings2);
        assert!(only_in_1.is_empty());
        assert!(only_in_2.is_empty());
    }

    #[test]
    fn distinct_relative_occurrences_and_counts_are_preserved() {
        let root1 = TempDir::new().unwrap();
        let root2 = TempDir::new().unwrap();
        let common1 = root1.path().join("SKILL.md");
        let common2 = root2.path().join("SKILL.md");
        let extra2 = root2.path().join("extra.md");
        let findings1 = vec![
            finding(&common1.display().to_string(), 1),
            finding(&common1.display().to_string(), 1),
        ];
        let findings2 = vec![
            finding(&common2.display().to_string(), 1),
            finding(&extra2.display().to_string(), 1),
        ];

        let (only_in_1, only_in_2) =
            diff_findings(root1.path(), &findings1, root2.path(), &findings2);
        assert_eq!(only_in_1.len(), 1);
        assert_eq!(only_in_2.len(), 1);
        assert_eq!(only_in_2[0].location.file, "extra.md");
    }

    #[test]
    fn location_changes_are_differences() {
        let root1 = TempDir::new().unwrap();
        let root2 = TempDir::new().unwrap();
        let file1 = root1.path().join("SKILL.md");
        let file2 = root2.path().join("SKILL.md");
        let findings1 = vec![finding(&file1.display().to_string(), 1)];
        let findings2 = vec![finding(&file2.display().to_string(), 2)];

        let (only_in_1, only_in_2) =
            diff_findings(root1.path(), &findings1, root2.path(), &findings2);
        assert_eq!(only_in_1.len(), 1);
        assert_eq!(only_in_2.len(), 1);
    }

    #[test]
    fn code_changes_are_differences() {
        let root1 = TempDir::new().unwrap();
        let root2 = TempDir::new().unwrap();
        let file1 = root1.path().join("SKILL.md");
        let file2 = root2.path().join("SKILL.md");
        let mut changed = finding(&file2.display().to_string(), 1);
        changed.code = "changed code".to_string();
        let findings1 = vec![finding(&file1.display().to_string(), 1)];
        let findings2 = vec![changed];

        let (only_in_1, only_in_2) =
            diff_findings(root1.path(), &findings1, root2.path(), &findings2);
        assert_eq!(only_in_1.len(), 1);
        assert_eq!(only_in_2.len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn path_normalization_preserves_native_names_and_symlink_roots() {
        let root = TempDir::new().unwrap();
        let nested = root.path().join("nested");
        std::fs::create_dir(&nested).unwrap();
        let file = nested.join("file.md");
        std::fs::write(&file, "content").unwrap();
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(root.path(), &alias).unwrap();

        assert_eq!(
            logical_file(root.path(), &file.display().to_string()),
            "nested/file.md"
        );
        assert_eq!(
            logical_file(&alias, &file.display().to_string()),
            "nested/file.md"
        );
        assert_eq!(
            logical_file(
                &root.path().join("nested").join("."),
                &file.display().to_string()
            ),
            "file.md"
        );
        assert_eq!(
            logical_file(
                &root.path().join("nested").join(".."),
                &file.display().to_string()
            ),
            "nested/file.md"
        );
        assert_eq!(
            logical_file(
                root.path(),
                &root
                    .path()
                    .join("nested")
                    .join("..")
                    .join("file.md")
                    .display()
                    .to_string()
            ),
            "file.md"
        );
        assert_eq!(
            logical_file(
                root.path(),
                &root
                    .path()
                    .join("nested")
                    .join(".")
                    .join("file.md")
                    .display()
                    .to_string()
            ),
            "nested/file.md"
        );

        let unix_name = root.path().join("a\\b.md");
        let unix_path = logical_file(root.path(), &unix_name.display().to_string());
        let nested_path = logical_file(
            root.path(),
            &root.path().join("a/b.md").display().to_string(),
        );
        assert_ne!(unix_path, nested_path);
    }

    #[test]
    fn unmappable_locations_use_distinct_fallbacks() {
        let root = TempDir::new().unwrap();
        let first = logical_file(root.path(), "/outside/first.md");
        let second = logical_file(root.path(), "/outside/second.md");
        assert!(first.starts_with("<unmapped:"));
        assert_ne!(first, second);
    }

    #[test]
    fn single_files_with_different_names_compare_as_one_logical_file() {
        let dir = TempDir::new().unwrap();
        let old = dir.path().join("old.md");
        let new = dir.path().join("new.md");
        std::fs::write(&old, "sudo").unwrap();
        std::fs::write(&new, "sudo").unwrap();
        let findings1 = vec![finding(&old.display().to_string(), 1)];
        let findings2 = vec![finding(&new.display().to_string(), 1)];

        let (only_in_1, only_in_2) = diff_findings(&old, &findings1, &new, &findings2);
        assert!(only_in_1.is_empty());
        assert!(only_in_2.is_empty());
    }
}
