//! Auto-fix handler.

use crate::run::EffectiveConfig;
use crate::{AutoFixer, CheckArgs, Config, run_scan_with_check_args};
use colored::Colorize;
use std::process::ExitCode;

/// Handle --fix or --fix-dry-run command.
pub fn handle_fix(args: &CheckArgs) -> ExitCode {
    // Load config to get effective settings
    let project_root = args.paths.first().and_then(|p| {
        if p.is_dir() {
            Some(p.as_path())
        } else {
            p.parent()
        }
    });
    let config = Config::load(project_root);
    let effective = EffectiveConfig::from_check_args_and_config(args, &config);

    let dry_run = effective.fix_dry_run;

    // First, run a scan to get findings
    let result = match run_scan_with_check_args(args) {
        Some(r) => r,
        None => {
            eprintln!("Failed to scan");
            return ExitCode::from(2);
        }
    };

    if result.findings.is_empty() {
        println!("{}", "No findings to fix.".green());
        return ExitCode::SUCCESS;
    }

    // Generate and apply fixes
    let fixer = AutoFixer::new(dry_run);
    let fixes = fixer.generate_fixes(&result.findings);

    if fixes.is_empty() {
        println!(
            "{}",
            "No auto-fixable issues found. Manual review required.".yellow()
        );
        println!(
            "\nFound {} issues, but none have automatic fixes available.",
            result.findings.len()
        );
        return ExitCode::from(1);
    }

    println!(
        "Found {} fixable issue(s) out of {} total findings.\n",
        fixes.len(),
        result.findings.len()
    );

    let fix_result = fixer.apply_fixes(&fixes);
    println!("{}", fix_result.format_terminal(dry_run));

    if fix_result.errors.is_empty() {
        if dry_run {
            println!("{}", "Run with --fix to apply these changes.".cyan().bold());
        }
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
