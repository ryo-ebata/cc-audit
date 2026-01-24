use cc_audit::{
    Cli, HookScanner, JsonReporter, OutputFormat, Reporter, SarifReporter, ScanResult, ScanType,
    Scanner, SkillScanner, Summary, TerminalReporter,
};
use chrono::Utc;
use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = Cli::parse();

    let mut all_findings = Vec::new();
    let mut targets = Vec::new();

    for path in &cli.paths {
        let result = match cli.scan_type {
            ScanType::Skill => {
                let scanner = SkillScanner::new();
                scanner.scan_path(path)
            }
            ScanType::Hook => {
                let scanner = HookScanner::new();
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
                return ExitCode::from(2);
            }
        }
    }

    let summary = Summary::from_findings(&all_findings);
    let result = ScanResult {
        version: env!("CARGO_PKG_VERSION").to_string(),
        scanned_at: Utc::now().to_rfc3339(),
        target: targets.join(", "),
        summary,
        findings: all_findings,
    };

    let output = match cli.format {
        OutputFormat::Terminal => {
            let reporter = TerminalReporter::new(cli.strict, cli.verbose);
            reporter.report(&result)
        }
        OutputFormat::Json => {
            let reporter = JsonReporter::new();
            reporter.report(&result)
        }
        OutputFormat::Sarif => {
            let reporter = SarifReporter::new();
            reporter.report(&result)
        }
    };

    println!("{}", output);

    if result.summary.passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
