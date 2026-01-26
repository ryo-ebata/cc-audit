//! Hook mode runner.
//!
//! This module provides integration with hook_mode for CI/CD.

use crate::hook_mode::HookAnalyzer;

/// Runner for hook mode operations.
///
/// Provides a unified interface for running hook mode and
/// analyzing different types of inputs.
pub struct HookRunner;

impl HookRunner {
    /// Create a new hook runner.
    pub fn new() -> Self {
        Self
    }

    /// Analyze bash command input.
    pub fn analyze_bash(
        input: &crate::hook_mode::BashInput,
    ) -> Vec<crate::hook_mode::types::HookFinding> {
        HookAnalyzer::analyze_bash(input)
    }

    /// Analyze write input.
    pub fn analyze_write(
        input: &crate::hook_mode::WriteInput,
    ) -> Vec<crate::hook_mode::types::HookFinding> {
        HookAnalyzer::analyze_write(input)
    }

    /// Analyze edit input.
    pub fn analyze_edit(
        input: &crate::hook_mode::EditInput,
    ) -> Vec<crate::hook_mode::types::HookFinding> {
        HookAnalyzer::analyze_edit(input)
    }

    /// Run hook mode (blocking).
    ///
    /// This reads events from stdin and writes responses to stdout.
    pub fn run() -> i32 {
        crate::hook_mode::run_hook_mode()
    }
}

impl Default for HookRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hook_mode::{BashInput, EditInput, WriteInput};

    #[test]
    fn test_hook_runner_creation() {
        let _runner = HookRunner::new();
    }

    #[test]
    fn test_hook_runner_default() {
        let runner = HookRunner;
        // Just verify it creates successfully
        let _ = runner;
    }

    #[test]
    fn test_hook_runner_analyze_bash_safe() {
        let input = BashInput {
            command: "ls -la".to_string(),
            description: None,
            timeout: None,
        };
        let findings = HookRunner::analyze_bash(&input);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_hook_runner_analyze_bash_dangerous() {
        let input = BashInput {
            command: "sudo rm -rf /".to_string(),
            description: None,
            timeout: None,
        };
        let findings = HookRunner::analyze_bash(&input);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_hook_runner_analyze_write_safe() {
        let input = WriteInput {
            file_path: "/tmp/test.txt".to_string(),
            content: "Hello, world!".to_string(),
        };
        let findings = HookRunner::analyze_write(&input);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_hook_runner_analyze_write_dangerous() {
        let input = WriteInput {
            file_path: "/etc/passwd".to_string(),
            content: "root::0:0::/root:/bin/bash".to_string(),
        };
        let findings = HookRunner::analyze_write(&input);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_hook_runner_analyze_edit_safe() {
        let input = EditInput {
            file_path: "/tmp/test.txt".to_string(),
            old_string: "old".to_string(),
            new_string: "new".to_string(),
        };
        let findings = HookRunner::analyze_edit(&input);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_hook_runner_analyze_edit_dangerous() {
        let input = EditInput {
            file_path: "/etc/sudoers".to_string(),
            old_string: "old".to_string(),
            new_string: "ALL=(ALL) NOPASSWD: ALL".to_string(),
        };
        let findings = HookRunner::analyze_edit(&input);
        assert!(!findings.is_empty());
    }
}
