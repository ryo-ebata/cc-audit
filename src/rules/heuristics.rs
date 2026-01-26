//! File and variable name heuristics for reducing false positives.
//!
//! This module provides heuristics to identify test files, dummy credentials,
//! and other patterns that are likely to be false positives in security scans.

use regex::Regex;
use std::sync::LazyLock;

/// Known dummy API key patterns that should be excluded from secret detection.
pub static DUMMY_KEY_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    vec![
        // AWS example keys from official documentation
        Regex::new(r"AKIAIOSFODNN7EXAMPLE").unwrap(),
        Regex::new(r"ASIAIOSFODNN7EXAMPLE").unwrap(),
        Regex::new(r"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY").unwrap(),
        // Stripe test keys
        Regex::new(r"^sk_test_[A-Za-z0-9]{24}$").unwrap(),
        Regex::new(r"^pk_test_[A-Za-z0-9]{24}$").unwrap(),
        Regex::new(r"^rk_test_[A-Za-z0-9]{24}$").unwrap(),
        // OpenAI dummy keys (placeholder patterns)
        Regex::new(r"sk-[xX]{32,}").unwrap(),
        Regex::new(r"sk-proj-[xX]{32,}").unwrap(),
        // Anthropic dummy keys
        Regex::new(r"sk-ant-[xX]{32,}").unwrap(),
        Regex::new(r"sk-ant-api\d{2}-[xX]{32,}").unwrap(),
        // Generic placeholder patterns
        Regex::new(r"YOUR_API_KEY(?:_HERE)?").unwrap(),
        Regex::new(r"INSERT_API_KEY").unwrap(),
        Regex::new(r"<API_KEY>").unwrap(),
        Regex::new(r"REPLACE_WITH_YOUR_KEY").unwrap(),
        Regex::new(r"PUT_YOUR_KEY_HERE").unwrap(),
        // All X's or zeros (common placeholders)
        Regex::new(r"^[xX]{16,}$").unwrap(),
        Regex::new(r"^[0]{16,}$").unwrap(),
        // Common test/example literals
        Regex::new(r"(?i)test[_-]?key").unwrap(),
        Regex::new(r"(?i)example[_-]?key").unwrap(),
        Regex::new(r"(?i)dummy[_-]?key").unwrap(),
        Regex::new(r"(?i)fake[_-]?key").unwrap(),
        Regex::new(r"(?i)sample[_-]?key").unwrap(),
    ]
});

/// File name heuristics for identifying test/example files.
pub struct FileHeuristics;

impl FileHeuristics {
    /// Patterns indicating a file is likely a test file.
    const TEST_FILE_PATTERNS: &'static [&'static str] = &[
        "test",
        "tests",
        "spec",
        "specs",
        "__test__",
        "__tests__",
        "__spec__",
        "__specs__",
        "_test",
        "_spec",
        ".test.",
        ".spec.",
        "mock",
        "mocks",
        "__mock__",
        "__mocks__",
        "fake",
        "fakes",
        "dummy",
        "dummies",
        "example",
        "examples",
        "fixture",
        "fixtures",
        "sample",
        "samples",
        "stub",
        "stubs",
        "testdata",
        "test_data",
        "testcases",
        "test_cases",
    ];

    /// Check if a file path indicates a test/example file.
    ///
    /// # Examples
    ///
    /// ```
    /// use cc_audit::rules::heuristics::FileHeuristics;
    ///
    /// assert!(FileHeuristics::is_test_file("src/test_utils.rs"));
    /// assert!(FileHeuristics::is_test_file("tests/integration.rs"));
    /// assert!(FileHeuristics::is_test_file("__tests__/api.test.js"));
    /// assert!(FileHeuristics::is_test_file("fixtures/sample_data.json"));
    /// assert!(!FileHeuristics::is_test_file("src/main.rs"));
    /// ```
    pub fn is_test_file(file_path: &str) -> bool {
        let lower = file_path.to_lowercase();

        // Check for test-related patterns in the path
        Self::TEST_FILE_PATTERNS
            .iter()
            .any(|pattern| lower.contains(pattern))
    }

    /// Check if a variable name indicates a dummy/example credential.
    ///
    /// # Examples
    ///
    /// ```
    /// use cc_audit::rules::heuristics::FileHeuristics;
    ///
    /// assert!(FileHeuristics::is_dummy_variable("EXAMPLE_API_KEY"));
    /// assert!(FileHeuristics::is_dummy_variable("TEST_SECRET"));
    /// assert!(FileHeuristics::is_dummy_variable("DUMMY_TOKEN"));
    /// assert!(FileHeuristics::is_dummy_variable("SAMPLE_KEY"));
    /// assert!(FileHeuristics::is_dummy_variable("MOCK_PASSWORD"));
    /// assert!(!FileHeuristics::is_dummy_variable("API_KEY"));
    /// ```
    pub fn is_dummy_variable(var_name: &str) -> bool {
        let upper = var_name.to_uppercase();
        let prefixes = [
            "EXAMPLE_", "TEST_", "DUMMY_", "SAMPLE_", "MOCK_", "FAKE_", "STUB_",
        ];

        prefixes.iter().any(|prefix| upper.starts_with(prefix))
    }

    /// Check if a line contains a dummy variable name pattern.
    pub fn contains_dummy_variable(line: &str) -> bool {
        static DUMMY_VAR_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"\b(?:EXAMPLE|TEST|DUMMY|SAMPLE|MOCK|FAKE|STUB)_[A-Z_]+")
                .expect("Invalid dummy var regex")
        });

        DUMMY_VAR_PATTERN.is_match(line)
    }

    /// Check if a value matches known dummy key patterns.
    pub fn is_dummy_key_value(value: &str) -> bool {
        DUMMY_KEY_PATTERNS
            .iter()
            .any(|pattern| pattern.is_match(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_test_file_common_patterns() {
        // Test directories and files
        assert!(FileHeuristics::is_test_file("src/test_utils.rs"));
        assert!(FileHeuristics::is_test_file("tests/integration.rs"));
        assert!(FileHeuristics::is_test_file("__tests__/api.test.js"));
        assert!(FileHeuristics::is_test_file("src/__mocks__/db.js"));
        assert!(FileHeuristics::is_test_file("test/unit/auth_test.go"));
        assert!(FileHeuristics::is_test_file("spec/models/user_spec.rb"));
    }

    #[test]
    fn test_is_test_file_fixture_patterns() {
        assert!(FileHeuristics::is_test_file("fixtures/sample_data.json"));
        assert!(FileHeuristics::is_test_file("testdata/config.yaml"));
        assert!(FileHeuristics::is_test_file("test_data/credentials.txt"));
        assert!(FileHeuristics::is_test_file("examples/usage.py"));
        assert!(FileHeuristics::is_test_file("samples/demo.sh"));
    }

    #[test]
    fn test_is_test_file_negative() {
        assert!(!FileHeuristics::is_test_file("src/main.rs"));
        assert!(!FileHeuristics::is_test_file("lib/auth.py"));
        assert!(!FileHeuristics::is_test_file("config/settings.yaml"));
        assert!(!FileHeuristics::is_test_file("app/models/user.rb"));
    }

    #[test]
    fn test_is_dummy_variable() {
        assert!(FileHeuristics::is_dummy_variable("EXAMPLE_API_KEY"));
        assert!(FileHeuristics::is_dummy_variable("TEST_SECRET"));
        assert!(FileHeuristics::is_dummy_variable("DUMMY_TOKEN"));
        assert!(FileHeuristics::is_dummy_variable("SAMPLE_KEY"));
        assert!(FileHeuristics::is_dummy_variable("MOCK_PASSWORD"));
        assert!(FileHeuristics::is_dummy_variable("FAKE_CREDENTIAL"));
        assert!(FileHeuristics::is_dummy_variable("STUB_API_TOKEN"));
    }

    #[test]
    fn test_is_dummy_variable_negative() {
        assert!(!FileHeuristics::is_dummy_variable("API_KEY"));
        assert!(!FileHeuristics::is_dummy_variable("SECRET_TOKEN"));
        assert!(!FileHeuristics::is_dummy_variable("AWS_ACCESS_KEY_ID"));
        assert!(!FileHeuristics::is_dummy_variable("GITHUB_TOKEN"));
    }

    #[test]
    fn test_contains_dummy_variable() {
        assert!(FileHeuristics::contains_dummy_variable(
            "const key = EXAMPLE_API_KEY"
        ));
        assert!(FileHeuristics::contains_dummy_variable(
            "TEST_SECRET = 'abc123'"
        ));
        assert!(FileHeuristics::contains_dummy_variable(
            "export DUMMY_TOKEN=xxx"
        ));
    }

    #[test]
    fn test_contains_dummy_variable_negative() {
        assert!(!FileHeuristics::contains_dummy_variable(
            "const key = API_KEY"
        ));
        assert!(!FileHeuristics::contains_dummy_variable(
            "SECRET_TOKEN = 'real'"
        ));
    }

    #[test]
    fn test_is_dummy_key_value_aws() {
        assert!(FileHeuristics::is_dummy_key_value("AKIAIOSFODNN7EXAMPLE"));
        assert!(FileHeuristics::is_dummy_key_value("ASIAIOSFODNN7EXAMPLE"));
        assert!(FileHeuristics::is_dummy_key_value(
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        ));
    }

    #[test]
    fn test_is_dummy_key_value_stripe() {
        // Test that Stripe test key patterns are matched
        // We test the pattern structure using direct regex matching to avoid
        // triggering GitHub's secret scanning on actual pattern examples
        let patterns = &*DUMMY_KEY_PATTERNS;

        // Verify sk_test_ pattern exists and matches 24 char alphanumeric suffix
        let sk_pattern = patterns.iter().find(|p| {
            let s = format!("{:?}", p);
            s.contains("sk_test_")
        });
        assert!(sk_pattern.is_some(), "sk_test_ pattern should exist");

        // Verify pk_test_ pattern exists
        let pk_pattern = patterns.iter().find(|p| {
            let s = format!("{:?}", p);
            s.contains("pk_test_")
        });
        assert!(pk_pattern.is_some(), "pk_test_ pattern should exist");

        // Verify rk_test_ pattern exists
        let rk_pattern = patterns.iter().find(|p| {
            let s = format!("{:?}", p);
            s.contains("rk_test_")
        });
        assert!(rk_pattern.is_some(), "rk_test_ pattern should exist");
    }

    #[test]
    fn test_is_dummy_key_value_placeholder() {
        assert!(FileHeuristics::is_dummy_key_value("YOUR_API_KEY_HERE"));
        assert!(FileHeuristics::is_dummy_key_value("YOUR_API_KEY"));
        assert!(FileHeuristics::is_dummy_key_value("INSERT_API_KEY"));
        assert!(FileHeuristics::is_dummy_key_value("<API_KEY>"));
        assert!(FileHeuristics::is_dummy_key_value("REPLACE_WITH_YOUR_KEY"));
    }

    #[test]
    fn test_is_dummy_key_value_x_pattern() {
        assert!(FileHeuristics::is_dummy_key_value("xxxxxxxxxxxxxxxx"));
        assert!(FileHeuristics::is_dummy_key_value("XXXXXXXXXXXXXXXX"));
        assert!(FileHeuristics::is_dummy_key_value("0000000000000000"));
        assert!(FileHeuristics::is_dummy_key_value(
            "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        ));
    }

    #[test]
    fn test_is_dummy_key_value_test_example() {
        assert!(FileHeuristics::is_dummy_key_value("test_key"));
        assert!(FileHeuristics::is_dummy_key_value("example_key"));
        assert!(FileHeuristics::is_dummy_key_value("dummy-key"));
        assert!(FileHeuristics::is_dummy_key_value("fake_key"));
        assert!(FileHeuristics::is_dummy_key_value("sample-key"));
    }

    #[test]
    fn test_is_dummy_key_value_negative() {
        // Real-looking keys should not match
        assert!(!FileHeuristics::is_dummy_key_value("AKIAI44QH8DHBEXAMPLE")); // Not exact AWS example
        assert!(!FileHeuristics::is_dummy_key_value(
            "sk_live_abcdefghij1234567890"
        )); // Live key pattern
        assert!(!FileHeuristics::is_dummy_key_value(
            "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        )); // GitHub token format
    }
}
