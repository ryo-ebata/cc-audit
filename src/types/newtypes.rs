//! NewType wrappers for primitive types.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Git reference (branch, tag, or commit hash).
///
/// Wraps a string to provide type safety when passing git refs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GitRef(String);

impl GitRef {
    /// Create a new GitRef from any string-like type.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Get the underlying string reference.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume self and return the inner String.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Default for GitRef {
    fn default() -> Self {
        Self("HEAD".to_string())
    }
}

impl From<&str> for GitRef {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for GitRef {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<str> for GitRef {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GitRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// GitHub/Git authentication token.
///
/// Implements a secure Debug that doesn't leak the token value.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthToken(String);

impl AuthToken {
    /// Create a new AuthToken from any string-like type.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Get the underlying token string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume self and return the inner String.
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Check if the token is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            write!(f, "AuthToken(empty)")
        } else {
            write!(f, "AuthToken(***)")
        }
    }
}

impl From<&str> for AuthToken {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for AuthToken {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Rule identifier (e.g., "PE-001", "EX-002").
///
/// Provides type-safe rule references throughout the codebase.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RuleId(String);

impl RuleId {
    /// Create a new RuleId from any string-like type.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Get the underlying string reference.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume self and return the inner String.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl From<&str> for RuleId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for RuleId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<str> for RuleId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// SHA256 file hash for baseline comparison.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FileHash(String);

impl FileHash {
    /// Create a new FileHash from any string-like type.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Get the underlying hash string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consume self and return the inner String.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl From<&str> for FileHash {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for FileHash {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl AsRef<str> for FileHash {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FileHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// MCP server name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ServerName(String);

impl ServerName {
    /// Create a new ServerName.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Get the underlying string reference.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<&str> for ServerName {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for ServerName {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl fmt::Display for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Command line arguments wrapper.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommandArgs(Vec<String>);

impl CommandArgs {
    /// Create new CommandArgs from an iterator.
    pub fn new(args: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self(args.into_iter().map(Into::into).collect())
    }

    /// Get the arguments as a slice.
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    /// Join arguments with a separator.
    pub fn join(&self, sep: &str) -> String {
        self.0.join(sep)
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get the number of arguments.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<Vec<String>> for CommandArgs {
    fn from(args: Vec<String>) -> Self {
        Self(args)
    }
}

impl<'a> From<&'a [&'a str]> for CommandArgs {
    fn from(args: &'a [&'a str]) -> Self {
        Self(args.iter().map(|s| s.to_string()).collect())
    }
}

/// Compiled regex pattern for efficient reuse.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pattern: regex::Regex,
    source: String,
}

impl CompiledPattern {
    /// Create a new CompiledPattern from a regex string.
    pub fn new(pattern: &str) -> Result<Self, regex::Error> {
        let regex = regex::Regex::new(pattern)?;
        Ok(Self {
            pattern: regex,
            source: pattern.to_string(),
        })
    }

    /// Check if the pattern matches the text.
    pub fn is_match(&self, text: &str) -> bool {
        self.pattern.is_match(text)
    }

    /// Get the source pattern string.
    pub fn as_str(&self) -> &str {
        &self.source
    }

    /// Get the underlying regex.
    pub fn regex(&self) -> &regex::Regex {
        &self.pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_git_ref_default() {
        assert_eq!(GitRef::default().as_str(), "HEAD");
    }

    #[test]
    fn test_git_ref_from_str() {
        let ref1: GitRef = "main".into();
        assert_eq!(ref1.as_str(), "main");

        let ref2 = GitRef::from("develop");
        assert_eq!(ref2.as_str(), "develop");
    }

    #[test]
    fn test_git_ref_display() {
        let git_ref = GitRef::new("v1.0.0");
        assert_eq!(format!("{}", git_ref), "v1.0.0");
    }

    #[test]
    fn test_auth_token_debug_hides_value() {
        let token = AuthToken::new("secret123");
        let debug = format!("{:?}", token);
        assert!(!debug.contains("secret123"));
        assert!(debug.contains("***"));
    }

    #[test]
    fn test_auth_token_empty_debug() {
        let token = AuthToken::new("");
        let debug = format!("{:?}", token);
        assert!(debug.contains("empty"));
    }

    #[test]
    fn test_rule_id_display() {
        let id = RuleId::new("PE-001");
        assert_eq!(format!("{}", id), "PE-001");
    }

    #[test]
    fn test_rule_id_equality() {
        let id1 = RuleId::new("EX-001");
        let id2 = RuleId::new("EX-001");
        let id3 = RuleId::new("EX-002");
        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_file_hash_from_string() {
        let hash = FileHash::new("abc123def456");
        assert_eq!(hash.as_str(), "abc123def456");
    }

    #[test]
    fn test_into_inner() {
        let git_ref = GitRef::new("main");
        assert_eq!(git_ref.into_inner(), "main".to_string());

        let rule_id = RuleId::new("PE-001");
        assert_eq!(rule_id.into_inner(), "PE-001".to_string());
    }

    #[test]
    fn test_server_name() {
        let name = ServerName::new("my-server");
        assert_eq!(name.as_str(), "my-server");
        assert_eq!(format!("{}", name), "my-server");
    }

    #[test]
    fn test_command_args() {
        let args = CommandArgs::new(["arg1", "arg2", "arg3"]);
        assert_eq!(args.len(), 3);
        assert_eq!(args.join(" "), "arg1 arg2 arg3");
        assert!(!args.is_empty());
    }

    #[test]
    fn test_command_args_empty() {
        let args = CommandArgs::default();
        assert!(args.is_empty());
        assert_eq!(args.len(), 0);
    }

    #[test]
    fn test_compiled_pattern() {
        let pattern = CompiledPattern::new(r"hello\s+world").unwrap();
        assert!(pattern.is_match("hello   world"));
        assert!(!pattern.is_match("helloworld"));
        assert_eq!(pattern.as_str(), r"hello\s+world");
    }

    #[test]
    fn test_compiled_pattern_invalid() {
        let result = CompiledPattern::new(r"[invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_auth_token_is_empty() {
        let empty = AuthToken::new("");
        assert!(empty.is_empty());

        let non_empty = AuthToken::new("token");
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn test_auth_token_into_inner() {
        let token = AuthToken::new("secret");
        assert_eq!(token.into_inner(), "secret".to_string());
    }

    #[test]
    fn test_auth_token_from_string() {
        let token: AuthToken = String::from("token123").into();
        assert_eq!(token.as_str(), "token123");

        let token2: AuthToken = "token456".into();
        assert_eq!(token2.as_str(), "token456");
    }

    #[test]
    fn test_file_hash_into_inner() {
        let hash = FileHash::new("abc123");
        assert_eq!(hash.into_inner(), "abc123".to_string());
    }

    #[test]
    fn test_file_hash_display() {
        let hash = FileHash::new("sha256:abc123");
        assert_eq!(format!("{}", hash), "sha256:abc123");
    }

    #[test]
    fn test_file_hash_as_ref() {
        let hash = FileHash::new("abc123");
        let s: &str = hash.as_ref();
        assert_eq!(s, "abc123");
    }

    #[test]
    fn test_server_name_from_implementations() {
        let name1: ServerName = "server1".into();
        assert_eq!(name1.as_str(), "server1");

        let name2: ServerName = String::from("server2").into();
        assert_eq!(name2.as_str(), "server2");
    }

    #[test]
    fn test_command_args_as_slice() {
        let args = CommandArgs::new(["a", "b", "c"]);
        assert_eq!(
            args.as_slice(),
            &["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn test_command_args_from_vec() {
        let vec = vec!["x".to_string(), "y".to_string()];
        let args: CommandArgs = vec.into();
        assert_eq!(args.len(), 2);
    }

    #[test]
    fn test_command_args_from_slice() {
        let slice: &[&str] = &["p", "q", "r"];
        let args: CommandArgs = slice.into();
        assert_eq!(args.len(), 3);
    }

    #[test]
    fn test_compiled_pattern_regex() {
        let pattern = CompiledPattern::new(r"\d+").unwrap();
        let regex = pattern.regex();
        assert!(regex.is_match("123"));
    }

    #[test]
    fn test_git_ref_as_ref() {
        let git_ref = GitRef::new("main");
        let s: &str = git_ref.as_ref();
        assert_eq!(s, "main");
    }

    #[test]
    fn test_git_ref_from_string() {
        let git_ref: GitRef = String::from("develop").into();
        assert_eq!(git_ref.as_str(), "develop");
    }

    #[test]
    fn test_rule_id_as_ref() {
        let rule_id = RuleId::new("PE-001");
        let s: &str = rule_id.as_ref();
        assert_eq!(s, "PE-001");
    }

    #[test]
    fn test_rule_id_from_string() {
        let rule_id: RuleId = String::from("EX-001").into();
        assert_eq!(rule_id.as_str(), "EX-001");
    }

    #[test]
    fn test_file_hash_from_owned_string() {
        let hash: FileHash = String::from("hash123").into();
        assert_eq!(hash.as_str(), "hash123");
    }
}
