use crate::rules::types::{Category, Confidence, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![
        pe_001(),
        pe_002(),
        pe_003(),
        pe_004(),
        pe_005(),
        pe_006(),
        pe_007(),
        pe_008(),
        pe_009(),
        pe_010(),
        pe_011(),
    ]
}

fn pe_001() -> Rule {
    Rule {
        id: "PE-001",
        name: "Sudo execution",
        description: "Detects sudo commands which could be used for privilege escalation",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Certain,
        patterns: vec![Regex::new(r"\bsudo\s+").expect("PE-001: invalid regex")],
        exclusions: vec![],
        message: "Privilege escalation: sudo command detected",
        recommendation: "Skills should not require sudo. Review why elevated privileges are needed",
        fix_hint: Some("Remove sudo or run the skill with appropriate user permissions"),
        cwe_ids: &["CWE-250"],
    }
}

fn pe_002() -> Rule {
    Rule {
        id: "PE-002",
        name: "Destructive root deletion",
        description: "Detects rm -rf / or similar commands that could destroy the entire filesystem",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Certain,
        patterns: vec![
            // rm -rf / at end of line
            Regex::new(r"rm\s+(-[rfRF]+\s+)+/\s*$").expect("PE-002: invalid regex"),
            // rm -rf / followed by non-alpha (e.g., rm -rf /* or rm -rf /)
            Regex::new(r"rm\s+(-[rfRF]+\s+)+/[^a-zA-Z]").expect("PE-002: invalid regex"),
            // rm -rf with wildcards
            Regex::new(r"rm\s+(-[rfRF]+\s+)+\*").expect("PE-002: invalid regex"),
            // Explicit --no-preserve-root
            Regex::new(r"rm\s+.*--no-preserve-root").expect("PE-002: invalid regex"),
            // rm -rf / followed by command separator (;, &&, ||)
            Regex::new(r"rm\s+(-[rfRF]+\s+)+/\s*(;|&&|\|\|)").expect("PE-002: invalid regex"),
            // rm -rf / with escaped wildcard
            Regex::new(r"rm\s+(-[rfRF]+\s+)+/\\\*").expect("PE-002: invalid regex"),
            // rm -rf with variable expansion that could be /
            Regex::new(r"rm\s+(-[rfRF]+\s+)+\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\s*$")
                .expect("PE-002: invalid regex"),
            // rm -rf with subshell that could evaluate to /
            Regex::new(r"rm\s+(-[rfRF]+\s+)+\$\([^)]+\)").expect("PE-002: invalid regex"),
            // rm -rf with backtick command substitution
            Regex::new(r"rm\s+(-[rfRF]+\s+)+`[^`]+`").expect("PE-002: invalid regex"),
            // Critical system directories
            Regex::new(r"rm\s+(-[rfRF]+\s+)+/(bin|boot|dev|etc|lib|lib64|opt|proc|root|sbin|sys|usr|var)\b")
                .expect("PE-002: invalid regex"),
        ],
        exclusions: vec![],
        message: "Destructive command: potential filesystem destruction detected",
        recommendation: "Never use rm -rf on root or with wildcards in skills",
        fix_hint: Some("Specify exact paths instead of wildcards: rm -rf /tmp/specific-dir"),
        cwe_ids: &["CWE-250", "CWE-73"],
    }
}

fn pe_003() -> Rule {
    Rule {
        id: "PE-003",
        name: "Insecure permission change",
        description: "Detects chmod 777 which makes files world-writable, a security risk",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Certain,
        patterns: vec![
            Regex::new(r"chmod\s+777\b").expect("PE-003: invalid regex"),
            Regex::new(r"chmod\s+[0-7]?777\b").expect("PE-003: invalid regex"),
            Regex::new(r"chmod\s+-R\s+777\b").expect("PE-003: invalid regex"),
            Regex::new(r"chmod\s+a\+rwx\b").expect("PE-003: invalid regex"),
        ],
        exclusions: vec![],
        message: "Insecure permissions: chmod 777 makes files world-writable",
        recommendation: "Use more restrictive permissions (e.g., 755 for directories, 644 for files)",
        fix_hint: Some("chmod 755 for directories, chmod 644 for files"),
        cwe_ids: &["CWE-732"],
    }
}

fn pe_004() -> Rule {
    Rule {
        id: "PE-004",
        name: "System password file access",
        description: "Detects access to /etc/passwd, /etc/shadow, or other sensitive system files",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Firm,
        patterns: vec![
            Regex::new(r"/etc/passwd\b").expect("PE-004: invalid regex"),
            Regex::new(r"/etc/shadow\b").expect("PE-004: invalid regex"),
            Regex::new(r"/etc/sudoers").expect("PE-004: invalid regex"),
            Regex::new(r"/etc/gshadow").expect("PE-004: invalid regex"),
            Regex::new(r"/etc/master\.passwd").expect("PE-004: invalid regex"),
        ],
        exclusions: vec![],
        message: "Sensitive file access: system password file access detected",
        recommendation: "Skills should never access system authentication files",
        fix_hint: Some("Remove any references to /etc/passwd, /etc/shadow, or /etc/sudoers"),
        cwe_ids: &["CWE-200", "CWE-522"],
    }
}

fn pe_005() -> Rule {
    Rule {
        id: "PE-005",
        name: "SSH directory access",
        description: "Detects access to ~/.ssh/ directory which contains sensitive authentication keys",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Firm,
        patterns: vec![
            Regex::new(r"~/\.ssh/").expect("PE-005: invalid regex"),
            Regex::new(r"\$HOME/\.ssh/").expect("PE-005: invalid regex"),
            Regex::new(r"/home/[^/]+/\.ssh/").expect("PE-005: invalid regex"),
            Regex::new(r"\.ssh/id_").expect("PE-005: invalid regex"),
            Regex::new(r"\.ssh/authorized_keys").expect("PE-005: invalid regex"),
            Regex::new(r"\.ssh/known_hosts").expect("PE-005: invalid regex"),
        ],
        exclusions: vec![],
        message: "Sensitive file access: SSH directory access detected",
        recommendation: "Skills should never access SSH keys or configuration",
        fix_hint: Some("Remove any references to ~/.ssh/ or SSH key files"),
        cwe_ids: &["CWE-200", "CWE-522"],
    }
}

fn pe_006() -> Rule {
    Rule {
        id: "PE-006",
        name: "Setuid/setgid manipulation",
        description: "Detects setuid/setgid bit manipulation which can grant elevated privileges to executables",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Certain,
        patterns: vec![
            // chmod with setuid bit
            Regex::new(r"chmod\s+[0-7]*4[0-7]{3}\b").expect("PE-006: invalid regex"),
            Regex::new(r"chmod\s+u\+s\b").expect("PE-006: invalid regex"),
            // chmod with setgid bit
            Regex::new(r"chmod\s+[0-7]*2[0-7]{3}\b").expect("PE-006: invalid regex"),
            Regex::new(r"chmod\s+g\+s\b").expect("PE-006: invalid regex"),
            // chmod with both setuid and setgid
            Regex::new(r"chmod\s+[0-7]*6[0-7]{3}\b").expect("PE-006: invalid regex"),
            // find with -perm for setuid/setgid (suid discovery)
            Regex::new(r"find\s+.*-perm\s+.*[/-]4000").expect("PE-006: invalid regex"),
            Regex::new(r"find\s+.*-perm\s+.*[/-]2000").expect("PE-006: invalid regex"),
            Regex::new(r"find\s+.*-perm\s+.*[/-]6000").expect("PE-006: invalid regex"),
            // chown to root (often combined with setuid)
            Regex::new(r"chown\s+root[:\s]").expect("PE-006: invalid regex"),
        ],
        exclusions: vec![Regex::new(r"^\s*#").expect("PE-006: invalid regex")],
        message: "Setuid/setgid manipulation detected. This can grant elevated privileges to executables.",
        recommendation: "Avoid setting setuid/setgid bits. Use capability-based permissions instead.",
        fix_hint: Some(
            "Remove setuid/setgid: chmod u-s,g-s <file>. Use capabilities if elevated privileges are needed.",
        ),
        cwe_ids: &["CWE-250", "CWE-269"],
    }
}

fn pe_007() -> Rule {
    Rule {
        id: "PE-007",
        name: "Linux capabilities manipulation",
        description: "Detects manipulation of Linux capabilities which can grant specific elevated privileges",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Firm,
        patterns: vec![
            // setcap to add capabilities
            Regex::new(r"\bsetcap\s+").expect("PE-007: invalid regex"),
            // Dangerous capabilities
            Regex::new(r"cap_setuid").expect("PE-007: invalid regex"),
            Regex::new(r"cap_setgid").expect("PE-007: invalid regex"),
            Regex::new(r"cap_sys_admin").expect("PE-007: invalid regex"),
            Regex::new(r"cap_sys_ptrace").expect("PE-007: invalid regex"),
            Regex::new(r"cap_net_admin").expect("PE-007: invalid regex"),
            Regex::new(r"cap_net_raw").expect("PE-007: invalid regex"),
            Regex::new(r"cap_dac_override").expect("PE-007: invalid regex"),
            Regex::new(r"cap_dac_read_search").expect("PE-007: invalid regex"),
            Regex::new(r"cap_chown").expect("PE-007: invalid regex"),
            // getcap to discover capabilities (reconnaissance)
            Regex::new(r"\bgetcap\s+-r\s+/").expect("PE-007: invalid regex"),
            // Python capability libraries
            Regex::new(r"prctl\.set_keepcaps").expect("PE-007: invalid regex"),
            Regex::new(r"capng\.|libcap").expect("PE-007: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"^\s*#").expect("PE-007: invalid regex"),
            Regex::new(r"getcap\s+[^/]").expect("PE-007: invalid regex"), // getcap on specific file is less suspicious
        ],
        message: "Linux capabilities manipulation detected. This can grant specific elevated privileges.",
        recommendation: "Avoid manipulating capabilities. Skills should not require elevated privileges.",
        fix_hint: Some("Remove capability operations. Run with minimal privileges required."),
        cwe_ids: &["CWE-250", "CWE-269"],
    }
}

fn pe_008() -> Rule {
    Rule {
        id: "PE-008",
        name: "Sudoers NOPASSWD injection",
        description: "Detects writes that grant passwordless root by appending to /etc/sudoers or dropping a file into /etc/sudoers.d/ (MITRE T1548.003)",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Firm,
        patterns: vec![
            // echo/printf a NOPASSWD grant redirected into the sudoers file
            Regex::new(r"(echo|printf)\s+[^\n]*NOPASSWD[^\n]*(>>|>|tee)\s*[^\n]*/etc/sudoers")
                .expect("PE-008: invalid regex"),
            // Creating/overwriting a drop-in file under /etc/sudoers.d/
            Regex::new(r"(>>|>|tee\s+(-a\s+)?)\s*/etc/sudoers\.d/\S+")
                .expect("PE-008: invalid regex"),
            // Appending to the main sudoers file
            Regex::new(r"(>>|tee\s+(-a\s+)?)\s*/etc/sudoers\b").expect("PE-008: invalid regex"),
        ],
        exclusions: vec![
            // Comment lines
            Regex::new(r"^\s*#").expect("PE-008: invalid regex"),
        ],
        message: "Sudoers tampering detected: a write grants passwordless root via /etc/sudoers or /etc/sudoers.d/.",
        recommendation: "Artifacts must never edit sudoers. Remove the write and audit for a planted NOPASSWD entry granting root.",
        fix_hint: Some(
            "Remove writes to /etc/sudoers and /etc/sudoers.d/. Privilege changes belong in reviewed provisioning, not artifacts.",
        ),
        cwe_ids: &["CWE-250", "CWE-269"],
    }
}

fn pe_009() -> Rule {
    Rule {
        id: "PE-009",
        name: "Dynamic linker hijacking",
        description: "Detects shared-library injection via /etc/ld.so.preload writes or LD_PRELOAD pointing at writable, relative, or bare paths (MITRE T1574.006)",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Firm,
        patterns: vec![
            // Any reference to the global preload file (writes load a lib into every process)
            Regex::new(r"/etc/ld\.so\.preload").expect("PE-009: invalid regex"),
            // LD_PRELOAD from a world-writable/temp directory
            Regex::new(r"LD_PRELOAD\s*=\s*\S*/(tmp|dev/shm|var/tmp)/\S*\.so")
                .expect("PE-009: invalid regex"),
            // LD_PRELOAD from a relative path (current/parent dir)
            Regex::new(r"LD_PRELOAD\s*=\s*(\./|\.\./)").expect("PE-009: invalid regex"),
            // LD_PRELOAD of a bare filename (resolved from the current directory)
            Regex::new(r"LD_PRELOAD\s*=\s*[A-Za-z0-9_.-]+\.so\b").expect("PE-009: invalid regex"),
        ],
        exclusions: vec![
            // Comment lines
            Regex::new(r"^\s*#").expect("PE-009: invalid regex"),
            // Read-only inspection of the preload file
            Regex::new(r"^\s*(cat|less|stat|head|tail|grep|ls)\s+[^\n]*/etc/ld\.so\.preload")
                .expect("PE-009: invalid regex"),
        ],
        message: "Dynamic linker hijacking detected: a shared library is being injected via /etc/ld.so.preload or an untrusted LD_PRELOAD path.",
        recommendation: "Remove the preload injection. Artifacts must not write /etc/ld.so.preload or preload libraries from writable/relative paths.",
        fix_hint: Some(
            "Delete /etc/ld.so.preload writes and untrusted LD_PRELOAD assignments; load only vetted system libraries by absolute path.",
        ),
        cwe_ids: &["CWE-426", "CWE-114"],
    }
}

fn pe_010() -> Rule {
    Rule {
        id: "PE-010",
        name: "PATH hijacking",
        description: "Detects inline PATH assignments that prepend the current directory or a world-writable/temp directory, letting a planted binary shadow a real command (MITRE T1574.007)",
        severity: Severity::High,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Firm,
        patterns: vec![
            // Value starts with the current directory: PATH=.:...
            Regex::new(r"PATH\s*=\s*\.:").expect("PE-010: invalid regex"),
            // Value starts with an empty element (also the current directory): PATH=:...
            Regex::new(r"PATH\s*=\s*:").expect("PE-010: invalid regex"),
            // Current directory as a middle element: PATH=...:.:...
            Regex::new(r"PATH\s*=[^\n=]*:\.:").expect("PE-010: invalid regex"),
            // Current directory as the trailing element: PATH=...:.
            Regex::new(r"PATH\s*=[^\n=]*:\.(\s|$)").expect("PE-010: invalid regex"),
            // World-writable/temp directory prepended
            Regex::new(r"PATH\s*=\s*/(tmp|dev/shm|var/tmp)[:/\s]").expect("PE-010: invalid regex"),
        ],
        exclusions: vec![
            // Comment lines
            Regex::new(r"^\s*#").expect("PE-010: invalid regex"),
        ],
        message: "PATH hijacking detected: the current directory or a writable/temp path is placed on PATH, so a planted binary can shadow a trusted command.",
        recommendation: "Never put '.', an empty element, or a writable directory on PATH. Use absolute paths for the commands you invoke.",
        fix_hint: Some(
            "Remove '.'/empty/temp entries from PATH; keep only trusted absolute directories.",
        ),
        cwe_ids: &["CWE-426", "CWE-427"],
    }
}

fn pe_011() -> Rule {
    Rule {
        id: "PE-011",
        name: "Container escape primitives",
        description: "Detects classic container-escape techniques: cgroup release_agent, kernel core_pattern handler, nsenter into PID 1 namespaces, and host-root access via /proc/1/root (MITRE T1611)",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        confidence: Confidence::Firm,
        patterns: vec![
            // cgroup notify-on-release escape file
            Regex::new(r"release_agent").expect("PE-011: invalid regex"),
            // Kernel core dump handler hijack
            Regex::new(r"/proc/sys/kernel/core_pattern").expect("PE-011: invalid regex"),
            // Entering the host's namespaces via PID 1
            Regex::new(r"nsenter\s+[^\n]*(-t\s*1\b|--target[ =]1\b)")
                .expect("PE-011: invalid regex"),
            // Reaching the host root filesystem through PID 1
            Regex::new(r"/proc/1/root/").expect("PE-011: invalid regex"),
        ],
        exclusions: vec![
            // Comment lines
            Regex::new(r"^\s*#").expect("PE-011: invalid regex"),
            // Read-only inspection (diagnostics), not a write/escape
            Regex::new(r"^\s*(cat|less|stat|grep|head|tail|ls)\s+[^\n]*(core_pattern|/proc/1/root|release_agent)")
                .expect("PE-011: invalid regex"),
        ],
        message: "Container escape primitive detected: cgroup release_agent, core_pattern, nsenter into PID 1, or /proc/1/root host access.",
        recommendation: "Remove the container-escape construct. Artifacts must never manipulate cgroup release_agent, core_pattern, or enter host namespaces.",
        fix_hint: Some(
            "Delete release_agent/core_pattern writes, nsenter --target 1, and /proc/1/root access; run workloads with least privilege and no host namespace access.",
        ),
        cwe_ids: &["CWE-250", "CWE-269"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pe_001_detects_sudo() {
        let rule = pe_001();
        let test_cases = vec![
            ("sudo rm -rf /tmp", true),
            ("sudo apt install something", true),
            ("pseudocode", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_pe_002_detects_rm_rf_root() {
        let rule = pe_002();
        let test_cases = vec![
            ("rm -rf /", true),
            ("rm -rf /*", true),
            ("rm -rf --no-preserve-root /", true),
            ("rm -rf /tmp/test", false),
            ("rm file.txt", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_pe_003_detects_chmod_777() {
        let rule = pe_003();
        let test_cases = vec![
            ("chmod 777 /tmp/file", true),
            ("chmod -R 777 /var/www", true),
            ("chmod a+rwx script.sh", true),
            ("chmod 755 /tmp/file", false),
            ("chmod 644 config.txt", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_pe_004_detects_password_file_access() {
        let rule = pe_004();
        let test_cases = vec![
            ("cat /etc/passwd", true),
            ("cat /etc/shadow", true),
            ("cat /etc/sudoers", true),
            ("grep root /etc/passwd", true),
            ("cat /etc/master.passwd", true), // BSD
            ("echo 'password123'", false),
            ("cat /etc/hosts", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_pe_005_detects_ssh_access() {
        let rule = pe_005();
        let test_cases = vec![
            ("cat ~/.ssh/id_rsa", true),
            ("cat $HOME/.ssh/id_ed25519", true),
            ("cat /home/user/.ssh/authorized_keys", true),
            ("ssh-keygen -t rsa", false),
            ("ssh user@host", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }

    // Snapshot tests
    #[test]
    fn snapshot_pe_001() {
        let rule = pe_001();
        let content = include_str!("../../../tests/fixtures/rules/pe_001.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("pe_001", findings);
    }

    #[test]
    fn snapshot_pe_002() {
        let rule = pe_002();
        let content = include_str!("../../../tests/fixtures/rules/pe_002.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("pe_002", findings);
    }

    #[test]
    fn snapshot_pe_003() {
        let rule = pe_003();
        let content = include_str!("../../../tests/fixtures/rules/pe_003.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("pe_003", findings);
    }

    #[test]
    fn snapshot_pe_004() {
        let rule = pe_004();
        let content = include_str!("../../../tests/fixtures/rules/pe_004.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("pe_004", findings);
    }

    #[test]
    fn snapshot_pe_005() {
        let rule = pe_005();
        let content = include_str!("../../../tests/fixtures/rules/pe_005.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("pe_005", findings);
    }

    #[test]
    fn test_pe_008_detects_sudoers_injection() {
        let rule = pe_008();
        let test_cases = vec![
            // Malicious: passwordless-root grants via sudoers writes
            (
                "echo 'attacker ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
                true,
            ),
            (
                "echo \"claude ALL=(ALL) NOPASSWD:ALL\" | tee /etc/sudoers.d/claude",
                true,
            ),
            (
                "printf '%s\\n' 'x ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/backdoor",
                true,
            ),
            ("tee -a /etc/sudoers < payload.txt", true),
            ("cat evil >> /etc/sudoers.d/00-backdoor", true),
            // Benign: reads and syntax checks
            ("sudo apt-get update", false),
            ("cat /etc/sudoers", false),
            ("grep NOPASSWD /etc/sudoers", false),
            ("visudo -c", false),
            ("ls -l /etc/sudoers.d/", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "PE-008: Failed for input: {}", input);
        }
    }

    #[test]
    fn snapshot_pe_008() {
        let rule = pe_008();
        let content = include_str!("../../../tests/fixtures/rules/pe_008.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("pe_008", findings);
    }

    #[test]
    fn test_pe_009_detects_linker_hijacking() {
        let rule = pe_009();
        let test_cases = vec![
            // Malicious: ld.so.preload writes and untrusted LD_PRELOAD
            ("echo /tmp/evil.so > /etc/ld.so.preload", true),
            ("LD_PRELOAD=/tmp/rootkit.so ./app", true),
            ("LD_PRELOAD=./evil.so program", true),
            ("export LD_PRELOAD=evil.so", true),
            ("echo \"/dev/shm/x.so\" | tee /etc/ld.so.preload", true),
            // Benign: absolute system lib, read-only inspection, unrelated vars
            (
                "LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so myprogram",
                false,
            ),
            ("cat /etc/ld.so.preload", false),
            ("export LD_LIBRARY_PATH=/opt/lib", false),
            ("ldconfig -p", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "PE-009: Failed for input: {}", input);
        }
    }

    #[test]
    fn snapshot_pe_009() {
        let rule = pe_009();
        let content = include_str!("../../../tests/fixtures/rules/pe_009.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("pe_009", findings);
    }

    #[test]
    fn test_pe_010_detects_path_hijacking() {
        let rule = pe_010();
        let test_cases = vec![
            // Malicious: cwd/empty/temp entries on PATH
            ("export PATH=.:$PATH", true),
            ("export PATH=:/usr/bin", true),
            ("PATH=/tmp/bin:$PATH sh -c id", true),
            ("PATH=$PATH:. ./run", true),
            ("PATH=/dev/shm:$PATH ./payload", true),
            // Benign: trusted absolute directories
            ("export PATH=$HOME/bin:$PATH", false),
            ("export PATH=/usr/local/bin:$PATH", false),
            ("PATH=$PATH:/opt/tool/bin", false),
            ("echo $PATH", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "PE-010: Failed for input: {}", input);
        }
    }

    #[test]
    fn snapshot_pe_010() {
        let rule = pe_010();
        let content = include_str!("../../../tests/fixtures/rules/pe_010.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("pe_010", findings);
    }

    #[test]
    fn test_pe_011_detects_container_escape() {
        let rule = pe_011();
        let test_cases = vec![
            // Malicious: container-escape primitives
            ("echo '/tmp/x' > /sys/fs/cgroup/rdma/release_agent", true),
            ("echo '|/tmp/exploit' > /proc/sys/kernel/core_pattern", true),
            (
                "nsenter --target 1 --mount --uts --ipc --net --pid -- bash",
                true,
            ),
            ("nsenter -t 1 -m -u -i -n -p bash", true),
            ("cp /bin/sh /proc/1/root/tmp/sh", true),
            // Benign: reads and unrelated inspection
            ("cat /proc/1/cgroup", false),
            ("nsenter --help", false),
            ("cat /proc/sys/kernel/core_pattern", false),
            ("ls /proc/1/", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "PE-011: Failed for input: {}", input);
        }
    }

    #[test]
    fn snapshot_pe_011() {
        let rule = pe_011();
        let content = include_str!("../../../tests/fixtures/rules/pe_011.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("pe_011", findings);
    }
}
