use crate::rules::types::{Category, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![pe_001(), pe_002(), pe_003(), pe_004(), pe_005()]
}

fn pe_001() -> Rule {
    Rule {
        id: "PE-001",
        name: "Sudo execution",
        description: "Detects sudo commands which could be used for privilege escalation",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        patterns: vec![Regex::new(r"\bsudo\s+").unwrap()],
        exclusions: vec![],
        message: "Privilege escalation: sudo command detected",
        recommendation: "Skills should not require sudo. Review why elevated privileges are needed",
    }
}

fn pe_002() -> Rule {
    Rule {
        id: "PE-002",
        name: "Destructive root deletion",
        description: "Detects rm -rf / or similar commands that could destroy the entire filesystem",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        patterns: vec![
            Regex::new(r"rm\s+(-[rfRF]+\s+)+/\s*$").unwrap(),
            Regex::new(r"rm\s+(-[rfRF]+\s+)+/[^a-zA-Z]").unwrap(),
            Regex::new(r"rm\s+(-[rfRF]+\s+)+\*").unwrap(),
            Regex::new(r"rm\s+.*--no-preserve-root").unwrap(),
        ],
        exclusions: vec![],
        message: "Destructive command: potential filesystem destruction detected",
        recommendation: "Never use rm -rf on root or with wildcards in skills",
    }
}

fn pe_003() -> Rule {
    Rule {
        id: "PE-003",
        name: "Insecure permission change",
        description: "Detects chmod 777 which makes files world-writable, a security risk",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        patterns: vec![
            Regex::new(r"chmod\s+777\b").unwrap(),
            Regex::new(r"chmod\s+[0-7]?777\b").unwrap(),
            Regex::new(r"chmod\s+-R\s+777\b").unwrap(),
            Regex::new(r"chmod\s+a\+rwx\b").unwrap(),
        ],
        exclusions: vec![],
        message: "Insecure permissions: chmod 777 makes files world-writable",
        recommendation: "Use more restrictive permissions (e.g., 755 for directories, 644 for files)",
    }
}

fn pe_004() -> Rule {
    Rule {
        id: "PE-004",
        name: "System password file access",
        description: "Detects access to /etc/passwd, /etc/shadow, or other sensitive system files",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        patterns: vec![
            Regex::new(r"/etc/passwd\b").unwrap(),
            Regex::new(r"/etc/shadow\b").unwrap(),
            Regex::new(r"/etc/sudoers").unwrap(),
            Regex::new(r"/etc/gshadow").unwrap(),
            Regex::new(r"/etc/master\.passwd").unwrap(),
        ],
        exclusions: vec![],
        message: "Sensitive file access: system password file access detected",
        recommendation: "Skills should never access system authentication files",
    }
}

fn pe_005() -> Rule {
    Rule {
        id: "PE-005",
        name: "SSH directory access",
        description: "Detects access to ~/.ssh/ directory which contains sensitive authentication keys",
        severity: Severity::Critical,
        category: Category::PrivilegeEscalation,
        patterns: vec![
            Regex::new(r"~/\.ssh/").unwrap(),
            Regex::new(r"\$HOME/\.ssh/").unwrap(),
            Regex::new(r"/home/[^/]+/\.ssh/").unwrap(),
            Regex::new(r"\.ssh/id_").unwrap(),
            Regex::new(r"\.ssh/authorized_keys").unwrap(),
            Regex::new(r"\.ssh/known_hosts").unwrap(),
        ],
        exclusions: vec![],
        message: "Sensitive file access: SSH directory access detected",
        recommendation: "Skills should never access SSH keys or configuration",
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

}
