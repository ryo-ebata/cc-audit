use crate::rules::types::{Category, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![ps_001(), ps_003(), ps_004(), ps_005()]
}

fn ps_001() -> Rule {
    Rule {
        id: "PS-001",
        name: "Crontab manipulation",
        description: "Detects crontab commands which could be used to establish persistence",
        severity: Severity::Critical,
        category: Category::Persistence,
        patterns: vec![
            Regex::new(r"\bcrontab\s+").unwrap(),
            Regex::new(r"/etc/cron").unwrap(),
            Regex::new(r"/var/spool/cron").unwrap(),
        ],
        exclusions: vec![
            Regex::new(r"crontab\s+-l\b").unwrap(), // listing is less dangerous
        ],
        message: "Persistence mechanism: crontab manipulation detected",
        recommendation: "Skills should not modify scheduled tasks. Review the necessity of cron access",
    }
}

fn ps_003() -> Rule {
    Rule {
        id: "PS-003",
        name: "Shell profile modification",
        description: "Detects modifications to shell profiles (.bashrc, .zshrc, etc.) for persistence",
        severity: Severity::Critical,
        category: Category::Persistence,
        patterns: vec![
            Regex::new(r">>\s*.*\.(bashrc|bash_profile|zshrc|profile|zprofile)").unwrap(),
            Regex::new(r">\s*.*\.(bashrc|bash_profile|zshrc|profile|zprofile)").unwrap(),
            Regex::new(r"echo\s+.*\.(bashrc|bash_profile|zshrc|profile|zprofile)").unwrap(),
            Regex::new(r"tee\s+.*\.(bashrc|bash_profile|zshrc|profile|zprofile)").unwrap(),
        ],
        exclusions: vec![],
        message: "Persistence mechanism: shell profile modification detected",
        recommendation: "Skills should not modify shell startup files",
    }
}

fn ps_004() -> Rule {
    Rule {
        id: "PS-004",
        name: "System service registration",
        description: "Detects registration of system services (systemd, launchd) for persistence",
        severity: Severity::Critical,
        category: Category::Persistence,
        patterns: vec![
            // systemd
            Regex::new(r"systemctl\s+(enable|start|daemon-reload)").unwrap(),
            Regex::new(r"/etc/systemd/system/").unwrap(),
            Regex::new(r"\.service\b").unwrap(),
            // launchd (macOS)
            Regex::new(r"launchctl\s+(load|bootstrap|enable)").unwrap(),
            Regex::new(r"~/Library/LaunchAgents/").unwrap(),
            Regex::new(r"/Library/Launch(Agents|Daemons)/").unwrap(),
            Regex::new(r"\.plist\b").unwrap(),
        ],
        exclusions: vec![
            Regex::new(r"systemctl\s+status").unwrap(),
            Regex::new(r"launchctl\s+list").unwrap(),
        ],
        message: "Persistence mechanism: system service registration detected",
        recommendation: "Skills should not register system services without explicit approval",
    }
}

fn ps_005() -> Rule {
    Rule {
        id: "PS-005",
        name: "SSH authorized_keys modification",
        description: "Detects modifications to authorized_keys which could grant persistent SSH access",
        severity: Severity::Critical,
        category: Category::Persistence,
        patterns: vec![
            Regex::new(r">>\s*.*authorized_keys").unwrap(),
            Regex::new(r">\s*.*authorized_keys").unwrap(),
            Regex::new(r"echo\s+.*authorized_keys").unwrap(),
            Regex::new(r"tee\s+.*authorized_keys").unwrap(),
            Regex::new(r"cat\s+.*>\s*.*authorized_keys").unwrap(),
        ],
        exclusions: vec![],
        message: "Persistence mechanism: authorized_keys modification detected",
        recommendation: "Skills should never modify SSH authorized_keys",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ps_001_detects_crontab() {
        let rule = ps_001();
        let test_cases = vec![
            ("crontab -e", true),
            ("crontab /tmp/cron.txt", true),
            ("echo '* * * * * /tmp/backdoor' >> /etc/cron.d/evil", true),
            ("crontab -l", false), // listing is excluded
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_ps_003_detects_shell_profile_mod() {
        let rule = ps_003();
        let test_cases = vec![
            ("echo 'export PATH=...' >> ~/.bashrc", true),
            ("echo 'alias ll=ls' >> ~/.zshrc", true),
            ("tee -a ~/.bash_profile", true),
            ("cat ~/.bashrc", false), // reading is ok
            ("echo 'hello' > file.txt", false),
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_ps_004_detects_service_registration() {
        let rule = ps_004();
        let test_cases = vec![
            ("systemctl enable myservice", true),
            ("systemctl start backdoor.service", true),
            ("cp evil.service /etc/systemd/system/", true),
            ("launchctl load ~/Library/LaunchAgents/com.evil.plist", true),
            ("cp agent.plist ~/Library/LaunchAgents/", true),
            ("systemctl status nginx", false), // status is excluded
            ("launchctl list", false),         // list is excluded
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            let excluded = rule.exclusions.iter().any(|e| e.is_match(input));
            let result = matched && !excluded;
            assert_eq!(result, should_match, "Failed for input: {}", input);
        }
    }

    #[test]
    fn test_ps_005_detects_authorized_keys_mod() {
        let rule = ps_005();
        let test_cases = vec![
            ("echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys", true),
            ("cat key.pub >> /home/user/.ssh/authorized_keys", true),
            ("tee -a ~/.ssh/authorized_keys", true),
            ("cat ~/.ssh/authorized_keys", false), // reading is ok
        ];

        for (input, should_match) in test_cases {
            let matched = rule.patterns.iter().any(|p| p.is_match(input));
            assert_eq!(matched, should_match, "Failed for input: {}", input);
        }
    }
}
