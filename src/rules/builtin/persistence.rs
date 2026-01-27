use crate::rules::types::{Category, Confidence, Rule, Severity};
use regex::Regex;

pub fn rules() -> Vec<Rule> {
    vec![
        ps_001(),
        ps_003(),
        ps_004(),
        ps_005(),
        ps_006(),
        ps_007(),
        ps_008(),
        ps_009(),
    ]
}

fn ps_001() -> Rule {
    Rule {
        id: "PS-001",
        name: "Crontab manipulation",
        description: "Detects crontab commands which could be used to establish persistence",
        severity: Severity::Critical,
        category: Category::Persistence,
        confidence: Confidence::Firm,
        patterns: vec![
            Regex::new(r"\bcrontab\s+").expect("PS-001: invalid regex"),
            Regex::new(r"/etc/cron").expect("PS-001: invalid regex"),
            Regex::new(r"/var/spool/cron").expect("PS-001: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"crontab\s+-l\b").expect("PS-001: invalid regex"), // listing is less dangerous
        ],
        message: "Persistence mechanism: crontab manipulation detected",
        recommendation: "Skills should not modify scheduled tasks. Review the necessity of cron access",
        fix_hint: Some(
            "Remove crontab commands. Use explicit user interaction for scheduled tasks",
        ),
        cwe_ids: &["CWE-912"],
    }
}

fn ps_003() -> Rule {
    Rule {
        id: "PS-003",
        name: "Shell profile modification",
        description: "Detects modifications to shell profiles (.bashrc, .zshrc, etc.) for persistence",
        severity: Severity::Critical,
        category: Category::Persistence,
        confidence: Confidence::Firm,
        patterns: vec![
            Regex::new(r">>\s*.*\.(bashrc|bash_profile|zshrc|profile|zprofile)")
                .expect("PS-003: invalid regex"),
            Regex::new(r">\s*.*\.(bashrc|bash_profile|zshrc|profile|zprofile)")
                .expect("PS-003: invalid regex"),
            Regex::new(r"echo\s+.*\.(bashrc|bash_profile|zshrc|profile|zprofile)")
                .expect("PS-003: invalid regex"),
            Regex::new(r"tee\s+.*\.(bashrc|bash_profile|zshrc|profile|zprofile)")
                .expect("PS-003: invalid regex"),
        ],
        exclusions: vec![],
        message: "Persistence mechanism: shell profile modification detected",
        recommendation: "Skills should not modify shell startup files",
        fix_hint: Some(
            "Remove shell profile modifications. Document required env vars for manual setup",
        ),
        cwe_ids: &["CWE-912"],
    }
}

fn ps_004() -> Rule {
    Rule {
        id: "PS-004",
        name: "System service registration",
        description: "Detects registration of system services (systemd, launchd) for persistence",
        severity: Severity::Critical,
        category: Category::Persistence,
        confidence: Confidence::Tentative,
        patterns: vec![
            // systemd
            Regex::new(r"systemctl\s+(enable|start|daemon-reload)").expect("PS-004: invalid regex"),
            Regex::new(r"/etc/systemd/system/").expect("PS-004: invalid regex"),
            Regex::new(r"\.service\b").expect("PS-004: invalid regex"),
            // launchd (macOS)
            Regex::new(r"launchctl\s+(load|bootstrap|enable)").expect("PS-004: invalid regex"),
            Regex::new(r"~/Library/LaunchAgents/").expect("PS-004: invalid regex"),
            Regex::new(r"/Library/Launch(Agents|Daemons)/").expect("PS-004: invalid regex"),
            Regex::new(r"\.plist\b").expect("PS-004: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"systemctl\s+status").expect("PS-004: invalid regex"),
            Regex::new(r"launchctl\s+list").expect("PS-004: invalid regex"),
        ],
        message: "Persistence mechanism: system service registration detected",
        recommendation: "Skills should not register system services without explicit approval",
        fix_hint: Some(
            "Remove service registration. Provide manual installation instructions instead",
        ),
        cwe_ids: &["CWE-912"],
    }
}

fn ps_005() -> Rule {
    Rule {
        id: "PS-005",
        name: "SSH authorized_keys modification",
        description: "Detects modifications to authorized_keys which could grant persistent SSH access",
        severity: Severity::Critical,
        category: Category::Persistence,
        confidence: Confidence::Certain,
        patterns: vec![
            Regex::new(r">>\s*.*authorized_keys").expect("PS-005: invalid regex"),
            Regex::new(r">\s*.*authorized_keys").expect("PS-005: invalid regex"),
            Regex::new(r"echo\s+.*authorized_keys").expect("PS-005: invalid regex"),
            Regex::new(r"tee\s+.*authorized_keys").expect("PS-005: invalid regex"),
            Regex::new(r"cat\s+.*>\s*.*authorized_keys").expect("PS-005: invalid regex"),
        ],
        exclusions: vec![],
        message: "Persistence mechanism: authorized_keys modification detected",
        recommendation: "Skills should never modify SSH authorized_keys",
        fix_hint: Some("Remove authorized_keys modification. Never automate SSH key management"),
        cwe_ids: &["CWE-912", "CWE-522"],
    }
}

fn ps_006() -> Rule {
    Rule {
        id: "PS-006",
        name: "Delayed/background execution",
        description: "Detects commands that schedule delayed or background execution to evade detection",
        severity: Severity::High,
        category: Category::Persistence,
        confidence: Confidence::Firm,
        patterns: vec![
            // at command for delayed execution
            Regex::new(r"\bat\s+(now|midnight|noon|\d)").expect("PS-006: invalid regex"),
            Regex::new(r"\|\s*at\s+(now|midnight|\d)").expect("PS-006: invalid regex"),
            // batch command
            Regex::new(r"\bbatch\b").expect("PS-006: invalid regex"),
            // screen/tmux hidden sessions
            Regex::new(r"screen\s+-[dDmS]+.*(-c|bash|sh|curl|wget|nc)")
                .expect("PS-006: invalid regex"),
            Regex::new(r"tmux\s+(new-session|new)\s+-d").expect("PS-006: invalid regex"),
            // nohup with suspicious commands (shell, network tools)
            Regex::new(r"nohup\s+.*\b(curl|wget|nc|netcat|bash|sh)\b")
                .expect("PS-006: invalid regex"),
            // nohup with Python/Node (also suspicious)
            Regex::new(r"nohup\s+.*\b(python3?|node|ruby|perl)\b").expect("PS-006: invalid regex"),
            // disown to hide background processes
            Regex::new(r"&\s*;\s*disown").expect("PS-006: invalid regex"),
            Regex::new(r"disown\s+-h").expect("PS-006: invalid regex"),
            // setsid for new session
            Regex::new(r"setsid\s+.*\b(curl|wget|nc|bash|sh)\b").expect("PS-006: invalid regex"),
            // systemd-run for transient services (background execution)
            Regex::new(r"systemd-run\s+(--scope|--user).*\b(curl|wget|bash|sh|python|node)\b")
                .expect("PS-006: invalid regex"),
            // timeout with background execution
            Regex::new(r"timeout\s+.*&\s*$").expect("PS-006: invalid regex"),
            // sleep + command chaining (delayed execution)
            Regex::new(r"sleep\s+\d+\s*;\s*(curl|wget|bash|sh|nc)").expect("PS-006: invalid regex"),
            Regex::new(r"sleep\s+\d+\s*&&\s*(curl|wget|bash|sh|nc)")
                .expect("PS-006: invalid regex"),
            // fork bomb patterns (denial of service)
            Regex::new(r":\(\)\s*\{\s*:\|\:&\s*\}").expect("PS-006: invalid regex"),
            // daemon() style background execution
            Regex::new(r"\bstart-stop-daemon\s+--start").expect("PS-006: invalid regex"),
            // Background execution with output redirection (hiding output)
            Regex::new(r"&>\s*/dev/null\s*&").expect("PS-006: invalid regex"),
            Regex::new(r">\s*/dev/null\s+2>&1\s*&").expect("PS-006: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"^\s*#").expect("PS-006: invalid regex"),
            // Legitimate screen/tmux usage
            Regex::new(r"screen\s+-r").expect("PS-006: invalid regex"),
            Regex::new(r"tmux\s+attach").expect("PS-006: invalid regex"),
        ],
        message: "Delayed or background execution detected. This can be used to evade detection or establish persistence.",
        recommendation: "Avoid scheduling background tasks. Use explicit, foreground execution that users can observe.",
        fix_hint: Some("Remove delayed execution. Execute commands directly in the foreground."),
        cwe_ids: &["CWE-912"],
    }
}

fn ps_007() -> Rule {
    Rule {
        id: "PS-007",
        name: "Init system manipulation",
        description: "Detects manipulation of init systems and startup scripts for persistence",
        severity: Severity::Critical,
        category: Category::Persistence,
        confidence: Confidence::Firm,
        patterns: vec![
            // rc.local modification
            Regex::new(r">\s*/etc/rc\.local").expect("PS-007: invalid regex"),
            Regex::new(r">>\s*/etc/rc\.local").expect("PS-007: invalid regex"),
            // init.d scripts
            Regex::new(r">\s*/etc/init\.d/").expect("PS-007: invalid regex"),
            Regex::new(r"update-rc\.d").expect("PS-007: invalid regex"),
            Regex::new(r"chkconfig\s+--add").expect("PS-007: invalid regex"),
            // XDG autostart
            Regex::new(r"\.config/autostart/.*\.desktop").expect("PS-007: invalid regex"),
            Regex::new(r"/etc/xdg/autostart/").expect("PS-007: invalid regex"),
            // Windows-style (for WSL awareness)
            Regex::new(r"HKEY.*\\Run").expect("PS-007: invalid regex"),
            // Login hooks (macOS)
            Regex::new(r"defaults\s+write.*LoginHook").expect("PS-007: invalid regex"),
        ],
        exclusions: vec![Regex::new(r"^\s*#").expect("PS-007: invalid regex")],
        message: "Init system manipulation detected. This is commonly used to establish boot-time persistence.",
        recommendation: "Skills should not modify system startup scripts or init configurations.",
        fix_hint: Some("Remove init system modifications. Provide manual setup instructions."),
        cwe_ids: &["CWE-912"],
    }
}

fn ps_008() -> Rule {
    Rule {
        id: "PS-008",
        name: "Systemd service creation",
        description: "Detects creation of systemd service unit files for establishing persistence on Linux systems",
        severity: Severity::Critical,
        category: Category::Persistence,
        confidence: Confidence::Certain,
        patterns: vec![
            // Writing service files
            Regex::new(r">\s*/etc/systemd/system/[^/]+\.service").expect("PS-008: invalid regex"),
            Regex::new(r">>\s*/etc/systemd/system/").expect("PS-008: invalid regex"),
            Regex::new(r"tee\s+.*\.service").expect("PS-008: invalid regex"),
            // User systemd services
            Regex::new(r"~/.config/systemd/user/").expect("PS-008: invalid regex"),
            Regex::new(r"\$HOME/.config/systemd/user/").expect("PS-008: invalid regex"),
            // Service file content patterns
            Regex::new(r"\[Service\]").expect("PS-008: invalid regex"),
            Regex::new(r"ExecStart\s*=").expect("PS-008: invalid regex"),
            Regex::new(r"WantedBy\s*=\s*(multi-user|default)\.target")
                .expect("PS-008: invalid regex"),
            // Timer units (for scheduled execution)
            Regex::new(r">\s*/etc/systemd/system/[^/]+\.timer").expect("PS-008: invalid regex"),
            Regex::new(r"\[Timer\]").expect("PS-008: invalid regex"),
            Regex::new(r"OnBootSec\s*=|OnUnitActiveSec\s*=").expect("PS-008: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"^\s*#").expect("PS-008: invalid regex"),
            Regex::new(r"systemctl\s+(status|show|cat)").expect("PS-008: invalid regex"),
        ],
        message: "Systemd service creation detected. This establishes persistent execution on system boot.",
        recommendation: "Skills should not create systemd services. Provide manual installation instructions.",
        fix_hint: Some(
            "Remove systemd service creation. Document how users can manually install if needed.",
        ),
        cwe_ids: &["CWE-912"],
    }
}

fn ps_009() -> Rule {
    Rule {
        id: "PS-009",
        name: "Launchd plist creation (macOS)",
        description: "Detects creation of launchd plist files for establishing persistence on macOS",
        severity: Severity::Critical,
        category: Category::Persistence,
        confidence: Confidence::Certain,
        patterns: vec![
            // User LaunchAgents
            Regex::new(r">\s*~/Library/LaunchAgents/[^/]+\.plist").expect("PS-009: invalid regex"),
            Regex::new(r">\s*\$HOME/Library/LaunchAgents/").expect("PS-009: invalid regex"),
            Regex::new(r"tee\s+.*LaunchAgents.*\.plist").expect("PS-009: invalid regex"),
            // System-wide LaunchDaemons
            Regex::new(r">\s*/Library/LaunchDaemons/").expect("PS-009: invalid regex"),
            Regex::new(r">\s*/Library/LaunchAgents/").expect("PS-009: invalid regex"),
            // Plist content patterns
            Regex::new(r"<key>ProgramArguments</key>").expect("PS-009: invalid regex"),
            Regex::new(r"<key>RunAtLoad</key>").expect("PS-009: invalid regex"),
            Regex::new(r"<key>KeepAlive</key>").expect("PS-009: invalid regex"),
            Regex::new(r"<key>StartInterval</key>").expect("PS-009: invalid regex"),
            Regex::new(r"<key>StartCalendarInterval</key>").expect("PS-009: invalid regex"),
            // plutil to manipulate plists
            Regex::new(r"plutil\s+-insert.*LaunchAgents").expect("PS-009: invalid regex"),
            // defaults write to plist
            Regex::new(r"defaults\s+write.*LaunchAgents").expect("PS-009: invalid regex"),
        ],
        exclusions: vec![
            Regex::new(r"^\s*#").expect("PS-009: invalid regex"),
            Regex::new(r"launchctl\s+list").expect("PS-009: invalid regex"),
            Regex::new(r"plutil\s+-lint").expect("PS-009: invalid regex"),
        ],
        message: "Launchd plist creation detected. This establishes persistent execution on macOS.",
        recommendation: "Skills should not create launchd plists. Provide manual installation instructions.",
        fix_hint: Some(
            "Remove launchd plist creation. Document how users can manually install if needed.",
        ),
        cwe_ids: &["CWE-912"],
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

    // Snapshot tests
    #[test]
    fn snapshot_ps_001() {
        let rule = ps_001();
        let content = include_str!("../../../tests/fixtures/rules/ps_001.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ps_001", findings);
    }

    #[test]
    fn snapshot_ps_003() {
        let rule = ps_003();
        let content = include_str!("../../../tests/fixtures/rules/ps_003.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ps_003", findings);
    }

    #[test]
    fn snapshot_ps_004() {
        let rule = ps_004();
        let content = include_str!("../../../tests/fixtures/rules/ps_004.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ps_004", findings);
    }

    #[test]
    fn snapshot_ps_005() {
        let rule = ps_005();
        let content = include_str!("../../../tests/fixtures/rules/ps_005.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ps_005", findings);
    }

    #[test]
    fn snapshot_ps_006() {
        let rule = ps_006();
        let content = include_str!("../../../tests/fixtures/rules/ps_006.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ps_006", findings);
    }

    #[test]
    fn snapshot_ps_007() {
        let rule = ps_007();
        let content = include_str!("../../../tests/fixtures/rules/ps_007.txt");
        let findings = crate::rules::snapshot_test::scan_with_rule(&rule, content);
        crate::assert_rule_snapshot!("ps_007", findings);
    }
}
