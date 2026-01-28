# cc-audit Examples

Example files demonstrating security detection capabilities for each scan type and threat category.

## Usage

```bash
# Scan all examples
cargo run -- check ./examples/

# Scan by threat category (skill type)
cargo run -- check ./examples/clean/
cargo run -- check ./examples/exfiltration/
cargo run -- check ./examples/privilege-escalation/
cargo run -- check ./examples/persistence/
cargo run -- check ./examples/prompt-injection/
cargo run -- check ./examples/overpermission/
cargo run -- check ./examples/obfuscation/
cargo run -- check ./examples/supply-chain/
cargo run -- check ./examples/secrets/

# Scan by scan type
cargo run -- check --type hook ./examples/hook/
cargo run -- check --type mcp ./examples/mcp/
cargo run -- check --type command ./examples/command/
cargo run -- check --type docker ./examples/docker/
cargo run -- check --type dependency ./examples/dependency/
cargo run -- check --type subagent ./examples/subagent/
cargo run -- check --type plugin ./examples/plugin/

# Scan with custom rules
cargo run -- check ./examples/rules/test-content.md --custom-rules ./examples/rules/custom-rules.yaml

# Scan test cases
cargo run -- check ./examples/false-positives/
cargo run -- check ./examples/edge-cases/
cargo run -- check ./examples/bypass-attempts/
```

## Directory Structure

```
examples/
├── Threat Categories (--type skill)
│   ├── clean/                 # Safe example (no findings)
│   ├── exfiltration/          # Data exfiltration patterns
│   ├── privilege-escalation/  # Privilege escalation patterns
│   ├── persistence/           # Persistence mechanisms
│   ├── prompt-injection/      # Prompt injection attacks
│   ├── overpermission/        # Overpermission patterns
│   ├── obfuscation/           # Obfuscated code patterns
│   ├── supply-chain/          # Supply chain attacks
│   └── secrets/               # Secret/credential leaks
│
├── Scan Types
│   ├── hook/                  # Hook configurations (--type hook)
│   ├── mcp/                   # MCP server configs (--type mcp)
│   ├── command/               # Slash commands (--type command)
│   ├── rules/                 # Custom rules (--custom-rules)
│   ├── docker/                # Docker files (--type docker)
│   ├── dependency/            # Package manifests (--type dependency)
│   ├── subagent/              # Subagent definitions (--type subagent)
│   └── plugin/                # Plugin definitions (--type plugin)
│
├── Test Cases
│   ├── false-positives/       # Patterns that should NOT trigger
│   ├── edge-cases/            # Boundary condition tests
│   └── bypass-attempts/       # Detection bypass techniques
│
└── CI/CD Integration
    ├── github-actions/        # GitHub Actions workflows
    ├── gitlab-ci/             # GitLab CI configuration
    └── pre-commit/            # Pre-commit hook setup
```

## Examples by Category

### Threat Categories

| Directory | Expected Result | Detection Rules |
|-----------|-----------------|-----------------|
| `clean/` | PASS (0 findings) | - |
| `exfiltration/` | FAIL | EX-001, EX-002, EX-003, EX-005, EX-006, EX-007 |
| `privilege-escalation/` | FAIL | PE-001, PE-002, PE-003, PE-004, PE-005 |
| `persistence/` | FAIL | PS-001, PS-003, PS-004, PS-005, PS-006, PS-007 |
| `prompt-injection/` | FAIL | PI-001, PI-002, PI-003 |
| `overpermission/` | FAIL | OP-001 |
| `obfuscation/` | FAIL | OB-001, OB-002, OB-003, OB-004, OB-005, OB-006 |
| `supply-chain/` | FAIL | SC-001, SC-002, SC-003 |
| `secrets/` | FAIL | SL-001, SL-002, SL-003, SL-004, SL-005 |

### Scan Types

| Directory | Scan Type | Expected Result | Detection Rules |
|-----------|-----------|-----------------|-----------------|
| `hook/` | `--type hook` | FAIL | EX-001, PE-001, SC-001 |
| `mcp/` | `--type mcp` | FAIL | PE-001, SL-001, SL-003, SC-001, EX-005 |
| `command/` | `--type command` | FAIL | PE-001, EX-001, SC-001 |
| `rules/` | `--custom-rules` | FAIL | CUSTOM-001 to CUSTOM-004 |
| `docker/` | `--type docker` | FAIL | DK-001, DK-002, DK-003 |
| `dependency/` | `--type dependency` | FAIL | DEP-001 to DEP-009 |
| `subagent/` | `--type subagent` | FAIL | OP-001, EX-001, PE-001, PE-005 |
| `plugin/` | `--type plugin` | FAIL | OP-001, SC-001, PE-001 |

### Test Cases

| Directory | Purpose |
|-----------|---------|
| `false-positives/` | Patterns that SHOULD NOT trigger detections |
| `edge-cases/` | Boundary condition tests |
| `bypass-attempts/` | Detection bypass techniques for testing |

---

## Threat Category Details

### clean/
Example of a safe skill. No security issues detected.

### exfiltration/
Data exfiltration detection examples:
- `EX-001`: curl/wget with environment variables
- `EX-002`: base64 encoding with network transmission
- `EX-003`: DNS-based data exfiltration (nslookup, dig, host)
- `EX-005`: netcat outbound connection
- `EX-006`: Alternative protocol exfiltration (FTP, SCP, TFTP, SMTP, IRC)
- `EX-007`: Cloud storage exfiltration (S3, GCS, Azure)

### privilege-escalation/
Privilege escalation detection examples:
- `PE-001`: sudo execution
- `PE-002`: destructive root deletion (rm -rf /)
- `PE-003`: chmod 777 (world-writable permissions)
- `PE-004`: system password file access
- `PE-005`: ~/.ssh/ directory access

### persistence/
Persistence mechanism detection examples:
- `PS-001`: crontab manipulation
- `PS-003`: shell profile modification (.bashrc, .zshrc, .profile)
- `PS-004`: system service registration (systemd, launchd)
- `PS-005`: authorized_keys modification
- `PS-006`: delayed/background execution (nohup, disown, at, screen, tmux)
- `PS-007`: init system manipulation (rc.local, init.d)

### prompt-injection/
Prompt injection detection examples:
- `PI-001`: "ignore previous instructions" patterns
- `PI-002`: Hidden instructions in HTML comments
- `PI-003`: invisible Unicode characters

### overpermission/
Overpermission detection examples:
- `OP-001`: allowed-tools: * (wildcard)

### obfuscation/
Obfuscation detection examples:
- `OB-001`: eval with variable expansion
- `OB-002`: base64 decode execution
- `OB-003`: hex/octal encoded execution ($'\x..', printf \x)
- `OB-004`: string manipulation obfuscation (rev, cut, array joining)
- `OB-005`: dynamic code execution patterns (source /dev/stdin, bash -c)
- `OB-006`: alternative encoding execution (base32, rot13, gzip -d)

### supply-chain/
Supply chain attack detection examples:
- `SC-001`: curl piped to bash/sh
- `SC-002`: wget piped to bash/sh
- `SC-003`: untrusted package sources (HTTP registries)

### secrets/
Secret leak detection examples:
- `SL-001`: AWS Access Key IDs
- `SL-002`: GitHub tokens (ghp_, gho_, etc.)
- `SL-003`: AI API keys (OpenAI, Anthropic)
- `SL-004`: generic secret patterns
- `SL-005`: private key blocks (RSA, EC, OpenSSH)

---

## Scan Type Details

### hook/
Hook configuration scanning examples (use `--type hook`):
- Scans `settings.json` files with hooks configuration
- Checks PreToolUse, PostToolUse, Notification, Stop hooks
- Detects dangerous commands in hook definitions
- Files:
  - `dangerous-settings.json`: Hooks with exfiltration, sudo, supply chain attacks
  - `safe-settings.json`: Safe hooks with logging and notifications

### mcp/
MCP server configuration scanning examples (use `--type mcp`):
- Scans `mcp.json` and similar MCP configuration files
- Checks server commands, arguments, and environment variables
- Detects hardcoded secrets, sudo usage, supply chain attacks
- Files:
  - `dangerous-mcp.json`: MCP servers with sudo, hardcoded API keys, reverse shells
  - `safe-mcp.json`: Safe MCP server configurations

### command/
Slash command definition scanning examples (use `--type command`):
- Scans `.claude/commands/*.md` files
- Checks command definitions for dangerous patterns
- Files:
  - `dangerous-deploy.md`: Commands with sudo, curl|bash, credential exfiltration
  - `safe-build.md`: Safe build command

### rules/
Custom rules scanning examples (use `--custom-rules`):
- Example custom rule definitions in YAML format
- Test content to verify custom rule detection
- Files:
  - `custom-rules.yaml`: Custom rules for internal API, database credentials, sensitive files
  - `test-content.md`: Content that triggers custom rules

### docker/
Docker security detection examples (use `--type docker`):
- `DK-001`: privileged containers
- `DK-002`: running as root user
- `DK-003`: curl/wget piped to shell in RUN instructions

### dependency/
Package dependency scanning examples (use `--type dependency`):
- `DEP-001`: Dangerous lifecycle scripts (postinstall/preinstall with curl|bash)
- `DEP-002`: Git URL dependencies without version pinning
- `DEP-003`: Wildcard version dependencies ("*", "latest")
- `DEP-004`: HTTP dependency URLs (insecure, MITM vulnerable)
- `DEP-005`: Direct tarball/file URL dependencies
- `DEP-006`: Postinstall script execution
- `DEP-007`: Preinstall script execution
- `DEP-008`: Typosquatting package names (loadash, axois, etc.)
- `DEP-009`: Dependency confusion patterns (@internal/, @corp/)
- Files:
  - `dangerous-package.json`: npm package with multiple security issues
  - `safe-package.json`: Safe npm package configuration
  - `dangerous-Cargo.toml`: Rust crate with git and wildcard dependencies
  - `dangerous-requirements.txt`: Python requirements with git and HTTP URLs

### subagent/
Subagent definition scanning examples (use `--type subagent`):
- Scans `.claude/agents/*.md` files
- Checks for `allowed-tools: *` (wildcard permissions)
- Detects hooks with dangerous commands
- Identifies privileged operations in agent descriptions
- Files:
  - `dangerous-agent.md`: Agent with wildcard permissions, exfiltration hooks, sudo usage
  - `safe-agent.md`: Safe agent with minimal permissions (Read, Grep only)

### plugin/
Plugin marketplace definition scanning examples (use `--type plugin`):
- Scans `marketplace.json` and `plugin.json` files
- Checks for wildcard tool permissions in skills and permissions
- Detects sudo/privileged MCP server commands
- Identifies supply chain attacks in hooks (curl|bash, wget|sh)
- Files:
  - `marketplace.json`: Plugin with wildcard permissions, sudo MCP server, malicious hooks
  - `plugin.json`: Safe plugin with minimal permissions

---

## Test Case Details

### false-positives/
Patterns that SHOULD NOT trigger detections (false positive tests):
- Localhost/127.0.0.1 requests with env vars (excluded by EX-001)
- `nc -l` listening mode (excluded by EX-005)
- `crontab -l` list only (excluded by PS-001)
- `systemctl status` (excluded by PS-004)
- Safe chmod values (755, 644, 600)
- SSH commands without file access (ssh, ssh-keygen)
- TODO/FIXME/NOTE in HTML comments (excluded by PI-002)
- Base64 encoding without execution
- String literals containing patterns
- Comments containing patterns

**Known Limitations** (currently triggers false positives):
- Patterns in comments are still detected
- Patterns in string literals (`echo "..."`) are detected
- `.service`/`.plist` in filenames trigger PS-004
- `~/.ssh/` in `chmod` or `ssh-add` context triggers PE-005

### edge-cases/
Boundary condition tests to verify scanner behavior:
- Multi-line commands
- Mixed safe/unsafe patterns
- URL-like patterns in comments vs actual commands
- Commented-out dangerous code
- Heredocs and string literals
- Variable names resembling commands
- Different shell syntaxes (arrays, command substitution)
- Unicode variations
- Case sensitivity
- Whitespace variations
- Embedded commands in pipelines
- Path variations for SSH access
- Regex boundary edge cases

### bypass-attempts/
Detection bypass techniques for testing scanner effectiveness:
- **encoding/**: String concatenation, hex/octal encoding
- **language-specific/**: Node.js and Python evasion techniques
- **multiline/**: Split commands across lines
- **obfuscation/**: Advanced obfuscation patterns
- **reverse-shells/**: Polyglot shells
- **indirect/**: Alias and function-based execution
- **timing/**: Delayed execution patterns
- **suppression-abuse/**: Malicious suppression directives
- **data-exfil/**: Alternative exfiltration channels

---

## CI/CD Integration

### github-actions/
GitHub Actions workflow examples:
- `cc-audit.yml`: Basic scanning workflow
- `cc-audit-sarif.yml`: SARIF output with GitHub Security tab integration

### gitlab-ci/
GitLab CI configuration example:
- `.gitlab-ci.yml`: Pipeline configuration for GitLab

### pre-commit/
Pre-commit hook setup guide:
- Automatic installation with `cc-audit hook init`
- Manual setup with pre-commit framework, husky, lint-staged, lefthook
