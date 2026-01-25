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
| `-f, --format <FORMAT>` | Output format: `terminal` (default), `json`, `sarif`, `html` |
| `-o, --output <FILE>` | Output file path (for HTML/JSON output) |
| `-v, --verbose` | Verbose output |
| `--ci` | CI mode: non-interactive output |

### Scan Options

| Option | Description |
|--------|-------------|
| `-t, --type <SCAN_TYPE>` | Scan type (see [Scan Types](#scan-types)) |
| `-s, --strict` | Strict mode: show medium/low severity findings |
| `-r, --recursive` | Recursive scan |
| `--min-confidence <LEVEL>` | Minimum confidence level: `tentative` (default), `firm`, `certain` |
| `--skip-comments` | Skip comment lines when scanning |
| `--deep-scan` | Enable deep scan with deobfuscation |

### Include/Exclude Options

| Option | Description |
|--------|-------------|
| `--include-tests` | Include test directories in scan |
| `--include-node-modules` | Include node_modules directories in scan |
| `--include-vendor` | Include vendor directories in scan |

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

### Custom Rules & Malware

| Option | Description |
|--------|-------------|
| `--custom-rules <PATH>` | Path to custom rules file (YAML format) |
| `--malware-db <PATH>` | Path to custom malware signatures database |
| `--no-malware-scan` | Disable malware signature scanning |

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

## Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | No issues found | Safe to proceed |
| 1 | Critical/high severity issues detected | Review findings before installation |
| 2 | Scan error (e.g., file not found) | Check file paths and permissions |

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
```
