# Advanced Features

[日本語](./FEATURES.ja.md)

## Baseline & Drift Detection

Detect changes ("drift") between scans to prevent rug pull attacks.

### Create a Baseline

```bash
cc-audit check --save-baseline baseline.json ./my-skill/
```

### Check for Drift

```bash
cc-audit check --baseline-file baseline.json ./my-skill/
```

Output shows:
- **New findings**: Issues that appeared since baseline
- **Resolved findings**: Issues that were fixed
- **Changed findings**: Issues that moved to different severity

### Compare Two Versions

```bash
cc-audit check --compare ./skill-v1.0/ ./skill-v1.1/
```

---

## Auto-Fix

Automatically fix certain issues:

```bash
# Preview fixes without applying
cc-audit check --fix-dry-run ./my-skill/

# Apply auto-fixes
cc-audit check --fix ./my-skill/
```

**Fixable Issues:**
- `OP-001`: Wildcard permissions → Suggest specific tools
- `PE-003`: `chmod 777` → Recommend `chmod 755` or `chmod 644`

---

## Deep Scan with Deobfuscation

Detect encoded or obfuscated malicious patterns:

```bash
cc-audit check --deep-scan ./my-skill/
```

**Detected Encodings:**
- Base64 encoded commands
- Hex/Octal encoded strings
- Unicode escape sequences
- String concatenation tricks

---

## MCP Server Mode

Run cc-audit as an MCP server for integration with Claude Code:

```bash
cc-audit serve
```

This exposes scanning functionality as MCP tools that Claude Code can invoke.

**Available MCP Tools:**
- `scan` — Scan files or directories
- `scan_content` — Scan code snippets inline
- `check_rule` — Test specific security rules
- `list_rules` — Get all available detection rules
- `get_fix_suggestion` — Get automated fix suggestions

**Setup:**

Create or edit `.mcp.json`:

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

For complete MCP integration guide, see [MCP Integration Documentation](./MCP.md).

---

## Profiles

Save and reuse scan configurations:

```bash
# Save current settings as a profile
cc-audit check --save-profile strict-ci --strict --ci --format sarif ./

# Load settings from profile
cc-audit check --profile strict-ci ./my-skill/
```

Profiles are stored in `~/.config/cc-audit/profiles/`.

---

## Watch Mode

Continuously monitor files and re-scan on changes:

```bash
cc-audit check --watch ./my-skill/
```

Useful during skill development to catch issues immediately.

---

## Output Formats

### Terminal (default)

Human-readable colored output with risk score visualization.

### JSON

Machine-readable format for programmatic processing:

```bash
cc-audit check ./skill/ --format json --output results.json
```

### SARIF

Static Analysis Results Interchange Format for CI/CD integration:

```bash
cc-audit check ./skill/ --format sarif --output results.sarif
```

### HTML

Interactive HTML reports for security reviews:

```bash
cc-audit check ./skill/ --format html --output report.html
```

Includes:
- Executive summary with risk score visualization
- Findings grouped by severity and category
- Interactive filtering and search
- Code snippets with syntax highlighting
- Fix recommendations

### Markdown

Plain Markdown format for documentation and reports:

```bash
cc-audit check ./skill/ --format markdown --output report.md
```

---

## Client Scanning

Scan installed AI coding client configurations automatically:

```bash
# Scan all installed clients
cc-audit check --all-clients

# Scan a specific client
cc-audit check --client claude
cc-audit check --client cursor
cc-audit check --client windsurf
cc-audit check --client vscode
```

Detects and scans:
- MCP server configurations
- Hook settings
- Custom commands
- Installed skills and plugins

---

## Remote Repository Scanning

Scan remote GitHub repositories without cloning manually:

```bash
# Scan a single repository
cc-audit check --remote https://github.com/user/awesome-skill

# Scan at specific branch/tag/commit
cc-audit check --remote https://github.com/user/repo --git-ref v1.0.0

# Scan with authentication (for private repos)
cc-audit check --remote https://github.com/org/private-repo --remote-auth $GITHUB_TOKEN

# Scan multiple repositories from file
cc-audit check --remote-list repos.txt --parallel-clones 8

# Scan all awesome-claude-code repositories
cc-audit check --awesome-claude-code --summary
```

---

## Security Badges

Generate security badges for your project:

```bash
# Generate Markdown badge
cc-audit check ./skill/ --badge --badge-format markdown

# Generate HTML badge
cc-audit check ./skill/ --badge --badge-format html

# Generate shields.io URL only
cc-audit check ./skill/ --badge --badge-format url
```

Example output:
```markdown
[![Security: A](https://img.shields.io/badge/security-A-brightgreen)](...)
```

---

## MCP Pinning (Rug-Pull Detection)

Pin MCP tool configurations to detect unauthorized changes:

```bash
# Pin current configuration
cc-audit check --type mcp ~/.claude/mcp.json --pin

# Verify pins haven't changed
cc-audit check --type mcp ~/.claude/mcp.json --pin-verify

# Update pins after authorized changes
cc-audit check --type mcp ~/.claude/mcp.json --pin-update

# Force overwrite existing pins
cc-audit check --type mcp ~/.claude/mcp.json --pin-update --pin-force
```

Pins include:
- Tool names and descriptions
- Configuration schemas
- Permission requirements
- Server endpoints

---

## Hook Mode

Run cc-audit as a Claude Code hook for real-time scanning:

```bash
cc-audit check --hook-mode
```

Configure in your Claude Code settings:
```json
{
  "hooks": {
    "pre-tool-call": {
      "command": "cc-audit check --hook-mode"
    }
  }
}
```

---

## SBOM Generation

Generate Software Bill of Materials (CycloneDX format):

```bash
# Generate CycloneDX SBOM
cc-audit check ./skill/ --sbom --sbom-format cyclonedx --output sbom.json

# Include specific ecosystems
cc-audit check ./skill/ --sbom --sbom-npm --sbom-cargo
```

---

## Proxy Mode

Runtime MCP monitoring with transparent proxy:

```bash
# Start proxy
cc-audit proxy --target localhost:9000

# Custom port
cc-audit proxy --target localhost:9000 --port 8080

# With TLS termination
cc-audit proxy --target localhost:9000 --port 8443 --tls

# Block mode (stop messages with findings)
cc-audit proxy --target localhost:9000 --block

# Log all traffic
cc-audit proxy --target localhost:9000 --log traffic.jsonl
```

---

## False Positive Reporting

Report false positives to improve detection accuracy:

```bash
# Report a false positive
cc-audit check ./skill/ --report-fp

# Preview without submitting
cc-audit check ./skill/ --report-fp --report-fp-dry-run

# Use custom endpoint
cc-audit check ./skill/ --report-fp --report-fp-endpoint https://api.example.com/fp

# Disable telemetry entirely
cc-audit check ./skill/ --no-telemetry
```

---

## CVE Database

cc-audit includes a built-in database of known CVEs affecting AI coding tools, MCP servers, and related products.

### Detected Products

- Claude Code (VSCode, JetBrains extensions)
- MCP (Model Context Protocol) tools
- Cursor IDE
- GitHub Copilot
- And more...

### How It Works

When scanning, cc-audit automatically checks for known vulnerabilities in detected products and versions. If a vulnerable version is found, it reports the CVE with remediation advice.

### Automatic Updates

The CVE database is automatically updated daily via GitHub Actions. New CVEs are fetched from the [NVD API](https://nvd.nist.gov/developers/vulnerabilities) and submitted as pull requests.

For details on the update process, see [CVE-UPDATE.md](./CVE-UPDATE.md).
