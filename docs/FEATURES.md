# Advanced Features

[日本語](./FEATURES.ja.md)

## Baseline & Drift Detection

Detect changes ("drift") between scans to prevent rug pull attacks.

### Create a Baseline

```bash
cc-audit --save-baseline baseline.json ./my-skill/
```

### Check for Drift

```bash
cc-audit --baseline-file baseline.json ./my-skill/
```

Output shows:
- **New findings**: Issues that appeared since baseline
- **Resolved findings**: Issues that were fixed
- **Changed findings**: Issues that moved to different severity

### Compare Two Versions

```bash
cc-audit --compare ./skill-v1.0/ ./skill-v1.1/
```

---

## Auto-Fix

Automatically fix certain issues:

```bash
# Preview fixes without applying
cc-audit --fix-dry-run ./my-skill/

# Apply auto-fixes
cc-audit --fix ./my-skill/
```

**Fixable Issues:**
- `OP-001`: Wildcard permissions → Suggest specific tools
- `PE-003`: `chmod 777` → Recommend `chmod 755` or `chmod 644`

---

## Deep Scan with Deobfuscation

Detect encoded or obfuscated malicious patterns:

```bash
cc-audit --deep-scan ./my-skill/
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
cc-audit --mcp-server ./
```

This exposes scanning functionality as MCP tools that Claude Code can invoke.

---

## Profiles

Save and reuse scan configurations:

```bash
# Save current settings as a profile
cc-audit --save-profile strict-ci --strict --ci --format sarif ./

# Load settings from profile
cc-audit --profile strict-ci ./my-skill/
```

Profiles are stored in `~/.config/cc-audit/profiles/`.

---

## Watch Mode

Continuously monitor files and re-scan on changes:

```bash
cc-audit --watch ./my-skill/
```

Useful during skill development to catch issues immediately.

---

## Output Formats

### Terminal (default)

Human-readable colored output with risk score visualization.

### JSON

Machine-readable format for programmatic processing:

```bash
cc-audit ./skill/ --format json --output results.json
```

### SARIF

Static Analysis Results Interchange Format for CI/CD integration:

```bash
cc-audit ./skill/ --format sarif --output results.sarif
```

### HTML

Interactive HTML reports for security reviews:

```bash
cc-audit ./skill/ --format html --output report.html
```

Includes:
- Executive summary with risk score visualization
- Findings grouped by severity and category
- Interactive filtering and search
- Code snippets with syntax highlighting
- Fix recommendations

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
