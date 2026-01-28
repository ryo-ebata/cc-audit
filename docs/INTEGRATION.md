# CI/CD Integration

[日本語](./INTEGRATION.ja.md)

## GitHub Actions

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
        run: cc-audit check --type skill --ci --format sarif .claude/skills/ > skills.sarif
        continue-on-error: true

      - name: Scan MCP Configuration
        run: cc-audit check --type mcp --ci mcp.json
        continue-on-error: true

      - name: Scan Dependencies
        run: cc-audit check --type dependency --ci ./

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: skills.sarif
        if: always()
```

## GitLab CI

```yaml
cc-audit:
  stage: security
  image: rust:latest
  before_script:
    - cargo install cc-audit
  script:
    - cc-audit check --type skill --ci .claude/
    - cc-audit check --type mcp --ci mcp.json
    - cc-audit check --type dependency --ci ./
  allow_failure: false
```

## Pre-commit Hook

```bash
# Install hook in your project
cc-audit hook init

# Remove hook
cc-audit hook remove
```

The pre-commit hook automatically scans staged files before each commit.

---

# Troubleshooting

## Common Issues

### "No files found to scan"

```bash
# Check if the path exists and contains scannable files
ls -la ./my-skill/

# Recursive scan is enabled by default. Use --no-recursive to disable
cc-audit check ./my-skill/
cc-audit check --no-recursive ./my-skill/
```

### "Permission denied"

```bash
# Ensure read permissions on target files
chmod -R +r ./my-skill/
```

### High false positive rate

```bash
# Increase minimum confidence level
cc-audit check --min-confidence firm ./my-skill/

# Or use certain for highest precision
cc-audit check --min-confidence certain ./my-skill/

# Skip comment lines
cc-audit check --skip-comments ./my-skill/
```

### Scan is too slow

```bash
# Common directories (node_modules, .git, etc.) are excluded by default patterns
# Configure ignore patterns in .cc-audit.yaml

# Example: add custom ignore patterns
# ignore:
#   patterns:
#     - "/large_directory/"
#     - "\\.generated\\."
```

### Custom rules not loading

```bash
# Validate YAML syntax
cat ./my-rules.yaml | python -c "import yaml, sys; yaml.safe_load(sys.stdin)"

# Required fields: id, name, severity, category, patterns, message, recommendation
```

---

# FAQ

**Q: Does cc-audit send any data externally?**

A: By default, no. Scan results stay local. However, some optional features require network access:
- `--remote` / `--awesome-claude-code`: Clones repositories via git
- `--report-fp`: Submits false positive reports (use `--no-telemetry` to disable)

**Q: Can I use cc-audit in air-gapped environments?**

A: Yes, for local scanning. Clone repositories manually first, then scan locally. The `--remote` feature is not available in air-gapped environments.

**Q: How do I suppress specific rules?**

A: Add rule IDs to `disabled_rules` in `.cc-audit.yaml`:

```yaml
disabled_rules:
  - "PE-001"
  - "EX-002"
```

**Q: Does cc-audit scan binary files?**

A: No. Only text-based files (scripts, configs, markdown, JSON, YAML, etc.).

**Q: Can I scan remote repositories directly?**

A: Yes! Use `--remote <URL>` to scan a single repository, `--remote-list <FILE>` for multiple repositories, or `--awesome-claude-code` to scan all awesome-claude-code repositories. See [Remote Repository Scanning](./FEATURES.md#remote-repository-scanning) for details.

**Q: What's the difference between `--strict` and default mode?**

A: Default mode only reports critical and high severity. `--strict` includes medium and low.

**Q: How often is the malware signature database updated?**

A: With each release. Supplement with `--malware-db` for custom signatures.

**Q: Can I contribute new detection rules?**

A: Yes! See [Contributing Guide](../CONTRIBUTING.md).
