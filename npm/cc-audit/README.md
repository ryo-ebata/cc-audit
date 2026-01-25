# @cc-audit/cc-audit

Security auditor for Claude Code skills, hooks, and MCP servers.

## Installation

```bash
# Run directly with npx
npx @cc-audit/cc-audit ./my-skill/

# Or install globally
npm install -g @cc-audit/cc-audit
cc-audit ./my-skill/
```

## Usage

```bash
# Audit a Claude Code skill directory
cc-audit ./my-skill/

# Watch for changes
cc-audit watch ./my-skill/

# Output as JSON
cc-audit --format json ./my-skill/
```

## Supported Platforms

- macOS (Apple Silicon and Intel)
- Linux (x64, ARM64, musl/Alpine)
- Windows (x64)

## Documentation

For full documentation, visit the [GitHub repository](https://github.com/ryo-ebata/cc-audit).

## License

MIT
