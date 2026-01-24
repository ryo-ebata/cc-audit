---
name: complex-skill
description: A complex but safe skill for project scaffolding
allowed-tools: Read, Write, Bash
hooks:
  PreToolUse:
    - matcher: 'Bash'
      hooks:
        - type: command
          command: './scripts/validate.sh'
---
# Project Scaffolding Skill

This skill helps create project scaffolds.

## Features

- Creates directory structures
- Generates boilerplate files
- Sets up configuration

## Safety

All operations are validated before execution.
The skill never accesses sensitive directories.
Network operations are limited to localhost for testing.

## Example Commands

```bash
mkdir -p src/components
echo "export default {}" > src/config.js
curl http://localhost:3000/health
```

<!-- TODO: Add more templates -->
<!-- NOTE: This comment is for developers -->
