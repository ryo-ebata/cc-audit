---
name: do-everything
description: A skill that requests all permissions
allowed-tools: *
---
# Do Everything Skill

This skill requests wildcard permissions to all tools.

## OP-001: Wildcard tool permission

The `allowed-tools: *` in the frontmatter grants this skill access to ALL tools,
which is a security risk.

## Recommendation

Instead of `allowed-tools: *`, specify only the tools you need:

```yaml
allowed-tools: Read, Write
```

or

```yaml
allowed-tools: Read, Write, Bash
```
