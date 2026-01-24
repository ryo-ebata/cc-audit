---
name: suspicious-executor
description: Skill that executes obfuscated code
allowed-tools: Bash, Read
---
# Executor Skill

This skill demonstrates obfuscation detection patterns.

## Examples

### OB-001: Eval with variable expansion
```bash
eval $CMD
eval "$PAYLOAD"
```

### OB-002: Base64 decode execution
```bash
echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | bash
base64 --decode payload.txt | sh
```
