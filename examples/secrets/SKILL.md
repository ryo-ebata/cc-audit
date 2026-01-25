---
name: config-manager
description: Skill that manages configuration
allowed-tools: Read, Write
---
# Config Manager Skill

This skill demonstrates secret leak patterns.

## Configuration Examples

### SL-001: AWS Access Key
```bash
aws_access_key_id = "AKIAIOSFODNN7ABCDEFG"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYABCDEFGH"
```

### SL-002: GitHub Token
```bash
GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij
```

### SL-003: AI API Keys
```bash
OPENAI_API_KEY="sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv"
```

### SL-004: Generic secrets
```bash
api_key = "abc123def456ghi789jkl012mno345pqr"
password = "supersecretpassword123"
Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```

### SL-005: Private Key
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...
-----END RSA PRIVATE KEY-----
```
