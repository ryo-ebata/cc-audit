# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| < 0.2   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities in cc-audit seriously. If you discover a security issue, please report it responsibly.

### How to Report

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. Send an email to: security@example.com (replace with actual contact)
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Timeline**: Depends on severity
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: 90 days

### Disclosure Policy

- We follow responsible disclosure practices
- Security issues will be fixed before public disclosure
- Credit will be given to reporters (unless anonymity is requested)

## Security Considerations for Users

### Safe Usage

cc-audit is designed to analyze potentially malicious code. When using this tool:

1. **Isolated Environment**: Run in a sandboxed or isolated environment when scanning untrusted code
2. **Review Results**: Carefully review all findings before taking action
3. **Keep Updated**: Always use the latest version for the most up-to-date detection rules

### Known Limitations

- Static analysis cannot detect all malicious patterns
- False positives are possible; always verify findings
- Dynamic or obfuscated malware may evade detection

## Security Features

cc-audit includes several security-focused features:

- **No Code Execution**: Pure static analysis without executing scanned code
- **Sandboxed Parsing**: Safe parsing of configuration files
- **Input Validation**: Strict validation of all inputs
- **Minimal Dependencies**: Reduced attack surface through careful dependency management

## Dependency Security

We regularly audit dependencies for known vulnerabilities:

```bash
cargo audit
```

All dependencies are:
- Pinned to specific versions in Cargo.lock
- Regularly updated to address security issues
- Reviewed before inclusion
