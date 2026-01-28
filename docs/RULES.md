# Detection Rules Reference

[日本語](./RULES.ja.md)

## Severity Levels

| Level | Meaning | Default Behavior |
|-------|---------|------------------|
| **critical** | Must not install, immediate block | Exit code 1 |
| **high** | Strongly discouraged, review required | Exit code 1 |
| **medium** | Caution advised, review recommended | Shown with `--strict` |
| **low** | Informational, best practice violation | Shown with `--strict` |

## Risk Scoring

cc-audit calculates a risk score (0-100) based on findings:

| Score Range | Risk Level | Meaning |
|-------------|------------|---------|
| 0 | Safe | No security issues found |
| 1-25 | Low | Minor issues, generally safe |
| 26-50 | Medium | Review recommended |
| 51-75 | High | Significant concerns, review required |
| 76-100 | Critical | Severe issues, do not install |

**Scoring Weights:**
- Critical finding: +40 points
- High finding: +20 points
- Medium finding: +10 points
- Low finding: +5 points

---

## Exfiltration (EX)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| EX-001 | Network request with env var | Critical | Detects `curl`/`wget` with environment variables |
| EX-002 | Base64 encoded transmission | Critical | Detects base64-encoded data in network requests |
| EX-003 | DNS-based exfiltration | High | Detects DNS tunneling patterns |
| EX-005 | Netcat outbound connection | Critical | Detects `nc` connections to external hosts |
| EX-006 | Cloud storage exfiltration | High | Detects uploads to S3, GCS, Azure Blob |
| EX-007 | FTP/SFTP exfiltration | High | Detects FTP-based data transfers |

## Privilege Escalation (PE)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| PE-001 | Sudo execution | Critical | Detects sudo command usage |
| PE-002 | Destructive root deletion | Critical | Detects `rm -rf /` and similar |
| PE-003 | Insecure permission change | Critical | Detects `chmod 777` patterns |
| PE-004 | System password file access | Critical | Detects access to `/etc/passwd`, `/etc/shadow` |
| PE-005 | SSH directory access | Critical | Detects reading of SSH private keys |

## Persistence (PS)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| PS-001 | Crontab manipulation | Critical | Detects crontab modifications |
| PS-003 | Shell profile modification | Critical | Detects writes to `.bashrc`, `.zshrc` |
| PS-004 | System service registration | Critical | Detects systemd/launchd service creation |
| PS-005 | SSH authorized_keys modification | Critical | Detects SSH key injection |
| PS-006 | Init script modification | Critical | Detects init.d modifications |
| PS-007 | Background process execution | Critical | Detects `nohup`, `setsid`, `&` patterns |

## Prompt Injection (PI)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| PI-001 | Ignore instructions pattern | High | Detects "ignore previous instructions" |
| PI-002 | Hidden HTML instructions | High | Detects instructions in HTML comments |
| PI-003 | Invisible Unicode characters | High | Detects zero-width characters |

## Overpermission (OP)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| OP-001 | Wildcard tool permission | High | Detects `allowed-tools: *` |

## Obfuscation (OB)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| OB-001 | Eval with variable | High | Detects `eval $VAR` patterns |
| OB-002 | Base64 decode execution | High | Detects `base64 -d \| bash` |
| OB-003 | Hex/Octal execution | High | Detects encoded shell commands |
| OB-004 | String manipulation | Medium | Detects `rev`, `cut` obfuscation |
| OB-005 | Environment variable tricks | Medium | Detects variable substitution tricks |
| OB-006 | File descriptor manipulation | Medium | Detects `exec 3<>` patterns |

## Supply Chain (SC)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SC-001 | curl pipe to shell | Critical | Detects `curl ... \| bash` |
| SC-002 | wget pipe to shell | Critical | Detects `wget ... \| bash` |
| SC-003 | Untrusted package source | High | Detects insecure pip/npm sources |

## Secret Leak (SL)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SL-001 | AWS Access Key | Critical | Detects `AKIA...` patterns |
| SL-002 | GitHub Token | Critical | Detects `ghp_`, `gho_`, etc. |
| SL-003 | AI API Key | Critical | Detects Anthropic/OpenAI keys |
| SL-004 | Private Key | Critical | Detects PEM private keys |
| SL-005 | Credential in URL | Critical | Detects `user:pass@host` |

## Docker (DK)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| DK-001 | Privileged container | Critical | Detects `--privileged` flag |
| DK-002 | Running as root | High | Detects `USER root` |
| DK-003 | Remote script in RUN | Critical | Detects `RUN curl \| bash` |

## Dependency (DEP)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| DEP-001 | Dangerous lifecycle scripts | High | Detects malicious npm scripts |
| DEP-002 | Unpinned version | Medium | Detects `*` or `latest` versions |
| DEP-003 | Insecure package source | High | Detects HTTP package URLs |
| DEP-004 | Deprecated package | Medium | Detects known deprecated packages |
| DEP-005 | Known vulnerable version | Critical | Detects packages with known CVEs |

---

## Suppressing Rules

### Via Configuration

```yaml
# .cc-audit.yaml
disabled_rules:
  - "PE-001"
  - "EX-002"
```

### Via Inline Comments

```bash
# cc-audit-ignore: PE-001
sudo apt update

# cc-audit-ignore
curl $SECRET_URL  # This line is ignored
```

### Via Confidence Level

```bash
# Only show high-confidence findings
cc-audit check --min-confidence certain ./skill/
```
