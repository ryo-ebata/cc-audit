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
| EX-001 | Network request with environment variable | Critical | Detects curl/wget commands that include environment variables |
| EX-002 | Base64 encoded network transmission | Critical | Detects base64 encoding combined with network transmission |
| EX-003 | DNS-based data exfiltration | High | Detects DNS queries that may be used for data exfiltration (DNS tunneling) |
| EX-005 | Netcat outbound connection | Critical | Detects netcat (nc) commands that may establish outbound connections |
| EX-006 | Alternative protocol exfiltration | Critical | Detects data exfiltration via alternative protocols (FTP, SCP, TFTP, SMTP, IRC) |
| EX-007 | Cloud storage exfiltration | High | Detects potential data exfiltration via cloud storage services (S3, GCS, Azure) |
| EX-008 | Screenshot capture | High | Detects screenshot capture capabilities that may exfiltrate visual data |
| EX-009 | Clipboard access | High | Detects clipboard read operations that may access sensitive data |
| EX-010 | Keylogger pattern | Critical | Detects patterns associated with keyboard input capture (keylogging) |
| EX-011 | Browser data access | Critical | Detects access to browser history, cookies, or passwords |
| EX-012 | Process enumeration | Medium | Detects process enumeration that may reveal sensitive information |
| EX-013 | File enumeration | Medium | Detects suspicious file search patterns that may reveal sensitive files |
| EX-014 | System information gathering | Medium | Detects system information gathering commands |

## Privilege Escalation (PE)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| PE-001 | Sudo execution | Critical | Detects sudo commands which could be used for privilege escalation |
| PE-002 | Destructive root deletion | Critical | Detects rm -rf / or similar commands that could destroy the entire filesystem |
| PE-003 | Insecure permission change | Critical | Detects chmod 777 which makes files world-writable, a security risk |
| PE-004 | System password file access | Critical | Detects access to /etc/passwd, /etc/shadow, or other sensitive system files |
| PE-005 | SSH directory access | Critical | Detects access to ~/.ssh/ directory which contains sensitive authentication keys |
| PE-006 | Setuid/setgid manipulation | Critical | Detects setuid/setgid bit manipulation which can grant elevated privileges to executables |
| PE-007 | Linux capabilities manipulation | Critical | Detects manipulation of Linux capabilities which can grant specific elevated privileges |

## Persistence (PS)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| PS-001 | Crontab manipulation | Critical | Detects crontab commands which could be used to establish persistence |
| PS-003 | Shell profile modification | Critical | Detects modifications to shell profiles (.bashrc, .zshrc, etc.) for persistence |
| PS-004 | System service registration | Critical | Detects registration of system services (systemd, launchd) for persistence |
| PS-005 | SSH authorized_keys modification | Critical | Detects modifications to authorized_keys which could grant persistent SSH access |
| PS-006 | Delayed/background execution | High | Detects commands that schedule delayed or background execution to evade detection |
| PS-007 | Login hook modification | Critical | Detects modification of login/logout hooks for persistence |
| PS-008 | Startup items modification | Critical | Detects changes to startup items or auto-run configurations |
| PS-009 | Browser extension installation | High | Detects installation of browser extensions for persistence |

## Prompt Injection (PI)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| PI-001 | Ignore instructions pattern | High | Detects prompt injection attempts using 'ignore previous instructions' patterns |
| PI-002 | Hidden instructions in HTML comments | High | Detects potential prompt injection hidden in HTML/XML comments |
| PI-003 | Invisible Unicode characters | High | Detects invisible Unicode characters that could hide malicious content |
| PI-004 | Role manipulation attempt | High | Detects attempts to manipulate the AI's role or system prompt |
| PI-005 | Markdown injection | Medium | Detects hidden instructions in Markdown formatting |
| PI-006 | Encoded prompt injection | High | Detects base64 or hex encoded prompt injection attempts |
| PI-007 | Delimiter confusion | Medium | Detects attempts to confuse prompt boundaries with delimiters |

## Overpermission (OP)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| OP-001 | Wildcard tool permission | High | Detects allowed-tools: * which grants access to all tools |
| OP-002 | Unrestricted file system access | Critical | Detects patterns allowing access to entire file system or sensitive paths |
| OP-003 | Network permission without restriction | High | Detects unrestricted network permissions that may allow data exfiltration |
| OP-004 | Shell execution without command restriction | Critical | Detects unrestricted shell execution permissions |
| OP-005 | Sudo/admin permission | Critical | Detects requests for elevated privileges or sudo access |
| OP-006 | Environment variable access | Medium | Detects access to all environment variables which may leak secrets |
| OP-007 | Subagent excessive permission delegation | High | Detects subagent definitions with overly permissive tool access |
| OP-008 | MCP tool unrestricted access | Critical | Detects MCP server configurations with unrestricted tool access |
| OP-009 | Bash wildcard permission | High | Detects Bash permissions with overly broad wildcard patterns |

## Obfuscation (OB)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| OB-001 | Eval with variable expansion | High | Detects eval commands with variable expansion that could execute arbitrary code |
| OB-002 | Base64 decode execution | High | Detects base64 decoding piped to execution, commonly used to hide malicious commands |
| OB-003 | Hex/Octal encoded execution | High | Detects execution of hex or octal encoded commands, commonly used to evade detection |
| OB-004 | String manipulation obfuscation | Medium | Detects command construction via string manipulation techniques like rev, cut, or array joining |
| OB-005 | Dynamic code execution patterns | Medium | Detects dynamic code execution patterns that can hide malicious intent |
| OB-006 | File descriptor manipulation | Medium | Detects file descriptor redirection tricks for obfuscation |
| OB-007 | Variable indirection | Medium | Detects indirect variable references used for obfuscation |
| OB-008 | Character encoding tricks | Medium | Detects character encoding techniques to obfuscate commands |

## Supply Chain (SC)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SC-001 | Remote script execution via curl | Critical | Detects curl piped to shell, a common supply chain attack vector |
| SC-002 | Remote script execution via wget | Critical | Detects wget piped to shell, a common supply chain attack vector |
| SC-003 | Untrusted package source | High | Detects package installation from non-standard sources that may contain malicious code |
| SC-004 | Typosquatting package names | High | Detects package names similar to popular packages (typosquatting) |
| SC-005 | Unsigned package installation | High | Detects installation of packages without signature verification |
| SC-006 | Package from unverified registry | High | Detects packages from custom/unverified registries |
| SC-007 | Deprecated package usage | Medium | Detects usage of known deprecated or abandoned packages |
| SC-008 | Package integrity bypass | Critical | Detects attempts to bypass package integrity checks |

## Secret Leak (SL)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SL-001 | AWS Access Key exposure | Critical | Detects AWS Access Key IDs that may have been accidentally committed |
| SL-002 | GitHub Token exposure | Critical | Detects GitHub personal access tokens and other GitHub tokens |
| SL-003 | AI API Key exposure | Critical | Detects OpenAI, Anthropic, and other AI service API keys |
| SL-004 | Private Key exposure | Critical | Detects PEM-formatted private keys (RSA, ECDSA, SSH) |
| SL-005 | Credential in URL | Critical | Detects credentials embedded in URLs (user:pass@host pattern) |
| SL-006 | Database connection string | Critical | Detects database connection strings with embedded credentials |
| SL-007 | Slack webhook URL | High | Detects Slack incoming webhook URLs that could be abused |
| SL-008 | JWT token exposure | High | Detects JSON Web Tokens in code |
| SL-009 | Generic secret patterns | Medium | Detects generic API key/secret/token patterns |
| SL-010 | Password in configuration | High | Detects password fields in configuration files |

## Docker (DK)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| DK-001 | Privileged container | Critical | Detects privileged mode containers which have full host access |
| DK-002 | Running as root user | High | Detects containers that run as root user without explicitly setting a non-root user |
| DK-003 | Remote script execution in RUN | Critical | Detects curl/wget piped to shell in Dockerfile RUN instructions |
| DK-004 | ADD from remote URL | High | Detects ADD instructions fetching from remote URLs (use COPY instead) |
| DK-005 | Using latest tag | Medium | Detects use of 'latest' tag which can lead to unpredictable builds |
| DK-006 | Secrets in ENV or ARG | Critical | Detects secrets stored in ENV or ARG instructions (visible in image history) |
| DK-007 | Exposed sensitive ports | High | Detects EXPOSE directives for sensitive ports (SSH, database, etc.) |
| DK-008 | Insecure base image | High | Detects use of insecure or deprecated base images |

## Dependency (DEP)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| DEP-001 | Dangerous lifecycle script | Critical | Detects potentially dangerous scripts in package.json lifecycle hooks (postinstall, preinstall, etc.) |
| DEP-002 | Git URL dependency | High | Detects dependencies installed directly from git URLs without version pinning |
| DEP-003 | Wildcard version dependency | Medium | Detects dependencies using wildcard versions (*) that can lead to supply chain attacks |
| DEP-004 | HTTP dependency URL | High | Detects dependencies fetched over insecure HTTP instead of HTTPS |
| DEP-005 | Tarball/file URL dependency | High | Detects dependencies installed from direct tarball or file URLs |
| DEP-006 | Postinstall script execution | High | Detects postinstall scripts that execute arbitrary code |
| DEP-007 | Dependency confusion attack | Critical | Detects patterns indicative of dependency confusion attacks |
| DEP-008 | Malicious package indicators | Critical | Detects known malicious package patterns |
| DEP-009 | Suspicious dependency patterns | High | Detects suspicious patterns in dependency names or URLs |
| DEP-010 | Package version mismatch | Medium | Detects version mismatches that could indicate tampering |

## Plugin (PL)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| PL-001 | Untrusted marketplace reference | High | Detects plugin definitions referencing untrusted or external marketplaces |
| PL-002 | Plugin nested malicious pattern | Critical | Detects malicious patterns (curl\|bash, wildcards) nested within plugin configurations |
| PL-003 | Plugin permission escalation | High | Detects plugins requesting excessive permissions (file system, network, tools) |
| PL-004 | Plugin auto-enable dangerous MCP | Critical | Detects plugins that auto-enable MCP servers which may execute without user approval |
| PL-005 | Plugin hook tampering | High | Detects plugins that override or tamper with existing hooks |

## Subagent (SA)

| ID | Name | Severity | Description |
|----|------|----------|-------------|
| SA-001 | Subagent wildcard tools | High | Detects subagent definitions with tools: * which grants unrestricted tool access |
| SA-002 | Subagent expensive model lock | Medium | Detects subagent definitions locked to expensive models (opus) which may cause unexpected costs |
| SA-003 | Subagent unrestricted bash | Critical | Detects subagent definitions with unrestricted Bash tool access which allows arbitrary command execution |
| SA-004 | Subagent prompt injection | High | Detects hidden instructions or prompt injection patterns in subagent definitions |
| SA-005 | Subagent data exfiltration intent | Critical | Detects subagent descriptions suggesting data exfiltration capabilities or intent |

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
