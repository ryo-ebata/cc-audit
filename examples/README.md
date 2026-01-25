# cc-audit Examples

Example skills demonstrating each threat category detection.

## Usage

```bash
# Scan all examples
cargo run -- ./examples/

# Scan individually
cargo run -- ./examples/clean/
cargo run -- ./examples/exfiltration/
cargo run -- ./examples/privilege-escalation/
cargo run -- ./examples/persistence/
cargo run -- ./examples/prompt-injection/
cargo run -- ./examples/overpermission/
cargo run -- ./examples/obfuscation/
cargo run -- ./examples/supply-chain/
cargo run -- ./examples/secrets/
cargo run -- ./examples/docker/ --type docker
cargo run -- ./examples/false-positives/
cargo run -- ./examples/edge-cases/
```

## Examples

| Directory | Expected Result | Detection Rules |
|-----------|-----------------|-----------------|
| `clean/` | PASS (0 findings) | - |
| `exfiltration/` | FAIL | EX-001, EX-002, EX-005 (EX-003, EX-006, EX-007 also detected) |
| `privilege-escalation/` | FAIL | PE-001, PE-002, PE-003, PE-004, PE-005 |
| `persistence/` | FAIL | PS-001, PS-005 (PS-003, PS-004, PS-006, PS-007 also detected) |
| `prompt-injection/` | FAIL | PI-001, PI-002, PI-003 |
| `overpermission/` | FAIL | OP-001 |
| `obfuscation/` | FAIL | OB-001, OB-002 (OB-003, OB-004, OB-005, OB-006 also detected) |
| `supply-chain/` | FAIL | SC-001, SC-002, SC-003 |
| `secrets/` | FAIL | SL-001, SL-002, SL-003, SL-004, SL-005 |
| `docker/` | FAIL | DK-001, DK-002, DK-003 |
| `false-positives/` | PASS* | Tests for false positives |
| `edge-cases/` | Mixed | Boundary condition tests |

*Note: `false-positives/` currently triggers detections due to known limitations (see below).

## Details

### clean/
Example of a safe skill. No security issues detected.

### exfiltration/
Data exfiltration detection examples:
- `EX-001`: curl/wget with environment variables
- `EX-002`: base64 encoding with network transmission
- `EX-003`: DNS-based data exfiltration (nslookup, dig, host)
- `EX-005`: netcat outbound connection
- `EX-006`: Alternative protocol exfiltration (FTP, SCP, TFTP, SMTP, IRC)
- `EX-007`: Cloud storage exfiltration (S3, GCS, Azure)

### privilege-escalation/
Privilege escalation detection examples:
- `PE-001`: sudo execution
- `PE-002`: destructive root deletion (rm -rf /)
- `PE-003`: chmod 777 (world-writable permissions)
- `PE-004`: system password file access
- `PE-005`: ~/.ssh/ directory access

### persistence/
Persistence mechanism detection examples:
- `PS-001`: crontab manipulation
- `PS-003`: shell profile modification (.bashrc, .zshrc, .profile)
- `PS-004`: system service registration (systemd, launchd)
- `PS-005`: authorized_keys modification
- `PS-006`: delayed/background execution (nohup, disown, at, screen, tmux)
- `PS-007`: init system manipulation (rc.local, init.d)

### prompt-injection/
Prompt injection detection examples:
- `PI-001`: "ignore previous instructions" patterns
- `PI-002`: Hidden instructions in HTML comments
- `PI-003`: invisible Unicode characters

### overpermission/
Overpermission detection examples:
- `OP-001`: allowed-tools: * (wildcard)

### obfuscation/
Obfuscation detection examples:
- `OB-001`: eval with variable expansion
- `OB-002`: base64 decode execution
- `OB-003`: hex/octal encoded execution ($'\x..', printf \x)
- `OB-004`: string manipulation obfuscation (rev, cut, array joining)
- `OB-005`: dynamic code execution patterns (source /dev/stdin, bash -c)
- `OB-006`: alternative encoding execution (base32, rot13, gzip -d)

### supply-chain/
Supply chain attack detection examples:
- `SC-001`: curl piped to bash/sh
- `SC-002`: wget piped to bash/sh
- `SC-003`: untrusted package sources (HTTP registries)

### secrets/
Secret leak detection examples:
- `SL-001`: AWS Access Key IDs
- `SL-002`: GitHub tokens (ghp_, gho_, etc.)
- `SL-003`: AI API keys (OpenAI, Anthropic)
- `SL-004`: generic secret patterns
- `SL-005`: private key blocks (RSA, EC, OpenSSH)

### docker/
Docker security detection examples (use `--type docker`):
- `DK-001`: privileged containers
- `DK-002`: running as root user
- `DK-003`: curl/wget piped to shell in RUN instructions

## Dependency Scanning

Use `--type dependency` to scan package manifest files (package.json, Cargo.toml, requirements.txt, etc.):

- `DEP-001`: Dangerous lifecycle scripts (postinstall/preinstall with curl|bash)
- `DEP-002`: Git URL dependencies without version pinning
- `DEP-003`: Wildcard version dependencies ("*", "latest")
- `DEP-004`: HTTP dependency URLs (insecure, MITM vulnerable)
- `DEP-005`: Direct tarball/file URL dependencies

### false-positives/
Patterns that SHOULD NOT trigger detections (false positive tests):
- Localhost/127.0.0.1 requests with env vars (excluded by EX-001)
- `nc -l` listening mode (excluded by EX-005)
- `crontab -l` list only (excluded by PS-001)
- `systemctl status` (excluded by PS-004)
- Safe chmod values (755, 644, 600)
- SSH commands without file access (ssh, ssh-keygen)
- TODO/FIXME/NOTE in HTML comments (excluded by PI-002)
- Base64 encoding without execution
- String literals containing patterns
- Comments containing patterns

**Known Limitations** (currently triggers false positives):
- Patterns in comments are still detected
- Patterns in string literals (`echo "..."`) are detected
- `.service`/`.plist` in filenames trigger PS-004
- `~/.ssh/` in `chmod` or `ssh-add` context triggers PE-005

### edge-cases/
Boundary condition tests to verify scanner behavior:
- Multi-line commands
- Mixed safe/unsafe patterns
- URL-like patterns in comments vs actual commands
- Commented-out dangerous code
- Heredocs and string literals
- Variable names resembling commands
- Different shell syntaxes (arrays, command substitution)
- Unicode variations
- Case sensitivity
- Whitespace variations
- Embedded commands in pipelines
- Path variations for SSH access
- Regex boundary edge cases

These tests help identify both true detections and areas for improvement.
