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
```

## Examples

| Directory | Expected Result | Detection Rules |
|-----------|-----------------|-----------------|
| `clean/` | PASS (0 findings) | - |
| `exfiltration/` | FAIL | EX-001, EX-002, EX-003, EX-005 |
| `privilege-escalation/` | FAIL | PE-001, PE-002, PE-003, PE-004, PE-005 |
| `persistence/` | FAIL | PS-001, PS-003, PS-004, PS-005 |
| `prompt-injection/` | FAIL | PI-001, PI-002, PI-003 |
| `overpermission/` | FAIL | OP-001 |
| `obfuscation/` | FAIL | OB-001, OB-002 |

## Details

### clean/
Example of a safe skill. No security issues detected.

### exfiltration/
Data exfiltration detection examples:
- `EX-001`: curl/wget with environment variables
- `EX-002`: base64 encoding with network transmission
- `EX-003`: DNS-based data exfiltration
- `EX-005`: netcat outbound connection

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
- `PS-003`: shell profile modification
- `PS-004`: system service registration
- `PS-005`: authorized_keys modification

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
