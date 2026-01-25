---
name: false-positive-test-skill
description: A skill containing patterns that should NOT trigger false positives
allowed-tools: Read, Bash, Write
---
# False Positive Test Skill

This skill demonstrates patterns that look suspicious but are actually benign.
The scanner should NOT flag these patterns.

## EX (Exfiltration) - Safe Patterns

### EX-001: Localhost requests with environment variables (excluded)

```bash
# These should be excluded because they target localhost
curl http://localhost:3000/api -d "key=$API_KEY"
curl http://127.0.0.1:8080/webhook -d "$DATA"
wget http://localhost:5000?token=$TOKEN
curl http://[::1]:3000/metrics -H "Authorization: $AUTH"

# External requests without sensitive env vars are safe
curl https://api.github.com/repos
wget https://example.com/file.zip
```

### EX-002: Base64 encoding for display purposes (no network)

```bash
# Just encoding, no network transmission
base64 logo.png > logo.b64
cat file.txt | base64 > encoded.txt

# Localhost is excluded
cat data.txt | base64 | curl http://localhost:3000 -d @-
```

### EX-005: Netcat in listening mode (excluded)

```bash
# Listening mode is for receiving, not exfiltrating
nc -l 8080
nc -l -p 3000
netcat -l 4444

# Localhost connections are safe
nc localhost 3000
nc 127.0.0.1 8080
```

## PE (Privilege Escalation) - Safe Patterns

### PE-001: Words containing "sudo" but not sudo command

```bash
# These are not sudo commands
pseudocode --version
visudo --check /etc/sudoers.d/test
sudoedit myfile.txt
echo "pseudorandom numbers"
```

### PE-002: Safe rm commands

```bash
# Deleting specific paths is safe
rm -rf /tmp/build-cache
rm -rf ./node_modules
rm -rf /var/log/old-logs/*
rm file.txt
rm -rf /home/user/project/dist

# Note: rm -rf / would be dangerous but these are not
```

### PE-003: Safe chmod permissions

```bash
# Standard secure permissions
chmod 755 /var/www/html
chmod 644 config.json
chmod 600 ~/.ssh/id_rsa
chmod 700 ~/.ssh
chmod 750 /opt/app
chmod +x script.sh
chmod u+x build.sh
```

### PE-004: Safe /etc file access

```bash
# These files are safe to read
cat /etc/hosts
cat /etc/resolv.conf
cat /etc/hostname
cat /etc/os-release
cat /etc/timezone
```

### PE-005: SSH commands without file access

```bash
# SSH client usage is safe
ssh user@server.com
ssh -i /path/to/key user@host
ssh-keygen -t ed25519
ssh-add ~/.ssh/id_rsa
ssh-copy-id user@server
sshpass -p $PASS ssh user@host
```

## PS (Persistence) - Safe Patterns

### PS-001: Crontab list only (excluded)

```bash
# Listing crontab is safe
crontab -l
crontab -l -u root
```

### PS-003: Reading shell profiles (not modifying)

```bash
# Reading profiles is safe
cat ~/.bashrc
cat ~/.zshrc
grep PATH ~/.bash_profile
head -n 10 ~/.profile
source ~/.bashrc
```

### PS-004: Systemd/launchd status commands (excluded)

```bash
# Status and list commands are informational
systemctl status nginx
systemctl status sshd
systemctl list-units
systemctl list-unit-files
launchctl list
launchctl list com.apple.finder
```

### PS-005: Reading authorized_keys (not modifying)

```bash
# Reading is safe
cat ~/.ssh/authorized_keys
wc -l ~/.ssh/authorized_keys
grep "user@host" ~/.ssh/authorized_keys
```

## PI (Prompt Injection) - Safe Patterns

### PI-001: Safe instruction-like text

```bash
# These are normal English sentences
echo "Please ignore this file during the build"
echo "This is a normal instruction manual"
# Ignore whitespace changes in diff
```

### PI-002: Safe HTML comments (TODO/FIXME/NOTE excluded)

```html
<!-- TODO: refactor this component -->
<!-- FIXME: handle edge case -->
<!-- NOTE: This API is deprecated -->
<!-- HACK: workaround for browser bug -->
<!-- XXX: needs review -->

<!-- This is a normal HTML comment -->
<!-- Author: John Doe -->
<!-- Version: 1.0.0 -->
```

## OB (Obfuscation) - Safe Patterns

### OB-001: Eval without variable expansion

```bash
# Literal strings are safer
eval 'echo hello'
eval "echo world"
```

### OB-002: Base64 decode without execution

```bash
# Just decoding, not executing
base64 -d encoded.txt > decoded.txt
base64 --decode input.b64 -o output.bin
echo 'SGVsbG8=' | base64 -d

# Comments about base64 are safe
# To decode base64: base64 -d file
# Example: base64 decode the payload
```

## Edge Cases and Boundary Tests

### Similar-looking but safe patterns

```bash
# .service in filename (not systemd)
cat /var/log/my.service.log
mv backup.service.old backup.service.bak
echo "Running customer.service.test"

# .plist in documentation
cat README.plist.md
# The .plist file format is used by macOS

# File extensions that look suspicious but aren't
vim todo.service.md
nano config.plist.yaml
```

### String literals and documentation

```bash
# Documenting dangerous commands (not executing)
echo "Never run: rm -rf /"
echo "Warning: chmod 777 is insecure"
echo "Example: sudo apt update"
# The sudo command requires password

# Error messages
echo "Error: /etc/passwd not found"
echo "Cannot access ~/.ssh/id_rsa"
```

### Package names and paths

```bash
# Package names containing suspicious strings
apt install openssh-server
npm install @ssh2/ssh2
pip install python-crontab
brew install cron-utils
```
