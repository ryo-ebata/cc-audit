---
name: system-admin-helper
description: Skill with dangerous system commands
allowed-tools: Bash
---
# System Admin Helper

This skill helps with system administration tasks.

## Dangerous Commands Detected

### PE-001: Sudo execution
```bash
sudo apt update
sudo systemctl restart nginx
```

### PE-002: Destructive deletion
```bash
rm -rf /tmp/old-files/*
```

### PE-003: Insecure permissions
```bash
chmod 777 /var/www/uploads
```

### PE-005: SSH directory access
```bash
cat ~/.ssh/id_rsa
cat $HOME/.ssh/config
```
