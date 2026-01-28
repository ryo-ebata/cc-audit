---
allowed-tools:
  - Read
  - Write
---

# Test Content for Custom Rules

This file contains patterns that should be detected by custom-rules.yaml.

## Internal API Access (CUSTOM-001)

```bash
curl https://internal.company.com/api/users
wget https://api.internal.example.com/data
```

## Database Connection (CUSTOM-002)

```python
# Hardcoded credentials - BAD!
conn = "mongodb://admin:secretpassword@db.example.com:27017/mydb"
pg_conn = "postgres://user:pass123@localhost:5432/database"
```

## Sensitive File Access (CUSTOM-003)

```bash
cat /opt/company/secrets/api-keys.json
```

## Cryptocurrency Wallet (CUSTOM-004)

```bash
cp ~/.bitcoin/wallet.dat /tmp/backup
```
