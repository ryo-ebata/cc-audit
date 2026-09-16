#!/bin/sh
set -eu

profile_value() {
    profile=$1
    key=$2
    awk -v profile="[$profile]" -v key="$key" '
        $0 == profile { in_profile = 1; next }
        /^\[/ { in_profile = 0 }
        in_profile && $0 ~ "^" key "[[:space:]]*=" {
            sub("^[^=]*=[[:space:]]*", "")
            gsub(/[[:space:]]+$/, "")
            print
            found = 1
            exit
        }
        END { if (!found) exit 1 }
    ' Cargo.toml
}

test "$(profile_value profile.dev debug)" = '"line-tables-only"'
test "$(profile_value profile.dev incremental)" = 'false'
test "$(profile_value profile.dev-full inherits)" = '"dev"'
test "$(profile_value profile.dev-full debug)" = 'true'
test "$(profile_value profile.dev-full incremental)" = 'true'

echo "Cargo development profile declarations are configured as expected."
echo "This static check does not validate Cargo's profile interpretation or artifact size."
