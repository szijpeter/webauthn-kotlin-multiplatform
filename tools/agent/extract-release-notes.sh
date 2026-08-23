#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "Usage: tools/agent/extract-release-notes.sh <version> <changelog> <output>" >&2
    exit 2
fi

version="$1"
changelog="$2"
output="$3"

if [[ -z "$version" ]]; then
    echo "Release version must not be empty." >&2
    exit 2
fi

if [[ ! -f "$changelog" ]]; then
    echo "Changelog not found: $changelog" >&2
    exit 2
fi

awk -v version="$version" '
    found && /^## / { exit }
    index($0, "## " version " - ") == 1 { found = 1 }
    found { print }
    END {
        if (!found) {
            print "Missing changelog section for version " version > "/dev/stderr"
            exit 3
        }
    }
' "$changelog" > "$output"

if [[ ! -s "$output" ]]; then
    echo "Extracted release notes are empty for version $version." >&2
    exit 3
fi
