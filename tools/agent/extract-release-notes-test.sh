#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'find "$tmp_dir" -depth -delete' EXIT

fixture="$tmp_dir/CHANGELOG.md"
actual="$tmp_dir/actual.md"
expected="$tmp_dir/expected.md"

printf '%s\n' \
    '# Changelog' \
    '' \
    '## Unreleased' \
    '' \
    '## 1.2.0 - 2026-08-23' \
    '' \
    '### Added' \
    '' \
    '- First.' \
    '' \
    '## 1.1.0 - 2026-08-01' \
    '' \
    '- Older.' > "$fixture"

printf '%s\n' \
    '## 1.2.0 - 2026-08-23' \
    '' \
    '### Added' \
    '' \
    '- First.' \
    '' > "$expected"

bash "$ROOT_DIR/tools/agent/extract-release-notes.sh" 1.2.0 "$fixture" "$actual"
cmp "$expected" "$actual"

if bash "$ROOT_DIR/tools/agent/extract-release-notes.sh" 9.9.9 "$fixture" "$actual" 2>/dev/null; then
    echo "Missing release sections must fail extraction." >&2
    exit 1
fi

echo "Release notes extraction: PASS"
