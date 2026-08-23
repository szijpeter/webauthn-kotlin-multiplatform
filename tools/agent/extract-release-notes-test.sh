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

printf '%s\n' 'preserve-existing-output' > "$actual"
if bash "$ROOT_DIR/tools/agent/extract-release-notes.sh" 9.9.9 "$fixture" "$actual" 2>/dev/null; then
    echo "Missing release sections must fail extraction." >&2
    exit 1
fi
printf '%s\n' 'preserve-existing-output' | cmp - "$actual"

fixture_before="$tmp_dir/CHANGELOG.before.md"
cp "$fixture" "$fixture_before"
if bash "$ROOT_DIR/tools/agent/extract-release-notes.sh" 1.2.0 "$fixture" "$fixture" 2>/dev/null; then
    echo "In-place extraction must be rejected." >&2
    exit 1
fi
cmp "$fixture_before" "$fixture"

hard_link="$tmp_dir/CHANGELOG.hard-link.md"
ln "$fixture" "$hard_link"
if bash "$ROOT_DIR/tools/agent/extract-release-notes.sh" 1.2.0 "$fixture" "$hard_link" 2>/dev/null; then
    echo "Hard-linked output must be rejected." >&2
    exit 1
fi
cmp "$fixture_before" "$fixture"

symbolic_link="$tmp_dir/CHANGELOG.symbolic-link.md"
ln -s "$fixture" "$symbolic_link"
if bash "$ROOT_DIR/tools/agent/extract-release-notes.sh" 1.2.0 "$fixture" "$symbolic_link" 2>/dev/null; then
    echo "Symbolic-linked output must be rejected." >&2
    exit 1
fi
cmp "$fixture_before" "$fixture"

if bash "$ROOT_DIR/tools/agent/extract-release-notes.sh" 1.2.0 "$fixture" "$tmp_dir" 2>/dev/null; then
    echo "Directory output must be rejected." >&2
    exit 1
fi

echo "Release notes extraction: PASS"
