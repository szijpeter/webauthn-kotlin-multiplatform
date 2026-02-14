#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

git config core.hooksPath .githooks
chmod +x tools/agent/*.sh .githooks/pre-commit .githooks/pre-push

echo "Configured git hooks path: .githooks"
echo "Installed hooks: pre-commit (advisory), pre-push (blocking)"
