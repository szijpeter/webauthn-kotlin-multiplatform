#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

contains_pattern() {
  local pattern="$1"
  local file="$2"
  if command -v rg >/dev/null 2>&1; then
    rg -n -- "$pattern" "$file" >/dev/null
  else
    grep -n -- "$pattern" "$file" >/dev/null
  fi
}

required_files=(
  "docs/ai/STEERING.md"
  "AGENTS.md"
  "CLAUDE.md"
  ".cursor/rules/00-core.mdc"
  ".cursor/rules/10-quality-gates.mdc"
  ".cursor/rules/20-token-economy.mdc"
  ".gemini/settings.json"
  ".gemini/rules/01-core-rule.md"
  ".gemini/workflows/fast-pr-check.md"
  "tools/agent/quality-gate.sh"
  "tools/agent/changed-modules.sh"
  "tools/agent/spec-trace-check.sh"
  "tools/agent/context-pack.sh"
  "tools/agent/setup-hooks.sh"
  ".githooks/pre-commit"
  ".githooks/pre-push"
  "docs/ai/SKILLS.md"
  "docs/ai/WORKFLOWS.md"
  "docs/ai/COST_POLICY.md"
  "docs/IMPLEMENTATION_STATUS.md"
  "docs/ROADMAP.md"
  "docs/IMPLEMENTATION_TRACKER.md"
  "tools/agent/next-step.sh"
  "tools/agent/status-trace-check.sh"
)

for file in "${required_files[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "Missing required harness file: $file" >&2
    exit 1
  fi
done

for file in AGENTS.md CLAUDE.md .cursor/rules/00-core.mdc .gemini/rules/01-core-rule.md; do
  if ! contains_pattern "docs/ai/STEERING.md" "$file"; then
    echo "Adapter not linked to canonical steering source: $file" >&2
    exit 1
  fi
done

if ! contains_pattern "--mode fast --scope changed --block false" .githooks/pre-commit; then
  echo "pre-commit hook is out of policy" >&2
  exit 1
fi

if ! contains_pattern "--mode strict --scope changed --block true" .githooks/pre-push; then
  echo "pre-push hook is out of policy" >&2
  exit 1
fi

echo "Harness consistency: PASS"
