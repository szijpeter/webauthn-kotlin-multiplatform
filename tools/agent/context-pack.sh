#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

task=""
changed_only="false"
max_lines=400

usage() {
    cat <<USAGE
Usage: tools/agent/context-pack.sh [--task "<goal>"] [--changed-only] [--max-lines <n>]
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --task)
            task="$2"
            shift 2
            ;;
        --changed-only)
            changed_only="true"
            shift
            ;;
        --max-lines)
            max_lines="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if ! [[ "$max_lines" =~ ^[0-9]+$ ]]; then
    echo "--max-lines must be an integer" >&2
    exit 2
fi

eval "$(tools/agent/changed-modules.sh --scope changed --format shell)"

mapfile -t changed_files < <(tools/agent/changed-modules.sh --scope changed --print-files)

line_budget="$max_lines"
line_count=0

emit() {
    local text="$1"
    local lines
    lines=$(printf '%s\n' "$text" | wc -l | tr -d ' ')
    if (( line_count + lines > line_budget )); then
        return 1
    fi
    printf '%s\n' "$text"
    line_count=$((line_count + lines))
    return 0
}

emit "# Context Pack"
emit ""

if [[ -n "$task" ]]; then
    emit "## Task"
    emit "$task"
    emit ""
fi

emit "## Change Summary"
emit "- changed_count: $CHANGED_COUNT"
emit "- docs_only: $DOCS_ONLY"
emit "- spec_sensitive: $SPEC_SENSITIVE"
emit "- modules: ${MODULES_CSV:-none}"
emit "- categories: ${CATEGORIES_CSV:-none}"
emit ""

emit "## Changed Files"
if [[ ${#changed_files[@]} -eq 0 ]]; then
    emit "- (none)"
else
    for f in "${changed_files[@]}"; do
        emit "- $f" || break
    done
fi
emit ""

if [[ "$changed_only" != "true" ]]; then
    emit "## Core References"
    emit "- docs/architecture.md"
    emit "- docs/dependency-decisions.md"
    emit "- spec-notes/webauthn-l3-validation-map.md"
    emit ""
fi

if (( line_count < line_budget )) && [[ ${#changed_files[@]} -gt 0 ]]; then
    emit "## File Excerpts"
    emit ""
    for f in "${changed_files[@]}"; do
        [[ ! -f "$f" ]] && continue
        emit "### $f" || break
        emit '```' || break
        while IFS= read -r line; do
            if ! emit "$line"; then
                break 2
            fi
        done < <(sed -n '1,40p' "$f")
        emit '```' || break
        emit "" || break
    done
fi

if (( line_count >= line_budget )); then
    echo "_Context truncated at ${max_lines} lines._"
fi
