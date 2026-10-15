#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

changed_files_path=""
strict="false"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --changed-files)
            if [[ -z "${2:-}" || "${2:-}" == -* ]]; then
                echo "Missing value for --changed-files" >&2
                exit 2
            fi
            changed_files_path="$2"
            shift 2
            ;;
        --strict)
            strict="true"
            shift
            ;;
        -h|--help)
            echo "Usage: tools/agent/diagram-trace-check.sh --changed-files <path> [--strict]"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

if [[ -z "$changed_files_path" || ! -f "$changed_files_path" ]]; then
    echo "A readable --changed-files list is required." >&2
    exit 2
fi

relevant="false"
while IFS= read -r file; do
    case "$file" in
        docs/diagrams/*|tools/docs/diagram*|tools/docs/test_diagrams.py|*.md)
            relevant="true"
            ;;
    esac
done < "$changed_files_path"

if [[ "$relevant" == "false" ]]; then
    echo "Diagram trace: OK (no changed diagram inputs or documentation)"
    exit 0
fi

if python3 tools/docs/diagrams.py check; then
    echo "Diagram trace: OK"
elif [[ "$strict" == "true" ]]; then
    exit 1
else
    echo "WARN: diagram verification failed" >&2
fi
