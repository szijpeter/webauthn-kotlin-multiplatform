#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

changed_files_path=""
strict="false"

usage() {
    cat <<USAGE
Usage: tools/agent/mermaid-trace-check.sh --changed-files <path> [--strict]
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --changed-files)
            if [[ -z "${2:-}" || "${2:-}" == -* ]]; then
                echo "Missing value for --changed-files" >&2
                usage >&2
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

if [[ -z "$changed_files_path" ]]; then
    echo "Missing required --changed-files argument." >&2
    exit 2
fi

if [[ ! -f "$changed_files_path" ]]; then
    echo "Changed files list not found: $changed_files_path" >&2
    exit 2
fi

contains_mermaid_block() {
    local file="$1"
    if command -v rg >/dev/null 2>&1; then
        rg -n '```mermaid' "$file" >/dev/null 2>&1
    else
        grep -n '```mermaid' "$file" >/dev/null 2>&1
    fi
}

mapfile -t changed_files < "$changed_files_path"
mermaid_files=()

for file in "${changed_files[@]}"; do
    [[ -z "$file" ]] && continue
    [[ "$file" == *.md ]] || continue
    [[ -f "$file" ]] || continue
    if contains_mermaid_block "$file"; then
        mermaid_files+=("$file")
    fi
done

if [[ ${#mermaid_files[@]} -eq 0 ]]; then
    echo "Mermaid trace: OK (no changed Mermaid diagrams)"
    exit 0
fi

mmdc_cmd=()
if command -v mmdc >/dev/null 2>&1; then
    mmdc_cmd=(mmdc)
elif command -v npx >/dev/null 2>&1; then
    mmdc_cmd=(npx -y @mermaid-js/mermaid-cli)
else
    msg="Mermaid trace check requires either 'mmdc' or 'npx' in PATH."
    if [[ "$strict" == "true" ]]; then
        echo "$msg" >&2
        exit 1
    fi
    echo "WARN: $msg" >&2
    exit 0
fi

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

failures=()
for file in "${mermaid_files[@]}"; do
    output_file="$tmp_dir/$(echo "$file" | tr '/.' '__').md"
    log_file="$tmp_dir/$(echo "$file" | tr '/.' '__').log"
    if ! "${mmdc_cmd[@]}" -q -i "$file" -o "$output_file" -a "$tmp_dir/artifacts" >"$log_file" 2>&1; then
        failures+=("$file")
        echo "Mermaid parse failed in $file" >&2
        sed -n '1,30p' "$log_file" >&2
    fi
done

if [[ ${#failures[@]} -eq 0 ]]; then
    echo "Mermaid trace: OK"
    exit 0
fi

msg="Mermaid trace failed for: ${failures[*]}"
if [[ "$strict" == "true" ]]; then
    echo "$msg" >&2
    exit 1
fi

echo "WARN: $msg" >&2
exit 0
