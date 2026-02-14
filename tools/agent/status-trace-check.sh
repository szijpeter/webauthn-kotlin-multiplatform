#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

changed_files_path=""
strict="false"

usage() {
    cat <<USAGE
Usage: tools/agent/status-trace-check.sh --changed-files <path> [--strict]
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --changed-files)
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

mapfile -t changed_files < "$changed_files_path"

requires_status_update="false"
status_updated="false"
roadmap_updated="false"

for file in "${changed_files[@]}"; do
    [[ -z "$file" ]] && continue

    case "$file" in
        webauthn-model/*|\
        webauthn-core/*|\
        webauthn-serialization-kotlinx/*|\
        webauthn-crypto-api/*|\
        webauthn-server-core-jvm/*|\
        webauthn-server-jvm-crypto/*)
            requires_status_update="true"
            ;;
    esac

    if [[ "$file" == "docs/IMPLEMENTATION_STATUS.md" ]]; then
        status_updated="true"
    fi

    if [[ "$file" == "docs/ROADMAP.md" ]]; then
        roadmap_updated="true"
    fi
done

if [[ "$requires_status_update" != "true" ]]; then
    echo "Status trace: not required (no core/security-critical module changes)."
    exit 0
fi

if [[ "$status_updated" == "true" || "$roadmap_updated" == "true" ]]; then
    echo "Status trace: OK (status docs updated)."
    exit 0
fi

msg="Status trace required: update docs/IMPLEMENTATION_STATUS.md or docs/ROADMAP.md for core/security-critical module changes."
if [[ "$strict" == "true" ]]; then
    echo "$msg" >&2
    exit 1
fi

echo "WARN: $msg" >&2
exit 0
