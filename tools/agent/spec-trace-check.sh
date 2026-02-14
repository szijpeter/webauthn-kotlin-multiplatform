#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

changed_files_path=""
strict="false"

usage() {
    cat <<USAGE
Usage: tools/agent/spec-trace-check.sh --changed-files <path> [--strict]
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

requires_spec_update="false"
spec_note_updated="false"

for file in "${changed_files[@]}"; do
    [[ -z "$file" ]] && continue

    case "$file" in
        webauthn-core/src/commonMain/kotlin/dev/webauthn/core/*|\
        webauthn-model/src/commonMain/kotlin/dev/webauthn/model/Validation.kt|\
        webauthn-model/src/commonMain/kotlin/dev/webauthn/model/WebAuthnValidationError.kt|\
        webauthn-model/src/commonMain/kotlin/dev/webauthn/model/ProtocolModels.kt|\
        webauthn-model/src/commonMain/kotlin/dev/webauthn/model/Types.kt|\
        webauthn-model/src/commonMain/kotlin/dev/webauthn/model/Base64UrlCodec.kt|\
        webauthn-model/src/commonMain/kotlin/dev/webauthn/model/Base64UrlBytes.kt)
            requires_spec_update="true"
            ;;
    esac

    if [[ "$file" == "spec-notes/webauthn-l3-validation-map.md" ]]; then
        spec_note_updated="true"
    fi
done

if [[ "$requires_spec_update" != "true" ]]; then
    echo "Spec trace: not required (no validator/model semantic paths changed)."
    exit 0
fi

if [[ "$spec_note_updated" == "true" ]]; then
    echo "Spec trace: OK (spec note updated)."
    exit 0
fi

msg="Spec trace required: update spec-notes/webauthn-l3-validation-map.md when validator/model semantics change."
if [[ "$strict" == "true" ]]; then
    echo "$msg" >&2
    exit 1
fi

echo "WARN: $msg" >&2
exit 0
