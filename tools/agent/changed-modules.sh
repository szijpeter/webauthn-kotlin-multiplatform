#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

scope="changed"
format="human"
print_files="false"

usage() {
    cat <<USAGE
Usage: tools/agent/changed-modules.sh [--scope changed|full] [--format human|json|shell] [--print-files]
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --scope)
            scope="$2"
            shift 2
            ;;
        --format)
            format="$2"
            shift 2
            ;;
        --print-files)
            print_files="true"
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

if [[ "$scope" != "changed" && "$scope" != "full" ]]; then
    echo "Invalid --scope: $scope" >&2
    exit 2
fi

if [[ "$format" != "human" && "$format" != "json" && "$format" != "shell" ]]; then
    echo "Invalid --format: $format" >&2
    exit 2
fi

collect_changed_files() {
    if [[ "$scope" == "full" ]]; then
        git ls-files
        return
    fi

    # Prefer local in-progress changes for fast feedback loops.
    local local_changed
    local_changed="$(
        {
            git diff --name-only --diff-filter=ACMR
            git diff --cached --name-only --diff-filter=ACMR
            git ls-files --others --exclude-standard
        } | awk 'NF' | sort -u
    )"
    if [[ -n "$local_changed" ]]; then
        printf '%s\n' "$local_changed"
        return
    fi

    # If working tree is clean, fall back to commit-range diff for push scenarios.
    if git rev-parse --verify HEAD >/dev/null 2>&1; then
        local upstream
        upstream="$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)"
        if [[ -n "$upstream" ]]; then
            local base
            base="$(git merge-base HEAD "$upstream")"
            git diff --name-only --diff-filter=ACMR "$base"...HEAD
        elif git rev-parse --verify HEAD~1 >/dev/null 2>&1; then
            git diff --name-only --diff-filter=ACMR HEAD~1...HEAD
        fi
    fi
}

mapfile -t changed_files < <(collect_changed_files | awk 'NF' | sort -u)

if [[ "$print_files" == "true" ]]; then
    printf '%s\n' "${changed_files[@]}"
    exit 0
fi

declare -A modules=()
declare -A categories=()
docs_only="true"
spec_sensitive="false"

mark_module() {
    local name="$1"
    modules["$name"]=1
}

mark_category() {
    local name="$1"
    categories["$name"]=1
}

is_docs_file() {
    local file="$1"
    case "$file" in
        docs/*|spec-notes/*|README.md|LICENSE|AGENTS.md|CLAUDE.md|.cursor/*|.gemini/*|tools/agent/*|.githooks/*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

is_spec_sensitive_file() {
    local file="$1"
    case "$file" in
        webauthn-core/src/commonMain/kotlin/dev/webauthn/core/*)
            return 0
            ;;
        webauthn-model/src/commonMain/kotlin/dev/webauthn/model/Validation.kt|\
        webauthn-model/src/commonMain/kotlin/dev/webauthn/model/WebAuthnValidationError.kt|\
        webauthn-model/src/commonMain/kotlin/dev/webauthn/model/ProtocolModels.kt|\
        webauthn-model/src/commonMain/kotlin/dev/webauthn/model/Types.kt|\
        webauthn-model/src/commonMain/kotlin/dev/webauthn/model/Base64UrlCodec.kt|\
        webauthn-model/src/commonMain/kotlin/dev/webauthn/model/Base64UrlBytes.kt)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

for file in "${changed_files[@]}"; do
    [[ -z "$file" ]] && continue

    if ! is_docs_file "$file"; then
        docs_only="false"
    fi

    if is_spec_sensitive_file "$file"; then
        spec_sensitive="true"
    fi

    case "$file" in
        webauthn-model/*)
            mark_module "webauthn-model"
            mark_category "core"
            ;;
        webauthn-core/*)
            mark_module "webauthn-core"
            mark_category "core"
            ;;
        webauthn-serialization-kotlinx/*)
            mark_module "webauthn-serialization-kotlinx"
            mark_category "core"
            ;;
        webauthn-crypto-api/*)
            mark_module "webauthn-crypto-api"
            mark_category "core"
            ;;
        webauthn-server-core-jvm/*)
            mark_module "webauthn-server-core-jvm"
            mark_category "server"
            ;;
        webauthn-server-jvm-crypto/*)
            mark_module "webauthn-server-jvm-crypto"
            mark_category "server"
            ;;
        webauthn-server-ktor/*)
            mark_module "webauthn-server-ktor"
            mark_category "server"
            ;;
        webauthn-attestation-mds/*)
            mark_module "webauthn-attestation-mds"
            mark_category "server"
            ;;
        webauthn-network-ktor-client/*)
            mark_module "webauthn-network-ktor-client"
            mark_category "client"
            ;;
        webauthn-client-core/*)
            mark_module "webauthn-client-core"
            mark_category "client"
            ;;
        webauthn-client-android/*)
            mark_module "webauthn-client-android"
            mark_category "android"
            ;;
        webauthn-client-ios/*)
            mark_module "webauthn-client-ios"
            mark_category "ios"
            ;;
        samples/android-passkey/*)
            mark_module "samples:android-passkey"
            mark_category "android"
            ;;
        samples/backend-ktor/*)
            mark_module "samples:backend-ktor"
            mark_category "server"
            ;;
        samples/ios-passkey/*)
            mark_module "samples:ios-passkey"
            mark_category "ios"
            ;;
        docs/*|spec-notes/*)
            mark_category "docs"
            ;;
        tools/agent/*|.githooks/*|AGENTS.md|CLAUDE.md|.cursor/*|.gemini/*)
            mark_category "harness"
            ;;
        .github/workflows/*)
            mark_category "ci"
            ;;
        build-logic/*|build.gradle.kts|settings.gradle.kts|gradle/*|gradle.properties|platform/*)
            mark_category "build"
            ;;
    esac
done

join_csv() {
    local -a values=("$@")
    local out=""
    local v
    for v in "${values[@]}"; do
        if [[ -n "$out" ]]; then
            out+=","
        fi
        out+="$v"
    done
    printf '%s' "$out"
}

csv_to_json_array() {
    local csv="$1"
    if [[ -z "$csv" ]]; then
        printf '[]'
        return
    fi

    local IFS=','
    read -r -a parts <<< "$csv"
    local out="["
    local part
    for part in "${parts[@]}"; do
        [[ -z "$part" ]] && continue
        if [[ "$out" != "[" ]]; then
            out+=","
        fi
        out+="\"$part\""
    done
    out+="]"
    printf '%s' "$out"
}

mapfile -t module_list < <(printf '%s\n' "${!modules[@]}" | awk 'NF' | sort)
mapfile -t category_list < <(printf '%s\n' "${!categories[@]}" | awk 'NF' | sort)

module_csv="$(join_csv "${module_list[@]}")"
category_csv="$(join_csv "${category_list[@]}")"
changed_count="${#changed_files[@]}"

case "$format" in
    shell)
        echo "DOCS_ONLY=$docs_only"
        echo "SPEC_SENSITIVE=$spec_sensitive"
        echo "CHANGED_COUNT=$changed_count"
        echo "MODULES_CSV=$module_csv"
        echo "CATEGORIES_CSV=$category_csv"
        ;;
    json)
        printf '{"docs_only":%s,"spec_sensitive":%s,"changed_count":%d,"modules":%s,"categories":%s}\n' \
            "$docs_only" "$spec_sensitive" "$changed_count" \
            "$(csv_to_json_array "$module_csv")" "$(csv_to_json_array "$category_csv")"
        ;;
    human)
        echo "docs_only=$docs_only"
        echo "spec_sensitive=$spec_sensitive"
        echo "changed_count=$changed_count"
        [[ -n "$module_csv" ]] && echo "modules=$module_csv" || echo "modules="
        [[ -n "$category_csv" ]] && echo "categories=$category_csv" || echo "categories="
        ;;
esac
