#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

changed_files_path=""
strict="false"

usage() {
    cat <<USAGE
Usage: tools/agent/docs-trace-check.sh --changed-files <path> [--strict]
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

mapfile -t changed_files < "$changed_files_path"

discover_published_modules() {
    local -A seen=()
    local build_file

    while IFS= read -r build_file; do
        local module
        module="${build_file#./}"
        module="${module%/build.gradle.kts}"

        case "$module" in
            platform/bom|webauthn-*)
                seen["$module"]=1
                ;;
        esac
    done < <(find . -mindepth 2 -maxdepth 3 -name build.gradle.kts | sort)

    printf '%s\n' "${!seen[@]}" | sort
}

is_integration_change_file() {
    local file="$1"
    case "$file" in
        settings.gradle.kts|build.gradle.kts|platform/bom/build.gradle.kts)
            return 0
            ;;
        webauthn-*/build.gradle.kts)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

is_module_contract_change_file() {
    local module="$1"
    local file="$2"

    case "$file" in
        "$module/README.md")
            return 1
            ;;
        "$module/build.gradle.kts"|"$module/api/"*)
            return 0
            ;;
        "$module/src/"*Test/*|"$module/src/"*test/*)
            return 1
            ;;
        "$module/src/"*Main/*|"$module/src/"*main/*)
            return 0
            ;;
        "$module/src/"*)
            return 1
            ;;
        "$module/"*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

mapfile -t published_modules < <(discover_published_modules)

declare -A module_readme_required=()
declare -A module_readme_updated=()

requires_integration_docs="false"
root_readme_updated="false"
architecture_doc_updated="false"

for file in "${changed_files[@]}"; do
    [[ -z "$file" ]] && continue

    if [[ "$file" == "README.md" ]]; then
        root_readme_updated="true"
    fi

    if [[ "$file" == "docs/architecture.md" ]]; then
        architecture_doc_updated="true"
    fi

    if is_integration_change_file "$file"; then
        requires_integration_docs="true"
    fi

    for module in "${published_modules[@]}"; do
        if [[ "$file" == "$module/README.md" ]]; then
            module_readme_updated["$module"]="true"
            continue
        fi

        if is_module_contract_change_file "$module" "$file"; then
            module_readme_required["$module"]="true"
        fi
    done
done

missing_module_readmes=()
for module in "${published_modules[@]}"; do
    if [[ "${module_readme_required[$module]:-false}" == "true" && "${module_readme_updated[$module]:-false}" != "true" ]]; then
        missing_module_readmes+=("$module/README.md")
    fi
done

integration_missing=()
if [[ "$requires_integration_docs" == "true" ]]; then
    if [[ "$root_readme_updated" != "true" ]]; then
        integration_missing+=("README.md")
    fi
    if [[ "$architecture_doc_updated" != "true" ]]; then
        integration_missing+=("docs/architecture.md")
    fi
fi

if [[ ${#missing_module_readmes[@]} -eq 0 && ${#integration_missing[@]} -eq 0 ]]; then
    echo "Docs trace: OK"
    exit 0
fi

msg="Docs trace required:"
if [[ ${#missing_module_readmes[@]} -gt 0 ]]; then
    msg+=" update module README(s) for changed module implementation/build contract -> ${missing_module_readmes[*]};"
fi
if [[ ${#integration_missing[@]} -gt 0 ]]; then
    msg+=" update integration docs for module relationship/integration changes -> ${integration_missing[*]};"
fi

if [[ "$strict" == "true" ]]; then
    echo "$msg" >&2
    exit 1
fi

echo "WARN: $msg" >&2
exit 0
