#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

mode="fast"
scope="changed"
format="human"
block="true"

usage() {
    cat <<USAGE
Usage: tools/agent/quality-gate.sh [--mode fast|strict] [--scope changed|full] [--format human|json] [--block true|false]
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)
            mode="$2"
            shift 2
            ;;
        --scope)
            scope="$2"
            shift 2
            ;;
        --format)
            format="$2"
            shift 2
            ;;
        --block)
            block="$2"
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

if [[ "$mode" != "fast" && "$mode" != "strict" ]]; then
    echo "Invalid --mode: $mode" >&2
    exit 2
fi

if [[ "$scope" != "changed" && "$scope" != "full" ]]; then
    echo "Invalid --scope: $scope" >&2
    exit 2
fi

if [[ "$format" != "human" && "$format" != "json" ]]; then
    echo "Invalid --format: $format" >&2
    exit 2
fi

if [[ "$block" != "true" && "$block" != "false" ]]; then
    echo "Invalid --block: $block" >&2
    exit 2
fi

eval "$(tools/agent/changed-modules.sh --scope "$scope" --format shell)"

tmp_changed_files="$(mktemp)"
trap 'rm -f "$tmp_changed_files"' EXIT
tools/agent/changed-modules.sh --scope "$scope" --print-files > "$tmp_changed_files"

if [[ "$CHANGED_COUNT" -eq 0 ]]; then
    if [[ "$format" == "json" ]]; then
        echo '{"status":"ok","message":"No changed files detected."}'
    else
        echo "Quality gate: no changed files detected."
    fi
    exit 0
fi

if [[ "$scope" == "changed" && "$DOCS_ONLY" == "true" ]]; then
    if [[ "$mode" == "strict" ]]; then
        tools/agent/spec-trace-check.sh --changed-files "$tmp_changed_files" --strict >/dev/null
    fi
    if [[ "$format" == "json" ]]; then
        echo '{"status":"ok","message":"Docs-only change; skipping compile/test gates."}'
    else
        echo "Quality gate: docs-only change, skipping compile/test gates."
    fi
    exit 0
fi

export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$ROOT_DIR/.gradle-local}"

run_cmd() {
    local cmd="$1"
    if [[ "$format" == "human" ]]; then
        echo "Running: $cmd"
    fi
    if ! eval "$cmd"; then
        return 1
    fi
    return 0
}

status="ok"
message="All checks passed."

run_list=()

if [[ "$scope" == "full" ]]; then
    run_list+=("./gradlew check --stacktrace")
else
    IFS=',' read -r -a categories <<< "$CATEGORIES_CSV"
    IFS=',' read -r -a modules <<< "$MODULES_CSV"
    has_build="false"
    has_ci="false"
    has_harness="false"
    has_core="false"

    for category in "${categories[@]}"; do
        [[ -z "$category" ]] && continue
        case "$category" in
            build)
                has_build="true"
                ;;
            ci)
                has_ci="true"
                ;;
            harness)
                has_harness="true"
                ;;
            core)
                has_core="true"
                ;;
        esac
    done

    for module in "${modules[@]}"; do
        [[ -z "$module" ]] && continue
        case "$module" in
            webauthn-model|webauthn-core|webauthn-serialization-kotlinx|webauthn-crypto-api|webauthn-client-core|webauthn-network-ktor-client)
                run_list+=("./gradlew :$module:allTests --stacktrace")
                ;;
            webauthn-server-core-jvm|webauthn-server-jvm-crypto|webauthn-server-ktor|webauthn-attestation-mds)
                run_list+=("./gradlew :$module:test --stacktrace")
                ;;
            webauthn-client-android)
                run_list+=("./gradlew :webauthn-client-android:lintDebug :webauthn-client-android:assemble --stacktrace")
                ;;
            webauthn-client-ios)
                run_list+=("./gradlew :webauthn-client-ios:compileKotlinIosSimulatorArm64 --stacktrace")
                ;;
            samples:android-passkey)
                run_list+=("./gradlew :samples:android-passkey:lintDebug :samples:android-passkey:assemble --stacktrace")
                ;;
            samples:backend-ktor)
                run_list+=("./gradlew :samples:backend-ktor:test --stacktrace")
                ;;
            samples:ios-passkey)
                run_list+=("./gradlew :samples:ios-passkey:compileKotlinIosSimulatorArm64 --stacktrace")
                ;;
        esac
    done

    if [[ "$has_harness" == "true" || "$has_ci" == "true" ]]; then
        run_list+=("tools/agent/verify-harness-sync.sh")
    fi

    if [[ "$has_build" == "true" ]]; then
        if [[ "$mode" == "strict" ]]; then
            run_list+=("./gradlew check --stacktrace")
        else
            run_list+=("./gradlew :build-logic:check --stacktrace")
        fi
    fi

    if [[ "$mode" == "strict" ]]; then
        run_list+=("tools/agent/status-trace-check.sh --changed-files $tmp_changed_files --strict")

        if [[ "$SPEC_SENSITIVE" == "true" ]]; then
            run_list+=("tools/agent/spec-trace-check.sh --changed-files $tmp_changed_files --strict")
        fi

        if [[ "$has_core" == "true" ]]; then
            run_list+=("./gradlew :webauthn-server-core-jvm:test :webauthn-server-ktor:test --stacktrace")
        fi
    fi
fi

# Deduplicate while preserving order.
declare -A seen=()
unique_run_list=()
for cmd in "${run_list[@]}"; do
    [[ -z "$cmd" ]] && continue
    if [[ -z "${seen[$cmd]:-}" ]]; then
        unique_run_list+=("$cmd")
        seen[$cmd]=1
    fi
done

if [[ ${#unique_run_list[@]} -eq 0 ]]; then
    if [[ "$format" == "json" ]]; then
        echo '{"status":"ok","message":"No executable checks were selected for this change."}'
    else
        echo "Quality gate: no executable checks selected for this change."
    fi
    exit 0
fi

for cmd in "${unique_run_list[@]}"; do
    if ! run_cmd "$cmd"; then
        status="failed"
        message="Check failed: $cmd"
        break
    fi
done

if [[ "$format" == "json" ]]; then
    printf '{"status":"%s","message":"%s"}\n' "$status" "$message"
else
    if [[ "$status" == "ok" ]]; then
        echo "Quality gate: PASS"
    else
        echo "Quality gate: FAIL - $message" >&2
    fi
fi

if [[ "$status" == "failed" && "$block" == "true" ]]; then
    exit 1
fi

exit 0
