#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

mode="all"

usage() {
    cat <<USAGE
Usage: tools/compat/run-signum-serialization-matrix.sh [--mode all|baseline|target-a|target-b|canary]
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)
            mode="$2"
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

case "$mode" in
    all|baseline|target-a|target-b|canary) ;;
    *)
        echo "Invalid --mode: $mode" >&2
        exit 2
        ;;
esac

version_from_catalog() {
    local alias="$1"
    sed -n "s/^${alias} = \"\\([^\"]*\\)\"/\\1/p" gradle/libs.versions.toml | head -n 1
}

fetch_maven_metadata() {
    local group="$1"
    local artifact="$2"
    local url="https://repo1.maven.org/maven2/${group//./\/}/${artifact}/maven-metadata.xml"
    curl -fsSL "$url"
}

latest_release_from_metadata() {
    local xml="$1"
    local release
    release="$(printf '%s\n' "$xml" | sed -n 's|.*<release>\([^<]*\)</release>.*|\1|p' | head -n 1)"
    if [[ -n "$release" ]]; then
        printf '%s' "$release"
        return 0
    fi
    printf '%s\n' "$xml" | sed -n 's|.*<latest>\([^<]*\)</latest>.*|\1|p' | head -n 1
}

version_gt() {
    local a="$1"
    local b="$2"
    local IFS=.
    local a_parts b_parts
    read -r -a a_parts <<< "$a"
    read -r -a b_parts <<< "$b"
    for idx in 0 1 2; do
        local ai="${a_parts[$idx]:-0}"
        local bi="${b_parts[$idx]:-0}"
        if ((10#${ai} > 10#${bi})); then
            return 0
        fi
        if ((10#${ai} < 10#${bi})); then
            return 1
        fi
    done
    return 1
}

latest_patch_for_minor_from_metadata() {
    local xml="$1"
    local major_minor="$2"
    local best=""
    while IFS= read -r version; do
        [[ "$version" =~ ^${major_minor//./\\.}\.[0-9]+$ ]] || continue
        if [[ -z "$best" ]] || version_gt "$version" "$best"; then
            best="$version"
        fi
    done < <(printf '%s\n' "$xml" | sed -n 's|.*<version>\([^<]*\)</version>.*|\1|p')
    printf '%s' "$best"
}

gradle_compat_run() {
    local label="$1"
    local serialization_version="$2"
    local signum_version="$3"
    local signum_indispensable_version="$4"

    echo ""
    echo "=== Matrix combo: $label ==="
    echo "serialization=$serialization_version signum=$signum_version signum-indispensable=$signum_indispensable_version"

    ./gradlew \
        :webauthn-server-jvm-crypto:test \
        :webauthn-server-core-jvm:test \
        --tests "dev.webauthn.server.crypto.JvmSignatureVerifierTest.capturedAndroidAssertionVectorCanBeVerifiedWithJca" \
        --tests "dev.webauthn.server.ServiceSmokeTest.authenticationFinishSupportsCapturedAndroidAssertionVector" \
        --tests "dev.webauthn.server.ServiceSmokeTest.jvmSignatureVerifierSupportsCapturedAndroidAssertionVector" \
        -Pcompat.serializationVersionOverride="$serialization_version" \
        -Pcompat.signumVersionOverride="$signum_version" \
        -Pcompat.signumIndispensableVersionOverride="$signum_indispensable_version" \
        --rerun-tasks \
        --stacktrace
}

default_serialization="$(version_from_catalog "serialization")"
default_signum="$(version_from_catalog "signum")"
default_signum_indispensable="$(version_from_catalog "signum-indispensable")"

baseline_serialization="${BASELINE_SERIALIZATION:-1.9.0}"
baseline_signum="${BASELINE_SIGNUM:-0.11.3}"
baseline_signum_indispensable="${BASELINE_SIGNUM_INDISPENSABLE:-3.19.3}"
target_serialization="${TARGET_SERIALIZATION:-1.10.0}"

latest_signum="$default_signum"
latest_signum_indispensable="$default_signum_indispensable"
if metadata="$(fetch_maven_metadata "at.asitplus.signum" "supreme-jvm" 2>/dev/null)"; then
    latest_signum_release="$(latest_release_from_metadata "$metadata")"
    if [[ -n "$latest_signum_release" ]]; then
        latest_signum="$latest_signum_release"
    fi
fi
if metadata="$(fetch_maven_metadata "at.asitplus.signum" "indispensable-cosef-jvm" 2>/dev/null)"; then
    latest_indispensable_release="$(latest_release_from_metadata "$metadata")"
    if [[ -n "$latest_indispensable_release" ]]; then
        latest_signum_indispensable="$latest_indispensable_release"
    fi
fi

canary_serialization="$target_serialization"
if metadata="$(fetch_maven_metadata "org.jetbrains.kotlinx" "kotlinx-serialization-core" 2>/dev/null)"; then
    latest_110x="$(latest_patch_for_minor_from_metadata "$metadata" "1.10")"
    if [[ -n "$latest_110x" ]]; then
        canary_serialization="$latest_110x"
    fi
fi

failures=0
run_checked() {
    if ! "$@"; then
        failures=$((failures + 1))
    fi
}

case "$mode" in
    baseline)
        run_checked gradle_compat_run "baseline" "$baseline_serialization" "$baseline_signum" "$baseline_signum_indispensable"
        ;;
    target-a)
        run_checked gradle_compat_run "target-a" "$target_serialization" "$default_signum" "$default_signum_indispensable"
        ;;
    target-b)
        run_checked gradle_compat_run "target-b" "$target_serialization" "$latest_signum" "$latest_signum_indispensable"
        ;;
    canary)
        run_checked gradle_compat_run "canary" "$canary_serialization" "$latest_signum" "$latest_signum_indispensable"
        ;;
    all)
        run_checked gradle_compat_run "baseline" "$baseline_serialization" "$baseline_signum" "$baseline_signum_indispensable"
        run_checked gradle_compat_run "target-a" "$target_serialization" "$default_signum" "$default_signum_indispensable"
        run_checked gradle_compat_run "target-b" "$target_serialization" "$latest_signum" "$latest_signum_indispensable"
        ;;
esac

echo ""
echo "Compatibility matrix summary:"
echo "default serialization=$default_serialization signum=$default_signum signum-indispensable=$default_signum_indispensable"
echo "latest signum=$latest_signum latest signum-indispensable=$latest_signum_indispensable"
echo "target serialization=$target_serialization canary serialization=$canary_serialization"

if [[ "$failures" -gt 0 ]]; then
    echo "Matrix result: FAIL ($failures failing combo(s))" >&2
    exit 1
fi

echo "Matrix result: PASS"
