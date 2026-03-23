#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if ! command -v xcodebuild >/dev/null 2>&1; then
    echo "Skipping ComposePasskeyIos host build: xcodebuild is not available on this host."
    exit 0
fi

destination="generic/platform=iOS Simulator"
if command -v xcrun >/dev/null 2>&1; then
    set +o pipefail
    simulator_id="$(
        xcrun simctl list devices available 2>/dev/null \
            | sed -n 's/^[[:space:]]*iPhone[^()]* (\([0-9A-F-]\{36\}\)) (.*$/\1/p' \
            | head -n 1
    )"
    set -o pipefail
    if [[ -n "${simulator_id:-}" ]]; then
        destination="id=$simulator_id"
    fi
fi

# Avoid host-wide include path pollution (for example CPATH pointing to MacOSX SDK)
# that can break iOS simulator module resolution.
unset CPATH
unset C_INCLUDE_PATH
unset CPLUS_INCLUDE_PATH
unset OBJC_INCLUDE_PATH

export GRADLE_USER_HOME="${GRADLE_USER_HOME:-$ROOT_DIR/.gradle-local}"

log_file="$(mktemp)"
trap 'rm -f "$log_file"' EXIT

if xcodebuild \
    -project samples/compose-passkey-ios/ComposePasskeyIos.xcodeproj \
    -scheme ComposePasskeyIos \
    -sdk iphonesimulator \
    -derivedDataPath "$ROOT_DIR/.build/xcode-derived/compose-passkey-ios-host" \
    -destination "$destination" \
    ONLY_ACTIVE_ARCH=YES \
    CODE_SIGNING_ALLOWED=NO \
    build >"$log_file" 2>&1; then
    cat "$log_file"
    exit 0
fi

sandbox_error_pattern='CoreSimulatorService connection became invalid|java.net.SocketException: Operation not permitted|Couldn'\''t create workspace arena folder|Error opening log file'
if command -v rg >/dev/null 2>&1 && rg -q "$sandbox_error_pattern" "$log_file"; then
    echo "Skipping ComposePasskeyIos host build: sandbox restrictions prevented xcodebuild from accessing simulator or filesystem services."
    tail -n 40 "$log_file"
    exit 0
fi
if ! command -v rg >/dev/null 2>&1 && grep -Eq "$sandbox_error_pattern" "$log_file"; then
    echo "Skipping ComposePasskeyIos host build: sandbox restrictions prevented xcodebuild from accessing simulator or filesystem services."
    tail -n 40 "$log_file"
    exit 0
fi

cat "$log_file"
exit 1
