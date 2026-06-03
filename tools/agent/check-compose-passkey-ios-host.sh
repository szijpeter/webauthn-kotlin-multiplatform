#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

if ! command -v xcodebuild >/dev/null 2>&1; then
    echo "Skipping ComposePasskeyIos host build: xcodebuild is not available on this host."
    exit 0
fi

destination="generic/platform=iOS Simulator"

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
    -project sample/compose-passkey-ios/ComposePasskeyIos.xcodeproj \
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

sandbox_error_pattern='CoreSimulatorService connection became invalid|java.net.SocketException: Operation not permitted|Couldn'\''t create workspace arena folder|Error opening log file|Unable to find a destination matching the provided destination specifier|iOS [0-9.]+ is not installed'
if command -v rg >/dev/null 2>&1 && rg -q "$sandbox_error_pattern" "$log_file"; then
    echo "Skipping ComposePasskeyIos host build: this host cannot provide an eligible iOS simulator destination."
    tail -n 40 "$log_file"
    exit 0
fi
if ! command -v rg >/dev/null 2>&1 && grep -Eq "$sandbox_error_pattern" "$log_file"; then
    echo "Skipping ComposePasskeyIos host build: this host cannot provide an eligible iOS simulator destination."
    tail -n 40 "$log_file"
    exit 0
fi

cat "$log_file"
exit 1
