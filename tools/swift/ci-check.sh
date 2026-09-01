#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Swift CI checks require macOS." >&2
  exit 1
fi

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/webauthn-swift-ci.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT
derived_data="${WEBAUTHN_SWIFT_DERIVED_DATA:-$temporary/DerivedData}"
if [[ -n "${WEBAUTHN_EXPECTED_XCODE_VERSION:-}" ]]; then
  actual_xcode_version="$(xcodebuild -version | awk 'NR == 1 { print $2 }')"
  if [[ "$actual_xcode_version" != "$WEBAUTHN_EXPECTED_XCODE_VERSION" ]]; then
    echo "Expected Xcode $WEBAUTHN_EXPECTED_XCODE_VERSION, found $actual_xcode_version." >&2
    exit 1
  fi
fi

"$repo_root/gradlew" -p "$repo_root" \
  :client:webauthn-client-prf-crypto:jvmTest \
  :client:webauthn-client-swift-bridge:iosSimulatorArm64Test \
  :client:webauthn-client-swift-bridge:assembleWebAuthnBridgeReleaseXCFramework \
  --stacktrace
"$repo_root/tools/swift/check-xcframework.sh"
"$repo_root/tools/swift/check-xcodegen.sh"
python3 "$repo_root/tools/swift/test_check_parity.py"
python3 "$repo_root/tools/swift/test_check_client_parity.py"
python3 "$repo_root/tools/swift/test_check_package_layout.py"
python3 "$repo_root/tools/swift/test_reconcile_release.py"
"$repo_root/tools/swift/check-parity.py"
"$repo_root/tools/swift/check-client-parity.py"
release_manifest_root="$temporary/ReleaseManifest"
mkdir -p "$release_manifest_root"
"$repo_root/tools/swift/render-release-package.sh" \
  "0.0.0" \
  "0000000000000000000000000000000000000000000000000000000000000000" \
  "$release_manifest_root/Package.swift"
ln -s "$repo_root/swift" "$release_manifest_root/swift"
python3 "$repo_root/tools/swift/check-package-layout.py" \
  "$repo_root" \
  "$release_manifest_root"

simulator_id="$(xcrun simctl list devices available -j | python3 -c '
import json, sys
devices = json.load(sys.stdin)["devices"]
for runtime in sorted(devices, reverse=True):
    for device in devices[runtime]:
        if device.get("isAvailable") and device["name"].startswith("iPhone"):
            print(device["udid"])
            raise SystemExit
raise SystemExit("No available iPhone simulator")
')"

common_arguments=(
  -quiet
  -project "$repo_root/sample/swift-passkey/WebAuthnSwiftDemo.xcodeproj"
  -scheme WebAuthnSwiftDemo
  -destination "platform=iOS Simulator,id=$simulator_id"
  -derivedDataPath "$derived_data"
  ARCHS=arm64
  VALID_ARCHS=arm64
  EXCLUDED_ARCHS=x86_64
  ONLY_ACTIVE_ARCH=YES
  CODE_SIGNING_ALLOWED=NO
  SWIFT_TREAT_WARNINGS_AS_ERRORS=YES
  GCC_TREAT_WARNINGS_AS_ERRORS=YES
)

(
  cd "$repo_root"
  xcodebuild "${common_arguments[@]}" -configuration Debug test
  "$repo_root/tools/swift/check-sample-app.sh" \
    "$derived_data/Build/Products/Debug-iphonesimulator/WebAuthnSwiftDemo.app"
  xcodebuild \
    "${common_arguments[@]}" \
    -configuration Release \
    BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
    build
)
"$repo_root/tools/swift/check-package-consumer.sh" --local "$repo_root"
if [[ "${WEBAUTHN_SWIFT_CHECK_API_BASELINE:-true}" == "true" ]]; then
  "$repo_root/tools/swift/check-api.sh" "$derived_data"
fi

echo "Swift bridge, modular package/sample/consumer tests and configuration, Release build, API, parity, and XcodeGen checks passed."
