#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "Usage: $0 <xcframework-path> <privacy-manifest-path> <license-path> <notices-path>" >&2
  exit 2
fi

xcframework="$1"
privacy_manifest="$2"
project_license="$3"
third_party_notices="$4"
if [[ ! -d "$xcframework" || ! -f "$privacy_manifest" || ! -f "$project_license" || ! -f "$third_party_notices" ]]; then
  echo "XCFramework post-processing input is missing." >&2
  exit 1
fi

framework_count=0
for framework in "$xcframework"/*/WebAuthnBridge.framework; do
  [[ -d "$framework" ]] || continue
  framework_count=$((framework_count + 1))
  cp "$privacy_manifest" "$framework/PrivacyInfo.xcprivacy"
  cp "$project_license" "$framework/LICENSE"
  cp "$third_party_notices" "$framework/THIRD_PARTY_NOTICES.txt"
  xcrun strip -S "$framework/WebAuthnBridge"
done
if [[ $framework_count -eq 0 ]]; then
  echo "No WebAuthnBridge.framework slices found in $xcframework" >&2
  exit 1
fi
