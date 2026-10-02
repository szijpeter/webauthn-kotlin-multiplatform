#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <version> <output-directory>" >&2
  exit 2
fi
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Swift release artifacts must be prepared on macOS." >&2
  exit 1
fi

version="$1"
output_dir="$2"
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
source_xcframework="$repo_root/client/webauthn-client-swift-bridge/build/XCFrameworks/release/WebAuthnBridge.xcframework"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/webauthn-swift-release.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT

"$repo_root/gradlew" -p "$repo_root" \
  :client:webauthn-client-swift-bridge:assembleWebAuthnBridgeReleaseXCFramework \
  -PVERSION_NAME="$version" \
  --stacktrace
"$repo_root/tools/swift/check-xcframework.sh" "$source_xcframework"

mkdir -p "$output_dir"
artifact="$temporary/WebAuthnBridge.xcframework"
ditto --norsrc --noextattr --noqtn --noacl "$source_xcframework" "$artifact"
find "$artifact" -type f -name '*.swiftsourceinfo' -delete
for binary in "$artifact"/*/WebAuthnBridge.framework/WebAuthnBridge; do
  xcrun strip -S "$binary"
done
"$repo_root/tools/swift/check-xcframework.sh" "$artifact"

archive="$output_dir/WebAuthnBridge.xcframework.zip"
ditto --norsrc --noextattr --noqtn --noacl -c -k --keepParent "$artifact" "$archive"
if unzip -Z1 "$archive" | grep -E '(^|/)(__MACOSX|\.DS_Store|\._)' >/dev/null; then
  echo "Release archive contains macOS metadata sidecars." >&2
  exit 1
fi
checksum="$(swift package compute-checksum "$archive")"
printf '%s\n' "$checksum" > "$output_dir/WebAuthnBridge.xcframework.zip.sha256"
"$repo_root/tools/swift/render-release-package.sh" \
  "$version" \
  "$checksum" \
  "$output_dir/Package.swift"
manifest_validation_root="$temporary/ManifestValidation"
mkdir -p "$manifest_validation_root"
cp "$output_dir/Package.swift" "$manifest_validation_root/Package.swift"
ln -s "$repo_root/swift" "$manifest_validation_root/swift"
(cd "$manifest_validation_root" && swift package dump-package >/dev/null)

echo "Prepared Swift release artifact and manifest for v$version."
