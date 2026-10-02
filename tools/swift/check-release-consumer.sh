#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <released-version>" >&2
  exit 2
fi
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "The external Swift release smoke check requires macOS." >&2
  exit 1
fi

version="$1"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid released version: $version" >&2
  exit 1
fi
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
expected_xcode_version="${WEBAUTHN_EXPECTED_XCODE_VERSION:-26.6}"
actual_xcode_version="$(xcodebuild -version | awk 'NR == 1 { print $2 }')"
if [[ "$actual_xcode_version" != "$expected_xcode_version" ]]; then
  echo "Expected Xcode $expected_xcode_version, found $actual_xcode_version." >&2
  exit 1
fi

temporary="$(mktemp -d "${TMPDIR:-/tmp}/webauthn-swift-consumer.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/Sources"
cat > "$temporary/project.yml" <<EOF
name: SwiftReleaseConsumer
options:
  deploymentTarget:
    iOS: "16.0"
packages:
  WebAuthn:
    url: https://github.com/szijpeter/webauthn-kotlin-multiplatform.git
    exactVersion: "$version"
targets:
  SwiftReleaseConsumer:
    type: framework
    platform: iOS
    sources: [Sources]
    dependencies:
      - package: WebAuthn
        product: WebAuthn
      - package: WebAuthn
        product: WebAuthnFlow
    settings:
      base:
        SWIFT_VERSION: "6.0"
        CODE_SIGNING_ALLOWED: NO
EOF
cat > "$temporary/Sources/Consumer.swift" <<'EOF'
import Foundation
import WebAuthn
import WebAuthnFlow

@MainActor
public func makePasskeyClient() -> PasskeyClient {
    PasskeyClient(presentationAnchorProvider: { nil })
}

@MainActor
public func makePasskeyFlow(client: any PasskeyClientProtocol) -> PasskeyFlow {
    PasskeyFlow(client: client)
}
EOF

expected_xcodegen_version="$(tr -d '[:space:]' < "$repo_root/sample/swift-passkey/.xcodegen-version")"
actual_xcodegen_version="$(xcodegen --version | awk '{ print $2 }')"
if [[ "$actual_xcodegen_version" != "$expected_xcodegen_version" ]]; then
  echo "Expected XcodeGen $expected_xcodegen_version, found $actual_xcodegen_version." >&2
  exit 1
fi
xcodegen generate --spec "$temporary/project.yml" --project "$temporary" --quiet
xcodebuild \
  -quiet \
  -project "$temporary/SwiftReleaseConsumer.xcodeproj" \
  -scheme SwiftReleaseConsumer \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath "$temporary/DerivedData" \
  ARCHS=arm64 \
  VALID_ARCHS=arm64 \
  EXCLUDED_ARCHS=x86_64 \
  CODE_SIGNING_ALLOWED=NO \
  SWIFT_TREAT_WARNINGS_AS_ERRORS=YES \
  build

echo "Clean external iOS consumer resolved and compiled WebAuthn and WebAuthnFlow $version."
