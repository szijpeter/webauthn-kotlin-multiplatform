#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 --local <package-path> | --release <released-version>" >&2
}

if [[ $# -ne 2 ]]; then
  usage
  exit 2
fi
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "The external Swift package consumer check requires macOS." >&2
  exit 1
fi

mode="$1"
value="$2"
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
case "$mode" in
  --local)
    package_path="$(cd "$value" && pwd)"
    package_path_json="$(python3 -c 'import json, sys; print(json.dumps(sys.argv[1]))' "$package_path")"
    package_reference="    path: $package_path_json"
    consumer_label="local package"
    ;;
  --release)
    version="$value"
    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
      echo "Invalid released version: $version" >&2
      exit 1
    fi
    package_reference="    url: https://github.com/szijpeter/webauthn-kotlin-multiplatform.git
    exactVersion: \"$version\""
    consumer_label="released package $version"
    ;;
  *)
    usage
    exit 2
    ;;
esac

expected_xcode_version="${WEBAUTHN_EXPECTED_XCODE_VERSION:-26.6}"
actual_xcode_version="$(xcodebuild -version | awk 'NR == 1 { print $2 }')"
if [[ "$actual_xcode_version" != "$expected_xcode_version" ]]; then
  echo "Expected Xcode $expected_xcode_version, found $actual_xcode_version." >&2
  exit 1
fi

if [[ -n "${WEBAUTHN_SWIFT_CONSUMER_WORKDIR:-}" ]]; then
  temporary="$WEBAUTHN_SWIFT_CONSUMER_WORKDIR"
  mkdir -p "$temporary"
else
  temporary="$(mktemp -d "${TMPDIR:-/tmp}/webauthn-swift-consumer.XXXXXX")"
  trap 'rm -rf "$temporary"' EXIT
fi
mkdir -p "$temporary/Sources/BaseConsumer" "$temporary/Sources/FlowConsumer"
cat > "$temporary/project.yml" <<EOF
name: SwiftPackageConsumers
options:
  deploymentTarget:
    iOS: "16.0"
packages:
  WebAuthn:
$package_reference
targets:
  BaseConsumer:
    type: framework
    platform: iOS
    sources: [Sources/BaseConsumer]
    dependencies:
      - package: WebAuthn
        product: WebAuthn
    settings:
      base:
        SWIFT_VERSION: "6.0"
        CODE_SIGNING_ALLOWED: NO
  FlowConsumer:
    type: framework
    platform: iOS
    sources: [Sources/FlowConsumer]
    dependencies:
      - package: WebAuthn
        product: WebAuthn
      - package: WebAuthn
        product: WebAuthnFlow
    settings:
      base:
        SWIFT_VERSION: "6.0"
        CODE_SIGNING_ALLOWED: NO
schemes:
  SwiftPackageConsumers:
    build:
      targets:
        BaseConsumer: all
        FlowConsumer: all
EOF
cat > "$temporary/Sources/BaseConsumer/Consumer.swift" <<'EOF'
import UIKit
import WebAuthn

/// UIKit consumer that requires only the base package product.
@MainActor
public final class UIKitPasskeyOwner {
    public let client: PasskeyClient

    public init(window: UIWindow) {
        client = PasskeyClient(presentationAnchorProvider: { [weak window] in window })
    }
}
EOF
cat > "$temporary/Sources/FlowConsumer/Consumer.swift" <<'EOF'
import SwiftUI
import WebAuthn
import WebAuthnFlow

/// SwiftUI consumer that explicitly opts into the ceremony-flow product.
@MainActor
public struct PasskeyFlowConsumerView: View {
    private let flow: PasskeyFlow

    public init(client: any PasskeyClientProtocol) {
        flow = PasskeyFlow(client: client)
    }

    public var body: some View {
        Text("Passkey flow ready")
    }
}
EOF

expected_xcodegen_version="$(tr -d '[:space:]' < "$repo_root/sample/swift-passkey/.xcodegen-version")"
actual_xcodegen_version="$(xcodegen --version | awk '{ print $2 }')"
if [[ "$actual_xcodegen_version" != "$expected_xcodegen_version" ]]; then
  echo "Expected XcodeGen $expected_xcodegen_version, found $actual_xcodegen_version." >&2
  exit 1
fi
xcodegen generate --spec "$temporary/project.yml" --project "$temporary" --quiet

if [[ "${WEBAUTHN_SWIFT_CONSUMER_GENERATE_ONLY:-false}" == "true" ]]; then
  echo "Prepared clean package consumers at $temporary."
  exit 0
fi

xcodebuild \
  -quiet \
  -project "$temporary/SwiftPackageConsumers.xcodeproj" \
  -scheme SwiftPackageConsumers \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath "$temporary/DerivedData" \
  ARCHS=arm64 \
  VALID_ARCHS=arm64 \
  EXCLUDED_ARCHS=x86_64 \
  CODE_SIGNING_ALLOWED=NO \
  SWIFT_TREAT_WARNINGS_AS_ERRORS=YES \
  GCC_TREAT_WARNINGS_AS_ERRORS=YES \
  build

echo "Clean base-only UIKit and flow-enabled SwiftUI consumers compiled the $consumer_label."
