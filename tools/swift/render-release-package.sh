#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <version> <checksum> <output-file>" >&2
  exit 2
fi

version="$1"
checksum="$2"
output="$3"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid Swift package version: $version" >&2
  exit 1
fi
if [[ ! "$checksum" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Invalid Swift package checksum." >&2
  exit 1
fi

cat > "$output" <<EOF
// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "WebAuthn",
    platforms: [
        .iOS(.v16),
    ],
    products: [
        .library(name: "WebAuthn", targets: ["WebAuthn"]),
        .library(name: "WebAuthnFlow", targets: ["WebAuthnFlow"]),
    ],
    targets: [
        .binaryTarget(
            name: "WebAuthnBridge",
            url: "https://github.com/szijpeter/webauthn-kotlin-multiplatform/releases/download/v${version}/WebAuthnBridge.xcframework.zip",
            checksum: "${checksum}"
        ),
        .target(
            name: "WebAuthn",
            dependencies: ["WebAuthnBridge"],
            path: "swift/Sources/WebAuthn"
        ),
        .target(
            name: "WebAuthnFlow",
            dependencies: ["WebAuthn"],
            path: "swift/Sources/WebAuthnFlow"
        ),
        .testTarget(
            name: "WebAuthnTests",
            dependencies: ["WebAuthn"],
            path: "swift/Tests/WebAuthnTests"
        ),
        .testTarget(
            name: "WebAuthnFlowTests",
            dependencies: ["WebAuthnFlow", "WebAuthn"],
            path: "swift/Tests/WebAuthnFlowTests"
        ),
    ],
    swiftLanguageModes: [.v6]
)
EOF
