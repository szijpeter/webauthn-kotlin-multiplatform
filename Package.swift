// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "WebAuthn",
    platforms: [
        .iOS(.v16),
    ],
    products: [
        .library(name: "WebAuthn", targets: ["WebAuthn"]),
    ],
    targets: [
        // Release tags replace this local development path with the matching
        // checksum-pinned GitHub release URL.
        .binaryTarget(
            name: "WebAuthnBridge",
            path: "client/webauthn-client-swift-bridge/build/XCFrameworks/release/WebAuthnBridge.xcframework"
        ),
        .target(
            name: "WebAuthn",
            dependencies: ["WebAuthnBridge"],
            path: "swift/Sources/WebAuthn"
        ),
        .testTarget(
            name: "WebAuthnTests",
            dependencies: ["WebAuthn"],
            path: "swift/Tests/WebAuthnTests"
        ),
    ],
    swiftLanguageModes: [.v6]
)
