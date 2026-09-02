# webauthn-client-swift-bridge

Internal Kotlin/Native bridge used by the public `WebAuthn` Swift package.

This module deliberately exposes only a narrow, non-generic Objective-C/Swift boundary. Native Swift consumers should import the source facade from the repository's Swift package and must not depend on `WebAuthnBridge` directly.

The bridge owns no WebAuthn semantics. It delegates JSON decoding and encoding, passkey ceremonies,
capability reporting, and PRF request/result mapping to the existing Kotlin modules. The source-based
Swift facade derives and contains its PRF session key with CryptoKit, guarded by cross-language vectors.

The release XCFramework is static, includes privacy and legal notices in every slice, and is post-processed
to remove build-machine debug metadata. Release consumers receive it only through the checksum-pinned
`WebAuthn` Swift package manifest.

Supported Apple targets:

- iOS arm64 devices
- iOS arm64 simulators

Intel simulator support is not currently advertised; release validation covers arm64 devices and Apple
Silicon simulators.

Build the local binary with:

<!-- doc-example: id=client-webauthn-client-swift-bridge-readme-bash-1; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew :client:webauthn-client-swift-bridge:assembleWebAuthnBridgeReleaseXCFramework --stacktrace
```

Run `tools/swift/check-xcframework.sh` after assembly. Native Swift applications should follow
[`swift/README.md`](../../swift/README.md) and must not import this module directly.
