# WebAuthn for native Swift

`WebAuthn` is the native Swift facade for the shared passkey client. It presents Swift-owned values,
structured concurrency, typed errors, late-bound presentation anchors, capability reporting, and an
optional PRF-derived crypto session without exposing generated Kotlin types to application code.

## Requirements

- iOS 16 or newer
- Xcode 16 or newer with Swift 6 package support
- arm64 iOS devices or arm64 iOS simulators
- a correctly signed `webcredentials` Associated Domains entitlement and matching relying-party association

The binary bridge does not include an `iosX64` slice because the full optional crypto dependency graph does
not publish that target. Intel simulator hosts are therefore unsupported; physical iOS devices remain arm64.

<!-- public-site:swift-release:start -->
## Release status

**The native Swift package has not been released yet.** Existing coordinated release tags publish the Kotlin
artifacts only and do not contain the remote Swift manifest and XCFramework assets required by Swift Package
Manager. Do not use an existing Kotlin version as a Swift dependency. The root `Package.swift` is for local
repository development and release qualification until the first coordinated Swift release is published.
<!-- public-site:swift-release:end -->

## Create the client

Resolve the active window immediately before a ceremony. This avoids keeping a stale presentation anchor
when scenes activate, disconnect, or change key-window ownership.

<!-- doc-example: id=swift-readme-swift-1; owner=illustrative; verify=illustrative; audience=consumer; reason=Host window lookup depends on application scene ownership -->
```swift
import UIKit
import WebAuthn

@MainActor
let passkeys = PasskeyClient {
    UIApplication.shared.connectedScenes
        .compactMap { $0 as? UIWindowScene }
        .filter { $0.activationState == .foregroundActive }
        .flatMap(\.windows)
        .first(where: \.isKeyWindow)
}
```

Use the convenience `PasskeyClient(presentationAnchor:)` initializer only when the window identity is truly
stable for the client's lifetime.

## Registration and authentication

The API accepts and returns UTF-8 JSON as `Data`. The shared Kotlin codec remains the single source of truth
for WebAuthn JSON mapping; the Swift facade does not reimplement protocol models.

<!-- doc-example: id=swift-readme-swift-2; owner=illustrative; verify=illustrative; audience=consumer; reason=Backend methods are application-owned integration points -->
```swift
let creationOptions = try await backend.startRegistration()
let credentialResponse = try await passkeys.createCredential(optionsJSON: creationOptions)
try await backend.finishRegistration(responseJSON: credentialResponse)

let requestOptions = try await backend.startAuthentication()
let assertionResponse = try await passkeys.getAssertion(optionsJSON: requestOptions)
try await backend.finishAuthentication(responseJSON: assertionResponse)
```

The relying-party backend must validate challenge, origin, ceremony type, authenticator data, signature,
counter, and policy. A successful platform prompt alone is not an authenticated application session.

`PasskeyClientError` preserves cancellation, missing-credential, invalid-options, platform, codec, concurrency,
presentation, bridge-contract, and PRF-session failures as distinct Swift cases. Do not convert
`CancellationError` into a domain failure; let structured-concurrency cancellation propagate.

## Capabilities

Capability snapshots are extensible. Missing identifiers resolve to `.unknown`, not `.unsupported`, so a
new platform capability can cross the bridge without breaking older Swift clients.

<!-- doc-example: id=swift-readme-swift-3; owner=illustrative; verify=illustrative; audience=consumer; reason=Capability branch omits application-specific fallback UI -->
```swift
let capabilities = try await passkeys.capabilities()
if capabilities.supports(.prf) {
    // Offer PRF-backed application encryption.
}
```

## PRF-derived application crypto

The base package supports iOS 16+, while AuthenticationServices PRF execution requires iOS 18+ and a
`.supported` runtime capability result. Keep a non-PRF fallback for older or unsupported environments.

The caller owns the PRF inputs and should generate them with a cryptographically secure random source. A
successful assertion returns the WebAuthn response, raw PRF outputs, and an actor-isolated AES-256-GCM
session whose derived key remains inside actor-isolated Swift memory. HKDF-SHA-256 and AES-GCM use
CryptoKit. Deterministic derivation vectors keep the independent Kotlin and Swift crypto backends aligned in CI.

<!-- doc-example: id=swift-readme-swift-4; owner=illustrative; verify=illustrative; audience=consumer; reason=Backend and secret values are application-owned integration points -->
```swift
let prf = PrfCryptoClient(passkeyClient: passkeys)
let result = try await prf.authenticate(
    optionsJSON: requestOptions,
    firstSalt: callerOwnedRandomSalt,
    context: "com.example.account-vault"
)

do {
    try await backend.finishAuthentication(responseJSON: result.responseJSON)
    let sealed = try await result.session.encrypt(secret, associatedData: accountID)
    let opened = try await result.session.decrypt(sealed)
    await result.session.clear()
} catch {
    await result.session.clear()
    throw error
}
```

Do not use the session as proof of authentication until the backend accepts `responseJSON`. Clear it when
verification fails, when signing out, and when the protected workflow ends. The session is in-memory only;
persist the complete ciphertext payload, never the derived key.

## Privacy and distribution

The XCFramework includes a privacy manifest declaring no tracking, collected data, tracking domains, or
required-reason API use. Release automation checks a reviewed set of known required-reason API symbols and
fails when those categories need review; it is not an exhaustive binary privacy analysis. The generated Xcode
privacy report and the application's complete dependency review remain authoritative for release decisions.

Every framework slice also carries the project license and the complete
[`THIRD_PARTY_NOTICES.txt`](THIRD_PARTY_NOTICES.txt) for code linked into the static binary. Artifact checks
fail if either legal file is missing or stale.

The first and subsequent Swift package releases will use the coordinated Kotlin artifact version.
`publish-and-release` builds and checks the static XCFramework, uploads it with a SHA-256 checksum, and tags a
generated package manifest that references that immutable asset. A Maven-only `publish-only` run does not
create a Swift package release; `finalize-release` can resume GitHub finalization from the original retained
inputs without republishing Maven artifacts. `publish-and-release` remains blocked until the maintainer records
physical-iPhone qualification for the exact source commit and supplies its stable HTTPS evidence URL.

## Compatibility controls

The Swift surface is protected by:

- unit and UI tests in strict Swift 6 mode;
- a compiler-generated public `.swiftinterface` baseline;
- a machine-readable Kotlin/bridge/Swift semantic parity contract;
- complete declared Kotlin/bridge/Swift error-code mapping, with explicit exceptions;
- Release-mode library-evolution compilation;
- XCFramework slice, legal/privacy metadata, checksum, and build-path hygiene checks.

See [Swift API parity](API_PARITY.md) for the maintainer workflow and
[the native Swift sample](../sample/swift-passkey/README.md) for a runnable end-to-end host.
