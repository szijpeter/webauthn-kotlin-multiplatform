# Native Swift passkey sample

This SwiftUI app exercises the public `WebAuthn` Swift package against the repository's default four-route
backend contract. It demonstrates registration, authentication, capability reporting, typed UI states, and
a PRF-derived AES-GCM session without importing generated Kotlin types in application code.

## What it proves

- start → platform prompt → finish sequencing for registration and authentication;
- backend verification before opening an authenticated route;
- late resolution of the foreground presentation window;
- typed cancellation, rejection, platform, codec, concurrency, and internal failures;
- application-owned client fakes through the public `PasskeyClientProtocol`;
- capability-gated PRF authentication with caller-owned random input;
- clear-on-rejection, clear-on-sign-out, and explicit crypto-session lifecycle;
- safe diagnostics that log phases and metadata rather than credential response bodies.

A simulator run proves compilation, routing, and deterministic tests. It does not prove a signed entitlement,
live association response, iCloud Keychain state, or physical-device ceremony.

## Generate and open

Requirements: macOS, Xcode 16 or newer, Java 21, and XcodeGen 2.45.3.

<!-- doc-example: id=sample-swift-passkey-bash-1; owner=markdown; verify=syntax; audience=contributor -->
```bash
./gradlew :client:webauthn-client-swift-bridge:assembleWebAuthnBridgeReleaseXCFramework --stacktrace
cd sample/swift-passkey
xcodegen generate
open WebAuthnSwiftDemo.xcodeproj
```

The project file is committed for immediate use; `project.yml` remains the editable source of project
settings. The pinned generator version is recorded in `.xcodegen-version`. Regenerate after changing
targets, sources, or build settings and run `tools/swift/check-xcodegen.sh` to prove that the committed
project is current.

## Backend configuration

The committed Info.plist expands these build settings into runtime configuration:

| Key | Default | Purpose |
| --- | --- | --- |
| `WEBAUTHN_DEMO_ENDPOINT` | `http://127.0.0.1:8080` | Default-contract backend base URL |
| `WEBAUTHN_DEMO_RP_ID` | `localhost` | Relying-party identifier |
| `WEBAUTHN_DEMO_ORIGIN` | `https://localhost` | Expected WebAuthn origin |
| `WEBAUTHN_DEMO_USER_ID` | `42` | Raw UTF-8 stable sample identifier; encoded to unpadded base64url for `userHandle` |
| `WEBAUTHN_DEMO_USER_NAME` | `Zaphod Beeblebrox` | Display name used by registration |

Start the repository backend separately, or replace the values with a reachable HTTPS environment. A
physical iPhone cannot reach a Mac service through the phone's own `127.0.0.1`; use an approved reachable
host and keep its RP ID, origin, TLS, and association configuration aligned.

Treat `WEBAUTHN_DEMO_USER_ID` as raw text, not pre-encoded base64url. The sample performs the required
RFC 4648 URL-safe encoding exactly once before calling the backend.

The base passkey flow supports iOS 16+. The optional PRF screen requires iOS 18+ and stays disabled unless
the runtime reports PRF support.

## Associated Domains

For a real ceremony, change the sample bundle identifier, select a development team, and add the
`webcredentials:<rp-domain>` Associated Domains capability. The RP domain must serve a matching
`/.well-known/apple-app-site-association` file for the exact signed application identifier. Verify the
entitlement in the built app and the live HTTPS response before treating device behavior as library evidence.

## Tests

The repository check selects an available iPhone simulator and runs bridge tests, package tests (including a
consumer-style fake of `PasskeyClientProtocol`), sample unit tests, a launch UI test, built-app configuration
inspection, Release-mode library evolution, public API compatibility, semantic parity, and binary artifact
inspection:

<!-- doc-example: id=sample-swift-passkey-bash-2; owner=markdown; verify=syntax; audience=contributor -->
```bash
tools/swift/ci-check.sh
```

The same check is blocking in pull-request CI. Physical-device registration and authentication remain a
separate release-evidence step because CI cannot validate signing, association caching, account state, or the
actual system prompt on a user's device.
