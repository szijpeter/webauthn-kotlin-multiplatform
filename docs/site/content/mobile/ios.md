# iOS platform integration

The iOS client reaches Authentication Services through the shared Kotlin implementation. Native applications
can consume the versioned [Swift package](swift.md); Compose applications can use the Kotlin APIs directly.
Both routes share protocol mapping, platform-ceremony behavior, and typed outcome semantics. Their PRF crypto
backends are platform-native implementations kept aligned by shared behavioral contracts and test vectors. The
published targets and minimums are listed in the generated [platform support matrix](../reference/platform-support.md).
A successful ceremony still depends on Associated Domains, the signed application identifier, presentation
context, and physical-device behavior.

## Host responsibilities

1. Enable the `webcredentials` Associated Domains capability for the relying-party domain.
2. Serve a matching `apple-app-site-association` document over HTTPS.
3. Resolve a current presentation window immediately before each prompt; do not cache a stale scene window.
4. Use the native Swift facade or a deliberately narrow shared Kotlin facade; add its optional source-only flow
   product for reusable sequencing, and do not depend on the internal binary bridge.
5. Preserve task/coroutine cancellation and map typed outcomes into deliberate SwiftUI or UIKit state.

!!! note "Simulator versus device"
    Simulator compilation and unit tests are useful, but they do not prove entitlement, iCloud Keychain, account, or production association behavior. Complete the release gate on physical devices.

## Associated Domains

The RP domain must serve `/.well-known/apple-app-site-association` with the exact application identifier (`<TeamID>.<BundleID>`). The app entitlement, provisioning profile, installed binary, and live response must agree. Avoid redirects and verify the deployed response, not only its source template.

Inspect the relationship as deployed. A correct Xcode capability is insufficient if the signed binary contains a different entitlement, the distribution profile belongs to another application identifier, or a cached association response is stale. Repeat this check for development, internal distribution, TestFlight, and App Store identities that differ.

## Presentation and lifecycle

Authentication Services needs a valid window for the authorization UI. If your app has multiple scenes or delayed window creation, provide an anchor explicitly and resolve it at presentation time. Avoid caching a stale window across scene transitions.

## PRF availability

PRF support has a higher iOS requirement than the base client and must also pass a runtime capability check. Design an explicit fallback path; never assume an extension is available because the app compiled.

## Provider-backed verification

A release candidate should complete registration and authentication on a physical device with:

- the intended signed application and `webcredentials` entitlement;
- a device passcode and usable passkey account or keychain state;
- the production-like RP ID and live association response;
- a foreground scene with a resolvable presentation anchor;
- the same backend authorization, session, and origin policy planned for release.

Record the OS version, device class, distribution identity, account state, RP ID, and tested result. One successful configuration is evidence for that configuration, not every supported device and account combination.

## Common iOS failures

| Symptom | First evidence to inspect | Likely boundary |
| --- | --- | --- |
| RP ID or domain rejected | Signed app identifier and live association response | App association |
| Prompt has no presentation anchor | Foreground scene, current window, and anchor provider | Host lifecycle |
| Simulator succeeds but device fails | Entitlement, provisioning profile, account, and keychain state | Distribution/runtime setup |
| No matching passkey appears | RP ID, account/provider state, and authentication allow-list | Credential discovery |
| User cancellation appears as an error | `PasskeyClientError.UserCancelled` mapping and UI transition | Product behavior |

Use the [native Swift sample](../guides/samples/swift-passkey.md) for the Swift package or the
[Compose iOS host](../guides/samples/compose-passkey-ios.md) for shared Kotlin UI.
