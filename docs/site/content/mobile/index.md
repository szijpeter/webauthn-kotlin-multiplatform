# Choose your mobile path

The recommended integration keeps ceremony orchestration and network transport in shared Kotlin, while Android and iOS own their platform prompt, application identity, and lifecycle boundary.

## Recommended stack

| Layer | Recommended artifact | Why it exists |
| --- | --- | --- |
| Shared ceremony | `webauthn-client-flow` | Coordinates start → prompt → finish and exposes typed outcomes |
| Shared transport | `webauthn-client-ktor-kotlinx` | Implements the default JSON/Ktor endpoint contract |
| Platform client | `webauthn-client-defaults` | Constructs the supported Android or iOS client with default codecs |
| Compose lifecycle | `webauthn-client-compose` | Remembers clients and flows safely across recomposition without owning product state |

Use lower-level modules only when you have a concrete reason to replace the default codec, transport, or platform bridge. The [artifact catalog](../reference/modules.md) describes those seams.

## Pick the route that matches your app

### Compose Multiplatform

Start with [Mobile quickstart](quickstart.md), then use [`rememberPasskeyClient`](compose.md) at a stable composition boundary. Your screen owns UI state; the library owns ceremony coordination.

### Native Android UI

Construct `defaultPasskeyClient(context)` with an Activity-capable host context, then invoke it from a lifecycle-aware coroutine. Continue with [Android integration](android.md).

### Native SwiftUI or UIKit

The native `WebAuthn` facade is implemented but not yet released. Use the repository sample for development
and qualification; do not point Swift Package Manager at an existing Kotlin-only release tag. Once the guide
shows a verified install version, construct `PasskeyClient` with a late-bound presentation-anchor provider and
use Swift-owned values and typed errors. Continue with the [native Swift package guide](swift.md) and
[iOS platform setup](ios.md).

### Compose Multiplatform on iOS

Keep shared ceremony orchestration in Kotlin and use the committed Compose iOS host when the application is
already multiplatform. Continue with [Compose Multiplatform](compose.md) and [iOS platform setup](ios.md).

## What the library does—and does not do

The mobile modules encode and decode WebAuthn payloads, invoke platform credential APIs, classify outcomes, and coordinate calls to your backend. They do not provision your relying-party domain, configure app-to-site association, choose an account model, or turn the client into a trusted verifier.

!!! warning "A successful build is not a successful ceremony"
    Android provider availability, iOS entitlements, signing identity, RP association, device security, and account state are runtime prerequisites. Use the [production checklist](production.md) before claiming readiness.

## Next steps

Choose the next task that matches your current stage:

- **Integrate the first ceremony:** follow the [mobile quickstart](quickstart.md).
- **Run the client and server together:** use the [full mobile + backend sample](full-stack.md).
- **Connect the signed apps to your relying party:** configure [RP IDs, origins, and app association](../concepts/origins.md).
- **Design deliberate UI states:** map the [typed result and error model](../reference/results.md) into your product.
