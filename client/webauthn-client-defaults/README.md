# webauthn-client-defaults

Batteries-included platform-client composition over the same replaceable seams exposed by the lower
level modules.

## What it provides

- `defaultPasskeyClient(context)` on Android, composed with `KotlinxWebAuthnJsonCodec`.
- `defaultPasskeyClient()` on iOS, composed with AuthenticationServices.
- Android codec override through `DefaultPasskeyClientConfiguration`.
- iOS presentation-anchor override through `PasskeyPresentationAnchorProvider`.

This module deliberately selects `webauthn-json-kotlinx` for the recommended Android path. It does
not make Kotlinx a dependency of `webauthn-client-platform`, `webauthn-client-json-core`, or the
neutral Ktor adapter.

## When to use

Use this module for the shortest supported Android/iOS setup. Depend on `webauthn-client-platform`
directly when your application must own every codec/platform construction choice or must remain free
of the default Kotlinx implementation.

## Android

<!-- doc-example: id=client-webauthn-client-defaults-readme-kotlin-1; owner=source; verify=platform-compile; audience=consumer; source=documentation/examples/src/androidMain/kotlin/dev/webauthn/documentation/examples/DefaultAndroidClientExample.kt#default-android-client -->
```kotlin
import android.content.Context
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.defaults.defaultPasskeyClient
import dev.webauthn.json.WebAuthnJsonCodec

fun recommendedAndroidClient(context: Context): PasskeyClient = defaultPasskeyClient(context)

fun customCodecAndroidClient(
    context: Context,
    codec: WebAuthnJsonCodec,
): PasskeyClient = defaultPasskeyClient(context) {
    this.codec = codec
}
```

The default factory uses lifecycle-aware prompt-context resolution. If the client is retained across
activity recreation, ensure the application lifecycle callbacks can observe the current resumed
activity; use the platform module's explicit context-provider constructor for unusual host ownership.
The Android host must also include a Credential Manager provider, normally
`androidx.credentials:credentials-play-services-auth`; the defaults artifact does not select a
provider runtime for the application.

## iOS

<!-- doc-example: id=client-webauthn-client-defaults-readme-kotlin-2; owner=source; verify=platform-compile; audience=consumer; source=documentation/examples/src/iosMain/kotlin/dev/webauthn/documentation/examples/DefaultIosClientExample.kt#default-ios-client -->
```kotlin
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.defaults.defaultPasskeyClient
import dev.webauthn.client.ios.PasskeyPresentationAnchorProvider

fun recommendedIosClient(): PasskeyClient = defaultPasskeyClient()

fun anchoredIosClient(
    presentationAnchorProvider: PasskeyPresentationAnchorProvider,
): PasskeyClient = defaultPasskeyClient(presentationAnchorProvider)
```

Supply an anchor provider when the system prompt must be attached to application-owned window
selection. The no-argument factory uses the platform module's default lookup policy.

## How it fits in the system

<!-- doc-example: id=client-webauthn-client-defaults-readme-mermaid-1; owner=illustrative; verify=illustrative; audience=consumer; reason=Diagram is rendered by the Markdown host -->
```mermaid
flowchart TB
    APP["Application"] --> DEFAULTS["webauthn-client-defaults"]
    DEFAULTS --> PLATFORM["webauthn-client-platform"]
    DEFAULTS --> JSON["webauthn-json-kotlinx<br/>(Android default)"]
    PLATFORM --> CORE["webauthn-client-core"]
```

## Pitfalls and limits

- A custom Android codec changes response/options serialization only; it does not change backend
  transport contracts.
- Choosing this artifact intentionally resolves the Kotlinx implementation. Use the lower-level
  platform artifact for dependency-pure replacement.
- The factory does not create `PasskeyFlow`, a backend, a Ktor engine, or application UI state.

## Status

Beta. Configuration behavior has common tests, published-consumer compilation covers Android and
iOS factories, and platform lifecycle/runtime behavior remains covered by `webauthn-client-platform`.
