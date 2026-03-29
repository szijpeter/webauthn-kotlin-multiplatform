# webauthn-client-core

Audience: teams building shared passkey client orchestration across Android/iOS with one typed API surface.

## What it provides

- `PasskeyClient` abstraction for `createCredential` and `getAssertion` ceremonies.
- `DefaultPasskeyClient` error-mapped orchestration over platform bridges.
- `PasskeyController` that coordinates start -> platform prompt -> finish flow with state updates.
- Shared result/error contracts (`PasskeyResult`, `PasskeyClientError`, `PasskeyFinishResult`).
- `PasskeyCapabilities` API for querying platform support for extensions and features.

```mermaid
flowchart TD
    Action["UI/User action"] --> Start["PasskeyController.start step<br/>serverClient.get*Options"]
    Start --> Platform["PasskeyClient.createCredential/getAssertion"]
    Platform --> Finish["serverClient.finish* (challenge echo + response)"]
    Finish --> State["PasskeyControllerState.Success / Failure"]
    State --> App["App state + navigation"]
```

## When to use

Use this module when you want one shared ceremony flow and typed error/state handling, while leaving platform API details to `webauthn-client-android` / `webauthn-client-ios`.

## How to use

A common setup wires `PasskeyController` in a shared ViewModel/service and reacts to `uiState` transitions.

```kotlin
import dev.webauthn.client.PasskeyController
import dev.webauthn.client.PasskeyControllerState
import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult

class AccountServerClient : PasskeyServerClient<String, String> {
    override suspend fun getRegisterOptions(params: String): ValidationResult<PublicKeyCredentialCreationOptions> {
        TODO("Call backend /registration/start")
    }

    override suspend fun finishRegister(
        params: String,
        response: RegistrationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult {
        TODO("Call backend /registration/finish")
    }

    override suspend fun getSignInOptions(params: String): ValidationResult<PublicKeyCredentialRequestOptions> {
        TODO("Call backend /authentication/start")
    }

    override suspend fun finishSignIn(
        params: String,
        response: AuthenticationResponse,
        challengeAsBase64Url: String,
    ): PasskeyFinishResult {
        TODO("Call backend /authentication/finish")
    }
}

suspend fun runSignIn(controller: PasskeyController<String, String>, userId: String) {
    controller.signIn(userId)
    when (val state = controller.uiState.value) {
        is PasskeyControllerState.Success -> {
            // Continue into authenticated app flow.
        }
        is PasskeyControllerState.Failure -> {
            // Render or log state.error.message.
        }
        else -> Unit
    }
}
```

### Capabilities API

Query platform support for extensions and features:

```kotlin
suspend fun inspectCapabilities(client: PasskeyClient) {
    val capabilities = client.capabilities()
    if (capabilities.supports(PasskeyCapability.Extension(WebAuthnExtension.Prf))) {
        // Platform supports PRF extension.
    }
    if (capabilities.supports(PasskeyCapability.Extension(WebAuthnExtension.LargeBlob))) {
        // Platform supports largeBlob extension.
    }
}
```

Available capabilities:
- `PasskeyCapability.Extension(WebAuthnExtension.Prf)` - HMAC secret extension (W3C prf)
- `PasskeyCapability.Extension(WebAuthnExtension.LargeBlob)` - Large blob storage extension
- `PasskeyCapability.PlatformFeature("securityKey")` - Cross-platform authenticator support
- `PasskeyCapability.Extension(WebAuthnExtension.Custom("example"))` - proprietary/draft extension identifier

`PasskeyCapabilities.supports(key)` is key-based; `supports(capability)` requires an exact capability match for that key (same variant/value). Duplicate keys are rejected at construction time.

Usage notes:

- `challengeAsBase64Url` is echoed client data; server must verify it against trusted challenge state.
- Reuse a single controller per screen/session scope to avoid overlapping ceremonies.
- Prefer mapping backend rejection into actionable UX rather than generic transport failures.
- `DefaultPasskeyClient` preserves coroutine cancellation (it is rethrown and never mapped to `PasskeyResult.Failure`), while deterministic invalid-options and platform failures are returned as `PasskeyResult.Failure`.
- `IllegalArgumentException` is mapped via the platform bridge so bridge-level domain classification/message (for example Android `InvalidOptions` RP-ID hints) is preserved.
- Platform-level "user canceled prompt" remains a domain error (`PasskeyClientError.UserCancelled`) when provided by platform bridge mapping.

## How it fits in the system

- Uses `webauthn-runtime-core` for shared coroutine-boundary cancellation/failure handling helpers.
- Foundation for `webauthn-client-compose`, `webauthn-client-json-core`, and platform client modules.
- Pairs naturally with `webauthn-network-ktor-client` for default backend contract integration.

## Limits

- No UI toolkit or navigation policy.
- No backend validation/crypto behavior.
- Platform bridge implementation is provided by target-specific modules.

## Status

Beta, shared orchestration layer for client passkey ceremonies.
