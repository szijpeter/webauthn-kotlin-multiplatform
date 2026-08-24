# webauthn-server-core-jvm

Typed JVM ceremony services and store contracts for WebAuthn registration and authentication.

## What it provides

- `RegistrationService` and `AuthenticationService`
- Challenge, credential, and user-account store interfaces
- In-memory store implementations for development and testing
- Ceremony orchestration decoupled from web framework concerns
- Unified authentication start semantics:
  - `AuthenticationStartRequest.userName != null`: identified-account flow with populated `allowCredentials`
  - `AuthenticationStartRequest.userName == null`: discoverable flow with empty `allowCredentials`

## When to use

Use this when you want to implement WebAuthn server flows in Kotlin/JVM, with or without Ktor adapters.

## How to use

<!-- doc-example: id=server-webauthn-server-core-jvm-readme-kotlin-1; owner=source; verify=compile; audience=consumer; source=documentation/examples/src/jvmMain/kotlin/dev/webauthn/documentation/examples/ServerCoreExample.kt#server-core-services -->
```kotlin
import dev.webauthn.server.AuthenticationService
import dev.webauthn.server.InMemoryChallengeStore
import dev.webauthn.server.InMemoryCredentialStore
import dev.webauthn.server.InMemoryUserAccountStore
import dev.webauthn.server.RegistrationService
import dev.webauthn.server.crypto.JvmRpIdHasher
import dev.webauthn.server.crypto.JvmSignatureVerifier
import dev.webauthn.server.crypto.StrictAttestationVerifier
import dev.webauthn.model.ExperimentalWebAuthnL3Api
import dev.webauthn.serialization.KotlinxWebAuthnJsonCodec

/** Registration and authentication services sharing the same stores. */
data class PasskeyServices(
    val registration: RegistrationService,
    val authentication: AuthenticationService,
)

@OptIn(ExperimentalWebAuthnL3Api::class)
fun passkeyServices(): PasskeyServices {
    val challengeStore = InMemoryChallengeStore()
    val credentialStore = InMemoryCredentialStore()
    val userStore = InMemoryUserAccountStore()

    val registrationService = RegistrationService(
        challengeStore = challengeStore,
        credentialStore = credentialStore,
        userAccountStore = userStore,
        attestationVerifier = StrictAttestationVerifier(),
        rpIdHasher = JvmRpIdHasher(),
        clientDataDecoder = KotlinxWebAuthnJsonCodec(),
    )

    val authenticationService = AuthenticationService(
        challengeStore = challengeStore,
        credentialStore = credentialStore,
        userAccountStore = userStore,
        signatureVerifier = JvmSignatureVerifier(),
        rpIdHasher = JvmRpIdHasher(),
        clientDataDecoder = KotlinxWebAuthnJsonCodec(),
    )
    return PasskeyServices(registrationService, authenticationService)
}
```

Real-world scenario: run start/finish ceremonies in your backend service layer, then expose them via Ktor routes or your own HTTP transport.

## How it fits

<!-- doc-example: id=server-webauthn-server-core-jvm-readme-mermaid-1; owner=illustrative; verify=illustrative; audience=consumer; reason=Diagram is rendered by the Markdown host -->
```mermaid
flowchart LR
    KTOR["webauthn-server-ktor (optional)"] --> SVC["webauthn-server-core-jvm"]
    SVC --> CORE["webauthn-core"]
    SVC --> PROTOCOL["webauthn-protocol"]
    SVC --> JSON_API["webauthn-json-api<br/>codec interface"]
    JSON_KOTLINX["webauthn-json-kotlinx<br/>KotlinxWebAuthnJsonCodec"] --> JSON_API
    SVC --> CRYPTO["webauthn-server-jvm-crypto or custom crypto-api implementation"]
    SVC --> STORE["Challenge, credential, and account store contracts"]
    IMPLEMENTATION["In-memory or Exposed store implementations"] --> STORE
```

## Pitfalls and limits

- Services depend on correctly implemented store semantics (challenge expiry, credential lookup, counter updates).
- Registration and authentication keep shared fail-fast origin/session handling internally, so callers should expect matching origin-mismatch behavior across both ceremony types.
- `RegistrationService.finish()` now returns a typed validation error when the user disappears between start and finish instead of throwing from the user store lookup.
- Authentication challenge sessions allow nullable `userName` for discoverable ceremonies, while named-mode finish still enforces credential ownership for the resolved account.
- Finish requests carry only a byte-preserving `RawRegistrationResponse` or `RawAuthenticationResponse`. The service derives `CollectedClientData` from that response's signed `clientDataJSON` through the injected neutral decoder, so custom transports cannot supply conflicting challenge, origin, or type values.
- This module does not define your HTTP contract by itself.

## Status

Beta ceremony orchestration with contract-tested behavior.
