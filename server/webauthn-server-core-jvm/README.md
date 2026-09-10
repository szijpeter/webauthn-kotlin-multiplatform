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

<!-- diagram: server-webauthn-server-core-jvm-readme-1 -->
<picture>
  <source media="(max-width: 720px) and (prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/server-webauthn-server-core-jvm-readme-1-mobile-dark.svg">
  <source media="(max-width: 720px)" srcset="../../docs/diagrams/assets/server-webauthn-server-core-jvm-readme-1-mobile-light.svg">
  <source media="(prefers-color-scheme: dark)" srcset="../../docs/diagrams/assets/server-webauthn-server-core-jvm-readme-1-desktop-dark.svg">
  <img alt="server-core-jvm · How it fits. Selected responsibilities and relationships; see the surrounding module guide for scope and limits." src="../../docs/diagrams/assets/server-webauthn-server-core-jvm-readme-1-desktop-light.svg" width="960" loading="lazy">
</picture>
<details>
<summary>Diagram text: server-core-jvm · How it fits</summary>
<p>Selected responsibilities and relationships; see the surrounding module guide for scope and limits.</p>
<p>Nodes: webauthn-server-ktor (optional); webauthn-server-core-jvm; webauthn-core; webauthn-protocol; webauthn-json-api — codec interface; webauthn-json-kotlinx — KotlinxWebAuthnJsonCodec; webauthn-server-jvm-crypto or custom crypto-api implementation; Challenge, credential, and account store contracts; In-memory or Exposed store implementations.</p>
<p>1. webauthn-server-ktor (optional) → webauthn-server-core-jvm.</p>
<p>2. webauthn-server-core-jvm → webauthn-core.</p>
<p>3. webauthn-server-core-jvm → webauthn-protocol.</p>
<p>4. webauthn-server-core-jvm → webauthn-json-api codec interface.</p>
<p>5. webauthn-json-kotlinx KotlinxWebAuthnJsonCodec → webauthn-json-api codec interface.</p>
<p>6. webauthn-server-core-jvm → webauthn-server-jvm-crypto or custom crypto-api implementation.</p>
<p>7. webauthn-server-core-jvm → Challenge, credential, and account store contracts.</p>
<p>8. In-memory or Exposed store implementations → Challenge, credential, and account store contracts.</p>
</details>
<!-- /diagram -->

## Pitfalls and limits

- Services depend on correctly implemented store semantics (challenge expiry, credential lookup, counter updates).
- Registration and authentication keep shared fail-fast origin/session handling internally, so callers should expect matching origin-mismatch behavior across both ceremony types.
- `RegistrationService.finish()` now returns a typed validation error when the user disappears between start and finish instead of throwing from the user store lookup.
- Authentication challenge sessions allow nullable `userName` for discoverable ceremonies, while named-mode finish still enforces credential ownership for the resolved account.
- Finish requests carry only a byte-preserving `RawRegistrationResponse` or `RawAuthenticationResponse`. The service derives `CollectedClientData` from that response's signed `clientDataJSON` through the injected neutral decoder, so custom transports cannot supply conflicting challenge, origin, or type values.
- This module does not define your HTTP contract by itself.

## Status

Beta ceremony orchestration with contract-tested behavior.
