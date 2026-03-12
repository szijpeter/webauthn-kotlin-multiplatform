# webauthn-server-core-jvm

Audience: JVM backends that need typed registration/authentication ceremony services plus store contracts.

Use this module when you want WebAuthn ceremony orchestration without being tied to a specific web framework.

```kotlin
import dev.webauthn.server.AuthenticationService
import dev.webauthn.server.InMemoryChallengeStore
import dev.webauthn.server.InMemoryCredentialStore
import dev.webauthn.server.InMemoryUserAccountStore
import dev.webauthn.server.RegistrationService
import dev.webauthn.server.crypto.JvmRpIdHasher
import dev.webauthn.server.crypto.JvmSignatureVerifier
import dev.webauthn.server.crypto.StrictAttestationVerifier

val challengeStore = InMemoryChallengeStore()
val credentialStore = InMemoryCredentialStore()
val userStore = InMemoryUserAccountStore()

val registrationService = RegistrationService(
    challengeStore = challengeStore,
    credentialStore = credentialStore,
    userAccountStore = userStore,
    attestationVerifier = StrictAttestationVerifier(),
    rpIdHasher = JvmRpIdHasher(),
)

val authenticationService = AuthenticationService(
    challengeStore = challengeStore,
    credentialStore = credentialStore,
    userAccountStore = userStore,
    signatureVerifier = JvmSignatureVerifier(),
    rpIdHasher = JvmRpIdHasher(),
)
```

Choose this when you want services and store contracts but prefer to keep HTTP adapters optional.

Status: beta, production-leaning ceremony orchestration.
