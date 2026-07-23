package dev.webauthn.documentation.examples

// docs-region server-core-services
import dev.webauthn.server.AuthenticationService
import dev.webauthn.server.InMemoryChallengeStore
import dev.webauthn.server.InMemoryCredentialStore
import dev.webauthn.server.InMemoryUserAccountStore
import dev.webauthn.server.RegistrationService
import dev.webauthn.server.crypto.JvmRpIdHasher
import dev.webauthn.server.crypto.JvmSignatureVerifier
import dev.webauthn.server.crypto.StrictAttestationVerifier
import dev.webauthn.model.ExperimentalWebAuthnL3Api

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
    )

    val authenticationService = AuthenticationService(
        challengeStore = challengeStore,
        credentialStore = credentialStore,
        userAccountStore = userStore,
        signatureVerifier = JvmSignatureVerifier(),
        rpIdHasher = JvmRpIdHasher(),
    )
    return PasskeyServices(registrationService, authenticationService)
}
// docs-endregion server-core-services
