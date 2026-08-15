@file:Suppress("UndocumentedPublicFunction", "UndocumentedPublicProperty")

package dev.webauthn.client

import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawRegistrationResponse

/** Platform bridge contract implemented by target-specific modules. */
public interface PasskeyPlatformBridge {
    /** Returns byte-preserving registration output for shared protocol interpretation. */
    public suspend fun createCredential(options: PublicKeyCredentialCreationOptions): RawRegistrationResponse

    /** Returns byte-preserving assertion output for shared protocol interpretation. */
    public suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): RawAuthenticationResponse

    public fun mapPlatformError(throwable: Throwable): PasskeyClientError

    public suspend fun capabilities(): PasskeyCapabilities = PasskeyCapabilities()
}
