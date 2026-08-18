package dev.webauthn.client.defaults

import dev.webauthn.json.WebAuthnJsonCodec
import dev.webauthn.serialization.KotlinxWebAuthnJsonCodec

/** Replaceable pieces used by the batteries-included platform-client factories. */
public class DefaultPasskeyClientConfiguration {
    /** Codec used by the Android Credential Manager implementation. */
    public var codec: WebAuthnJsonCodec = KotlinxWebAuthnJsonCodec()
}
