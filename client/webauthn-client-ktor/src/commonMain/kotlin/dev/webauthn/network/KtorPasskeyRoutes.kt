package dev.webauthn.network

/** Route configuration for a Ktor-based passkey backend contract. */
public data class KtorPasskeyRoutes(
    public val registerOptionsPath: String = "/webauthn/registration/start",
    public val registerFinishPath: String = "/webauthn/registration/finish",
    public val signInOptionsPath: String = "/webauthn/authentication/start",
    public val signInFinishPath: String = "/webauthn/authentication/finish",
)
