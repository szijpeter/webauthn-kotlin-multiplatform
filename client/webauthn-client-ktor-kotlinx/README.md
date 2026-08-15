# webauthn-client-ktor-kotlinx

Kotlinx Serialization implementation of the default Ktor passkey backend contract.

Use this only with the default `/webauthn/…` payload shape. Apps that use another JSON library or
backend contract should depend on `webauthn-client-ktor` and provide their own
`KtorPasskeyContractCodec` implementation.

## What it provides

- `KotlinxKtorPasskeyBackend` and `KotlinxKtorPasskeyContractCodec` for typed flow backends
- `RegistrationStartPayload` and `AuthenticationStartPayload` for the default request shape
- `KtorOriginMetadataProvider`, which fails closed on fetch or parse errors
