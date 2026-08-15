# webauthn-client-defaults

Small batteries-included composition for the recommended platform client path.

It selects the Kotlinx codec and exports the Android/iOS platform implementations, while keeping
Ktor transport and high-level flow orchestration opt-in. Android callers can override the codec
through `defaultPasskeyClient(context) { codec = myCodec }`; dependency-pure alternatives should
compose `webauthn-client-platform` with a chosen codec directly.

## Status

Beta, default composition built from the same public interfaces used by custom integrations.
