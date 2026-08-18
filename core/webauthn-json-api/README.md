# webauthn-json-api

Audience: applications and adapters that need a replaceable JSON boundary for WebAuthn ceremony values.

## What it provides

- `CollectedClientDataDecoder`, the narrow server-side signed-data boundary
- `WebAuthnJsonCodec`, a JSON-library-neutral codec interface that also implements that decoder
- Typed creation and request options plus raw credential response conversion
- Signed `clientDataJSON` decoding without exposing a serialization-library API

## When to use

Depend on this module when your application should select its own JSON codec.
Use `webauthn-json-kotlinx` for the provided kotlinx implementation.

## Status

Beta, public codec abstraction.
