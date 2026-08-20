# webauthn-json-api

Audience: applications and adapters that need a replaceable JSON boundary for WebAuthn ceremony values.

## What it provides

- `WebAuthnJsonCodec`, a JSON-library-neutral codec interface
- Typed creation and request options plus raw credential response conversion
- Signed `clientDataJSON` decoding without exposing a serialization-library API

## When to use

Depend on this module when your application should select its own JSON codec.
Use `webauthn-serialization-kotlinx` for the provided kotlinx implementation.

## Status

Beta, public codec abstraction.
