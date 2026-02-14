# WebAuthn L3 Validation Map

This file maps implemented validations to normative sources. It should be expanded as implementation deepens.

## Implemented baseline checks

- Client data type equals expected ceremony value (`webauthn.create` / `webauthn.get`).
  - Source: W3C WebAuthn Level 3, collected client data verification steps.
- Client data challenge equals server-issued challenge.
  - Source: W3C WebAuthn Level 3 ceremony validation requirements.
- Client data origin equals expected RP origin.
  - Source: W3C WebAuthn Level 3 origin verification requirements.
- Authenticator data RP ID hash length is 32 bytes.
  - Source: WebAuthn authenticator data structure, SHA-256 RP ID hash.
- User presence flag is required.
  - Source: WebAuthn authenticator data flags processing.
- Signature counter monotonic increase check for non-zero counters.
  - Source: WebAuthn signature counter validation guidance.
- Base64url parsing rejects padding and invalid alphabet symbols.
  - Source: RFC 4648 base64url encoding profile used by WebAuthn.

## Pending in-depth coverage

- Full attestation statement format verification (`packed`, `tpm`, `android-safetynet`, `apple`, etc.)
- Full CBOR/COSE structural validation and algorithm-specific key checks
- Extension-specific Level 3 semantics (PRF, largeBlob, related origins)
