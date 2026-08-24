# Security

WebAuthn code sits on an authentication boundary. Review cryptographic validation, raw-byte preservation, RP ID and origin policy, account binding, replay prevention, persistence, and deployment association as one system. Include error handling and logging in that review.

## Report privately

Use GitHub private vulnerability reporting from the repository Security tab. Include affected modules, threat-model assumptions, impact, reproduction steps, and whether the behavior conflicts with WebAuthn or related requirements. Do not open a public issue for a suspected vulnerability.

[Read the repository security policy](https://github.com/szijpeter/webauthn-kotlin-multiplatform/blob/@@SOURCE_REF@@/SECURITY.md){ .md-button .md-button--primary }

## Integration review priorities

- Keep signed `clientDataJSON` byte-preserving through the server verification boundary.
- Pin RP IDs and allowed origins to trusted server configuration.
- Consume ceremony state once and reject replay.
- Bind credentials to authoritative accounts and tenant scope.
- Choose attestation and metadata policy deliberately.
- Keep credential payloads, PRF material, challenges, and session secrets out of logs.
- Treat mobile association and signing identities as security configuration.

The library cannot make an unsafe application authorization, storage, deployment, or recovery policy safe by itself.
