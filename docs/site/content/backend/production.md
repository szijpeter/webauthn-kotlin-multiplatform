# Backend production checklist

## Protocol and policy

- [ ] RP IDs and allowed origins are explicit per deployment and cannot be overridden by untrusted client input.
- [ ] Registration and authentication options use cryptographically strong challenges.
- [ ] Ceremony type, challenge, and origin are derived from the signed raw `clientDataJSON`.
- [ ] RP ID hash, signature, credential ownership, and required flags are validated.
- [ ] Attestation policy is chosen deliberately; unsupported or disallowed formats fail closed.
- [ ] Discoverable and named-account authentication have distinct, tested ownership rules.

## State and persistence

- [ ] Ceremony state expires and is consumed exactly once under concurrency.
- [ ] Credential identifiers and public keys remain byte-preserving.
- [ ] Durable stores work across restarts and all service replicas.
- [ ] Database migrations, backups, restore tests, and retention are operationally owned.
- [ ] Tenant/account boundaries are enforced in every credential lookup and update.

## Web deployment

- [ ] TLS is enforced from client to trusted termination point.
- [ ] Start and finish endpoints have intentional authentication, session-management, and CSRF policies.
- [ ] Request sizes, timeouts, rate limits, and abuse controls are configured.
- [ ] Error responses do not expose credential existence, validation internals, or secrets unnecessarily.
- [ ] Android and iOS association documents are deployed, monitored, and versioned with app identities.

## Observability and response

- [ ] Metrics distinguish start, platform/client abandonment, finish validation failure, and success.
- [ ] Logs omit raw credential bodies, cookies, authorization headers, challenge values, and key material.
- [ ] Audit events identify policy outcomes without storing signed payloads.
- [ ] Alerts, credential-revocation procedures, and incident playbooks exist.
- [ ] The previous supported mobile version is tested against the new backend and vice versa.

The mobile release has a separate [production checklist](../mobile/production.md).
