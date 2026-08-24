# Ceremony state and storage

Server correctness depends on store semantics as much as cryptographic primitives. The service contracts separate challenge, credential, and user-account storage so applications can supply durable implementations without changing ceremony orchestration.

## Challenge and ceremony state

A stored ceremony should be unpredictable, scoped to registration or authentication, bound to the intended RP and account context, short-lived, and consumable once. Finish must reject missing, expired, mismatched, or previously consumed state.

In a horizontally scaled deployment, “read then delete” is not enough if two finish requests can race. Use an atomic consume operation or a transaction/conditional update that permits one winner.

## Credential records

At minimum, a credential record needs the credential ID, public key material, account ownership, RP scope, and authenticator state required by your policy. Counter behavior varies by authenticator; handle supported counter updates consistently without treating every non-increment as the same incident.

Credential IDs and user handles are binary protocol values. Preserve bytes through storage and transport boundaries; do not normalize them through platform-default character encodings.

## User-account mapping

Registration must bind the new credential to the authenticated or explicitly provisioned account. Authentication must resolve the returned credential to its authoritative owner. Named authentication additionally enforces that the credential belongs to the requested account.

## Available implementations

- In-memory stores are useful for tests and single-process exploration. They are not restart-safe or horizontally scalable.
- `webauthn-server-store-exposed` implements the contracts over Exposed/JDBC and provides schema initialization for bootstrap.
- Mature deployments still own migrations, backups, retention, encryption at rest, tenancy, observability, and database operations.

## Test the contract

Exercise expiry, one-time consumption, concurrent finishes, duplicate credential IDs, ownership mismatch, absent accounts between start and finish, counter update behavior, transaction rollback, and process restart. The library's store contract tests are a baseline; your implementation needs database-specific concurrency evidence.
