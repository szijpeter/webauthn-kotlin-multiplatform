# Attestation and metadata

Attestation can provide evidence about the authenticator that created a credential. It is separate from the core fact that the credential's private key produced a valid assertion later.

## Separate collection from acceptance

The creation options' attestation conveyance preference controls what evidence the authenticator is asked to return. Server policy controls what the relying party accepts at registration finish. These are related decisions, but they are not interchangeable.

In this library, `AttestationPolicy.Strict` invokes the configured `AttestationVerifier`; `AttestationPolicy.None` skips that attestation-specific verifier. It does not skip the rest of registration validation: challenge, ceremony type, origin, RP ID hash, user-presence and user-verification policy, and account binding still need to pass.

## Choose policy first

Many consumer applications can use `none` attestation and avoid collecting identifying authenticator evidence. Regulated or managed-device deployments may require particular formats, trust anchors, or metadata. Choose a policy based on product risk and privacy requirements before enabling stricter collection.

Ask these questions before choosing strict acceptance:

| Decision | Question to answer |
| --- | --- |
| Purpose | What authorization or risk decision changes because of attestation? |
| Accepted evidence | Which formats, algorithms, roots, and authenticator classes are permitted? |
| Unknown authenticators | Are missing metadata and unknown AAGUIDs rejected, quarantined, or accepted with reduced trust? |
| Privacy | What evidence is retained, for how long, and under which user-facing policy? |
| Availability | What happens when metadata is stale or its source is unavailable? |

## Verification layers

- Parse the attestation object without losing signed bytes.
- Validate the RP ID hash, flags, credential data, client-data hash binding, and format-specific statement.
- Apply format and algorithm allow-lists.
- When metadata is used, validate its trust chain, status reports, freshness, and policy meaning.
- Store only the evidence required by your policy and retention obligations.

The JVM verifier recognizes `none`, `packed`, `android-key`, `tpm`, `apple`, `android-safetynet`, and `fido-u2f` attestation statements. Packed attestation requires a configured signature verifier, and certificate-chain trust depends on the configured `TrustAnchorSource`. Format recognition alone is not an application acceptance policy.

## Metadata integration boundary

`webauthn-attestation-mds` is a minimal, pull-based trust-source adapter. It loads metadata from a configured endpoint, caches it, and maps AAGUIDs to attestation root certificates. The cache begins empty, so call `refreshIfStale(...)` before the source is used for verification.

The module does not choose refresh scheduling, stale-data tolerance, outage behavior, status-report policy, or the privacy consequences of retaining attestation evidence. Treat it as a trust-anchor input to a larger policy, not as a complete Metadata Service policy engine.

!!! warning "Metadata is operational input"
    Metadata can change and fetches can fail. Refresh outside the critical finish path, monitor failures, and define freshness, outage, revocation, and rollback behavior before relying on the cache for registration decisions.

See the [artifact catalog](../reference/modules.md) for the server crypto and metadata modules.
