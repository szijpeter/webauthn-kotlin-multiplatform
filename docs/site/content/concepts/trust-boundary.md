# Mobile-to-server trust boundary

The mobile app is a protocol participant, not a verification authority. It can request options, invoke the platform prompt, and transport the result. It cannot prove its own origin, choose which challenge counts, or declare that a signature is valid.

## Ownership map

| Concern | Mobile/client ownership | Server ownership |
| --- | --- | --- |
| User gesture and prompt timing | Yes | No |
| Platform credential API and lifecycle | Yes | No |
| Challenge generation | No | Yes |
| RP ID and allowed-origin policy | No | Yes |
| Signature and RP ID hash validation | No | Yes |
| Ceremony state and replay prevention | No | Yes |
| Product session after success | Present the outcome | Authorize and issue |
| Association deployment | Supply the signed app identity | Deploy authoritative association files |

## Preserve signed bytes

The signed client-data boundary starts with raw `clientDataJSON`. Avoid parsing it on the client and sending separate challenge, type, or origin fields as if they were authoritative. The backend must derive those values from the same raw bytes used in cryptographic verification.

## Custom integrations

Replacing JSON, Ktor, storage, or crypto implementations is supported, but it transfers ownership. Preserve binary values, cancellation semantics, opaque continuation state, one-time ceremony consumption, and fail-closed validation. A convenient custom adapter must not create a second, unsigned source of truth.

Read [RP IDs, origins, and app association](origins.md) next.
