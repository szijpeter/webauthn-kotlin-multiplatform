# COSE Key Support Matrix (JVM Crypto)

COSE decoding is delegated to Signum COSEF via `SignumPrimitives`:

- `CoseKey.deserialize(...)`
- `CoseKey.toCryptoPublicKey()`

Unsupported or malformed inputs are rejected deterministically (decode returns `null`; verification returns `false`).

| Key type | kty | Parameters | Supported | Notes |
|---|---|---|---|---|
| EC2 P-256 | `2` | `crv=1`, `x`, `y` | Yes | Normalized to SPKI and uncompressed EC point when needed. |
| RSA | `3` | `n`, `e` | Yes | Normalized to SPKI for verification/interoperability paths. |
| OKP / Ed25519 | `1` | `crv`, `x` | No | Rejected by current JVM verifier path. |

## Behavior Guarantees

1. Malformed CBOR COSE bytes are rejected.
2. Unsupported key types/curves are rejected.
3. Missing required parameters are rejected.
4. No raw-byte verification fallback exists.

## Local Ownership Boundary

There is no dedicated local COSE parser/converter class in main source anymore. All COSE key parsing in runtime path goes through Signum COSEF.
