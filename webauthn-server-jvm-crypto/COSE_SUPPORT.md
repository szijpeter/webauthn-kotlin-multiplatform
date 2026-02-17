# COSE Key Support Matrix (JVM crypto)

COSE public key parsing and SPKI conversion in this module support the following key shapes. Unsupported or malformed inputs fail deterministically (no raw-byte fallback).

| Key type | kty | Parameters | Supported | Notes |
|----------|-----|------------|-----------|--------|
| **EC2 P-256** | 2 | crv=1, x, y (labels -1, -2, -3) | Yes | Converts to X.509 SPKI (id-ecPublicKey, secp256r1). |
| **RSA** | 3 | n, e (labels -1, -2) | Yes | Converts to X.509 SPKI (rsaEncryption). |
| **OKP / Ed25519** | 1 | crv, x (alg=-8) | No | Fails with structured [CoseParseFailure.UnsupportedKeyType]. |

- **Malformed CBOR** (truncated map, wrong major type, invalid length, etc.): decode returns `null`; `CoseKeyParser.parsePublicKey` returns `CoseParseResult.Failure` with `CoseParseFailure.MalformedCbor`.
- **Unsupported curve** (e.g. EC2 with crv ≠ 1): conversion returns `null`; parse returns `CoseParseResult.Failure` with `CoseParseFailure.UnsupportedCurve` or `UnsupportedKeyType`.
- **Missing required parameters**: `CoseParseResult.Failure` with `CoseParseFailure.MissingRequiredParameter`.

Single parser component: `JvmCoseParser`; conversion: `CoseToSpkiConverter`.
