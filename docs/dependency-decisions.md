# Dependency Decisions

## Policy

1. Prefer Kotlin and Kotlinx libraries first.
2. Add third-party dependencies only when Kotlin/Kotlinx cannot satisfy a requirement.
3. Keep `webauthn-model` and `webauthn-core` free of platform/network dependencies.

## Current baseline

- Kotlin `2.2.20`
- AGP `9.0.0`
- Ktor `3.3.0`
- kotlinx.serialization `1.9.0`
- kotlinx.coroutines `1.10.2`
- kotlinx.datetime `0.7.1`

## Notes

- JVM crypto currently uses JCA/JCE from the JDK.
- No external crypto provider is used in V1 scaffold.
- Optional MDS support uses Ktor client + Kotlinx serialization only.

## Signum adoption plan

### Scope

- Scope is limited to main sources under `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/`.
- Tests are excluded from this inventory.
- "Direct use" means explicit `getInstance(...)` callsites of:
  - `java.security.Signature`
  - `java.security.MessageDigest`
  - `java.security.KeyFactory`
  - `java.security.cert.CertificateFactory`

### Current direct JVM crypto touchpoints (main source)

Signature verification:

- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/JvmCrypto.kt:41` `Signature.getInstance("SHA256withECDSA")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/JvmCrypto.kt:42` `Signature.getInstance("SHA256withRSA")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/JvmCrypto.kt:43` `Signature.getInstance("Ed25519")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/PackedAttestationStatementVerifier.kt:118` `java.security.Signature.getInstance(jcaAlgorithm)`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidKeyAttestationStatementVerifier.kt:75` `java.security.Signature.getInstance(jcaParams(...))`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/TpmAttestationStatementVerifier.kt:95` `java.security.Signature.getInstance(jcaParams(...))`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidSafetyNetAttestationStatementVerifier.kt:106` `Signature.getInstance("SHA256withRSA")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/FidoU2fAttestationStatementVerifier.kt:55` `Signature.getInstance("SHA256withECDSA")`

Hashing:

- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/JvmCrypto.kt:20` `MessageDigest.getInstance("SHA-256")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/PackedAttestationStatementVerifier.kt:51` `MessageDigest.getInstance("SHA-256")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidKeyAttestationStatementVerifier.kt:70` `java.security.MessageDigest.getInstance("SHA-256")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/TpmAttestationStatementVerifier.kt:145` `java.security.MessageDigest.getInstance("SHA-256")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/TpmAttestationStatementVerifier.kt:146` `java.security.MessageDigest.getInstance("SHA-256")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidSafetyNetAttestationStatementVerifier.kt:134` `java.security.MessageDigest.getInstance("SHA-256")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidSafetyNetAttestationStatementVerifier.kt:135` `java.security.MessageDigest.getInstance("SHA-256")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/FidoU2fAttestationStatementVerifier.kt:41` `MessageDigest.getInstance("SHA-256")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AppleAttestationStatementVerifier.kt:70` `java.security.MessageDigest.getInstance("SHA-256")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AppleAttestationStatementVerifier.kt:71` `java.security.MessageDigest.getInstance("SHA-256")`

COSE key decode:

- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/JvmCrypto.kt:33` `KeyFactory.getInstance("EC")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/JvmCrypto.kt:34` `KeyFactory.getInstance("RSA")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/JvmCrypto.kt:35` `KeyFactory.getInstance("Ed25519")`

X.509 parse and trust material loading:

- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/ResourceTrustAnchorSource.kt:11` `CertificateFactory.getInstance("X.509")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidKeyAttestationStatementVerifier.kt:56` `CertificateFactory.getInstance("X.509")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/PackedAttestationStatementVerifier.kt:104` `CertificateFactory.getInstance("X.509")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/TpmAttestationStatementVerifier.kt:61` `CertificateFactory.getInstance("X.509")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidSafetyNetAttestationStatementVerifier.kt:75` `CertificateFactory.getInstance("X.509")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/FidoU2fAttestationStatementVerifier.kt:32` `CertificateFactory.getInstance("X.509")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AppleAttestationStatementVerifier.kt:41` `CertificateFactory.getInstance("X.509")`
- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/TrustChainVerifier.kt:19` `CertificateFactory.getInstance("X.509")`

Trust-chain verification:

- `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/TrustChainVerifier.kt` performs PKIX path validation using JDK classes (`CertPathValidator`, `PKIXParameters`, `TrustAnchor`) after loading anchors/certs via `CertificateFactory`.

Attestation-format-specific checks:

- `packed`: hash + cert parse + signature verify in `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/PackedAttestationStatementVerifier.kt`
- `android-key`: hash + cert parse + signature verify + ASN.1 extension parsing in `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidKeyAttestationStatementVerifier.kt`
- `tpm`: hash + cert parse + signature verify + `certInfo` checks in `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/TpmAttestationStatementVerifier.kt`
- `android-safetynet`: hash + cert parse + JWS signature verify in `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidSafetyNetAttestationStatementVerifier.kt`
- `apple`: hash + cert parse + extension checks in `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AppleAttestationStatementVerifier.kt`
- `fido-u2f`: hash + cert parse + signature verify in `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/FidoU2fAttestationStatementVerifier.kt`

### Ownership boundary: Signum vs JCA/JDK

Signum owns (migration target):

1. Signature verification primitives currently using `Signature.getInstance(...)`.
2. SHA-256 hashing primitives currently using `MessageDigest.getInstance(...)`.
3. COSE-key-to-verification-key decode path currently using `KeyFactory.getInstance(...)` in `JvmSignatureVerifier`.

Stays JCA/JDK in first Signum adoption step:

1. X.509 certificate parsing/loading via `CertificateFactory`.
2. PKIX trust-path validation (`CertPathValidator`/`PKIXParameters` in `TrustChainVerifier`) and related trust anchor handling.
3. Certificate object model and extension access via `X509Certificate`.
4. Module-local DER helpers (`DerParser`, DER emit/parse helpers in `CoseToSpkiConverter`) remain local/JDK-based and out of Signum scope.

### Compatibility constraints

- Kotlin version: `2.3.10` (`gradle/libs.versions.toml`).
- JVM toolchain target: Java `21` (`build-logic/src/main/kotlin/webauthn.kotlin.jvm.gradle.kts`).
- Module scope: JVM-only module (`id("webauthn.kotlin.jvm")` in `webauthn-server-jvm-crypto/build.gradle.kts`).
- Android/iOS impact: none for this module.

### Rollback strategy

1. Introduce provider flag: `dev.webauthn.server.crypto.provider`.
2. Supported values: `legacy` (default) and `signum`.
3. Keep legacy JCA-backed implementation active and buildable while Signum path is introduced.
4. Rollback procedure: set provider to `legacy` without code revert.
5. Keep both providers available until parity tests pass and CI shows sustained parity.

### Parity test gate before default switch

- Default provider remains `legacy` until parity passes.
- Parity criteria:
  - Existing JVM crypto tests pass with `provider=legacy`.
  - Same suite passes with `provider=signum`.
  - No behavior regression across `packed`, `android-key`, `android-safetynet`, `apple`, `tpm`, `fido-u2f`, and `JvmSignatureVerifier` algorithm coverage.
