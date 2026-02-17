package dev.webauthn.crypto

/**
 * Shared digest operations for attestation verification.
 *
 * Migration note:
 * Prefer this in attestation verifiers that previously called `MessageDigest.getInstance("SHA-256")` directly.
 * Migrated call sites include:
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/PackedAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidKeyAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/TpmAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AppleAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidSafetyNetAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/FidoU2fAttestationStatementVerifier.kt`
 */
public fun interface DigestService {
    public fun sha256(input: ByteArray): ByteArray
}

/**
 * Decodes a COSE public key into a neutral DTO.
 *
 * Migration note:
 * New attestation verifier call sites should prefer this over ad-hoc COSE parsing.
 * Migrated call sites include:
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidKeyAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AppleAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/FidoU2fAttestationStatementVerifier.kt`
 */
public fun interface CosePublicKeyDecoder {
    public fun decode(coseKey: ByteArray): CosePublicKeyMaterial?
}

/**
 * Normalizes decoded COSE key material into common encodings.
 *
 * Migration note:
 * New call sites should use this with [CosePublicKeyDecoder] instead of manually converting COSE maps.
 * Migrated call sites include:
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/FidoU2fAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/JvmCrypto.kt`
 */
public interface CosePublicKeyNormalizer {
    public fun toSubjectPublicKeyInfo(material: CosePublicKeyMaterial): ByteArray?

    public fun toUncompressedEcPoint(material: CosePublicKeyMaterial): ByteArray?
}

/**
 * Verifies signatures with a certificate public key provided as DER bytes.
 *
 * Migration note:
 * Use this for x5c signature verification in attestation statement verifiers that previously used JCA directly.
 * Migrated call sites include:
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/PackedAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidKeyAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/TpmAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidSafetyNetAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/FidoU2fAttestationStatementVerifier.kt`
 */
public fun interface CertificateSignatureVerifier {
    public fun verify(
        algorithm: CoseAlgorithm,
        certificateDer: ByteArray,
        data: ByteArray,
        signature: ByteArray,
    ): Boolean
}

/**
 * Reads certificate metadata and extensions as neutral DTOs.
 *
 * Migration note:
 * Existing JCA-based certificate field access in attestation verifiers should move here.
 * Migrated call sites include:
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/PackedAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidKeyAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/TpmAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AppleAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidSafetyNetAttestationStatementVerifier.kt`
 */
public interface CertificateInspector {
    public fun inspect(certificateDer: ByteArray): ParsedCertificate

    public fun extensionValue(certificateDer: ByteArray, oid: String): ByteArray?
}

/**
 * Validates certificate chains using DER inputs only.
 *
 * Migration note:
 * Existing direct `PKIX`/`X509Certificate.verify` use in attestation verifiers should move here.
 * Migrated call sites include:
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidKeyAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/TpmAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AppleAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/AndroidSafetyNetAttestationStatementVerifier.kt`
 * - `webauthn-server-jvm-crypto/src/main/kotlin/dev/webauthn/server/crypto/FidoU2fAttestationStatementVerifier.kt`
 */
public interface CertificateChainValidator {
    public fun verify(chainDer: List<ByteArray>, trustAnchorsDer: List<ByteArray>): Boolean

    public fun verifySignedByNext(chainDer: List<ByteArray>): Boolean
}

public data class CosePublicKeyMaterial(
    public val kty: Long,
    public val alg: Long? = null,
    public val crv: Long? = null,
    public val x: ByteArray? = null,
    public val y: ByteArray? = null,
    public val n: ByteArray? = null,
    public val e: ByteArray? = null,
)

public data class ParsedCertificate(
    public val subjectDistinguishedName: String,
    public val version: Int,
    public val basicConstraints: Int,
    public val extendedKeyUsageOids: List<String>,
    public val criticalExtensionOids: Set<String>,
    public val ecPublicKeyX: ByteArray? = null,
    public val ecPublicKeyY: ByteArray? = null,
) {
    public val isCa: Boolean
        get() = basicConstraints != -1
}
