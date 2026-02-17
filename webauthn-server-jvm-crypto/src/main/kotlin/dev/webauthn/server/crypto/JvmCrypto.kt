package dev.webauthn.server.crypto

import dev.webauthn.core.RegistrationValidationInput
import dev.webauthn.crypto.AttestationVerifier
import dev.webauthn.crypto.CertificateChainValidator
import dev.webauthn.crypto.CertificateInspector
import dev.webauthn.crypto.CertificateSignatureVerifier
import dev.webauthn.crypto.coseAlgorithmFromCode
import dev.webauthn.crypto.CoseAlgorithm
import dev.webauthn.crypto.CoseKeyParser
import dev.webauthn.crypto.CosePublicKeyDecoder
import dev.webauthn.crypto.CosePublicKeyNormalizer
import dev.webauthn.crypto.DigestService
import dev.webauthn.crypto.ParsedCosePublicKey
import dev.webauthn.crypto.RpIdHasher
import dev.webauthn.crypto.SignatureVerifier
import dev.webauthn.crypto.TrustAnchorSource
import dev.webauthn.model.ValidationResult

public class JvmRpIdHasher(
    private val digestService: DigestService = JvmDigestService(),
) : RpIdHasher {
    override fun hashRpId(rpId: String): ByteArray {
        return digestService.sha256(rpId.toByteArray(Charsets.UTF_8))
    }
}

/**
 * Default JVM [SignatureVerifier] with stable public API.
 * Internally delegates to a provider adapter (JCA by default; optional Signum via constructor).
 *
 * @param delegate When null (default), uses [JcaSignatureVerifier] (current JCA path).
 *                 Pass [SignumSignatureVerifier] or [CryptoProvider.SIGNUM].createSignatureVerifier() for Signum path.
 * @param cosePublicKeyDecoder Used when constructing the default JCA adapter when [delegate] is null.
 * @param cosePublicKeyNormalizer Used when constructing the default JCA adapter when [delegate] is null.
 */
public class JvmSignatureVerifier(
    delegate: SignatureVerifier? = null,
    private val cosePublicKeyDecoder: CosePublicKeyDecoder = JvmCosePublicKeyDecoder(),
    private val cosePublicKeyNormalizer: CosePublicKeyNormalizer = JvmCosePublicKeyNormalizer(),
) : SignatureVerifier by (delegate ?: JcaSignatureVerifier(cosePublicKeyDecoder, cosePublicKeyNormalizer)) {

    /**
     * Convenience constructor to select provider by [CryptoProvider].
     * Default [CryptoProvider.JCA] preserves current JCA path.
     */
    public constructor(
        provider: CryptoProvider,
        cosePublicKeyDecoder: CosePublicKeyDecoder = JvmCosePublicKeyDecoder(),
        cosePublicKeyNormalizer: CosePublicKeyNormalizer = JvmCosePublicKeyNormalizer(),
    ) : this(
        delegate = provider.createSignatureVerifier(cosePublicKeyDecoder, cosePublicKeyNormalizer),
        cosePublicKeyDecoder = cosePublicKeyDecoder,
        cosePublicKeyNormalizer = cosePublicKeyNormalizer,
    )
}

public class JvmCoseKeyParser(
    private val defaultAlgorithm: CoseAlgorithm = CoseAlgorithm.ES256,
    private val cosePublicKeyDecoder: CosePublicKeyDecoder = JvmCosePublicKeyDecoder(),
    private val cosePublicKeyNormalizer: CosePublicKeyNormalizer = JvmCosePublicKeyNormalizer(),
) : CoseKeyParser {
    override fun parsePublicKey(coseKey: ByteArray): ParsedCosePublicKey {
        val material = cosePublicKeyDecoder.decode(coseKey)
        val spki = material?.let(cosePublicKeyNormalizer::toSubjectPublicKeyInfo) ?: coseKey
        val algorithm = material?.alg?.toInt()?.let(::coseAlgorithmFromCode)
            ?: defaultAlgorithm
        return ParsedCosePublicKey(
            algorithm = algorithm,
            x509SubjectPublicKeyInfo = spki,
        )
    }
}

/**
 * Strict attestation verifier that delegates to [CompositeAttestationVerifier].
 * Accepts provider abstractions via constructor injection (e.g. [SignatureVerifier], [DigestService])
 * for JCA vs Signum or other backends.
 *
 * @param signatureVerifier When null, [CompositeAttestationVerifier] will reject packed attestation.
 *                          Use [JvmSignatureVerifier] or [JvmSignatureVerifier] with [CryptoProvider] for default JCA or Signum path.
 * @param trustAnchorSource Trust anchors for certificate chain validation.
 * @param digestService Digest service; default [JvmDigestService]. Pass [SignumDigestService] for Signum path.
 * @param cosePublicKeyDecoder Used by format verifiers that need COSE decode; default [JvmCosePublicKeyDecoder].
 * @param cosePublicKeyNormalizer Used by format verifiers; default [JvmCosePublicKeyNormalizer].
 * @param certificateSignatureVerifier X5c signature verification; default [JvmCertificateSignatureVerifier].
 * @param certificateInspector Certificate inspection; default [JvmCertificateInspector].
 * @param certificateChainValidator Chain validation; default [JvmCertificateChainValidator].
 */
public class StrictAttestationVerifier(
    signatureVerifier: SignatureVerifier? = null,
    trustAnchorSource: TrustAnchorSource? = ResourceTrustAnchorSource(),
    digestService: DigestService = JvmDigestService(),
    cosePublicKeyDecoder: CosePublicKeyDecoder = JvmCosePublicKeyDecoder(),
    cosePublicKeyNormalizer: CosePublicKeyNormalizer = JvmCosePublicKeyNormalizer(),
    certificateSignatureVerifier: CertificateSignatureVerifier = JvmCertificateSignatureVerifier(),
    certificateInspector: CertificateInspector = JvmCertificateInspector(),
    certificateChainValidator: CertificateChainValidator = JvmCertificateChainValidator(),
) : AttestationVerifier {

    /**
     * Convenience constructor using [CryptoProvider] for signature and digest.
     * Uses [provider].createSignatureVerifier() and [provider].createDigestService() for the Signum path.
     */
    public constructor(
        provider: CryptoProvider,
        trustAnchorSource: TrustAnchorSource? = ResourceTrustAnchorSource(),
        cosePublicKeyDecoder: CosePublicKeyDecoder = JvmCosePublicKeyDecoder(),
        cosePublicKeyNormalizer: CosePublicKeyNormalizer = JvmCosePublicKeyNormalizer(),
        certificateSignatureVerifier: CertificateSignatureVerifier = JvmCertificateSignatureVerifier(),
        certificateInspector: CertificateInspector = JvmCertificateInspector(),
        certificateChainValidator: CertificateChainValidator = JvmCertificateChainValidator(),
    ) : this(
        signatureVerifier = provider.createSignatureVerifier(cosePublicKeyDecoder, cosePublicKeyNormalizer),
        trustAnchorSource = trustAnchorSource,
        digestService = provider.createDigestService(),
        cosePublicKeyDecoder = cosePublicKeyDecoder,
        cosePublicKeyNormalizer = cosePublicKeyNormalizer,
        certificateSignatureVerifier = certificateSignatureVerifier,
        certificateInspector = certificateInspector,
        certificateChainValidator = certificateChainValidator,
    )

    private val delegate = CompositeAttestationVerifier(
        signatureVerifier = signatureVerifier,
        trustAnchorSource = trustAnchorSource,
        digestService = digestService,
        cosePublicKeyDecoder = cosePublicKeyDecoder,
        cosePublicKeyNormalizer = cosePublicKeyNormalizer,
        certificateSignatureVerifier = certificateSignatureVerifier,
        certificateInspector = certificateInspector,
        certificateChainValidator = certificateChainValidator,
    )

    override fun verify(input: RegistrationValidationInput): ValidationResult<Unit> {
        return delegate.verify(input)
    }
}
