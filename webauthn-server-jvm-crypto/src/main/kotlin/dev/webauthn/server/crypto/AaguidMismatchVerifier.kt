package dev.webauthn.server.crypto
import dev.webauthn.model.ValidationResult
import dev.webauthn.model.WebAuthnValidationError
import java.util.Arrays

internal object AaguidMismatchVerifier {
    private const val AAGUID_OID = "1.3.6.1.4.1.45724.1.1.4" // id-fido-gen-ce-aaguid

    fun verify(
        certificateDer: ByteArray,
        aaguid: ByteArray,
        certificateInspector: JvmCertificateInspector = JvmCertificateInspector(),
    ): ValidationResult<Unit> {
        val extensionValue = certificateInspector.extensionValue(certificateDer, AAGUID_OID)
            ?: return ValidationResult.Valid(Unit)

        return try {
            val outerParser = DerParser(extensionValue)
            val innerBytes = outerParser.readOctetString()

            if (innerBytes.size == 16) {
                if (!Arrays.equals(innerBytes, aaguid)) {
                    return ValidationResult.Invalid(
                        listOf(WebAuthnValidationError.InvalidValue("x5c", "AAGUID in certificate does not match authenticator AAGUID")),
                    )
                }
                return ValidationResult.Valid(Unit)
            }

            try {
                val innerParser = DerParser(innerBytes)
                val doubleInner = innerParser.readOctetString()
                if (doubleInner.size == 16) {
                    if (!Arrays.equals(doubleInner, aaguid)) {
                        return ValidationResult.Invalid(
                            listOf(WebAuthnValidationError.InvalidValue("x5c", "AAGUID in certificate does not match authenticator AAGUID")),
                        )
                    }
                    return ValidationResult.Valid(Unit)
                }
            } catch (_: Exception) {
                // fall through to format error below
            }

            ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Invalid AAGUID extension length: ${innerBytes.size}")),
            )
        } catch (e: Exception) {
            ValidationResult.Invalid(
                listOf(WebAuthnValidationError.InvalidValue("x5c", "Failed to parse AAGUID extension: ${e.message}")),
            )
        }
    }
}
