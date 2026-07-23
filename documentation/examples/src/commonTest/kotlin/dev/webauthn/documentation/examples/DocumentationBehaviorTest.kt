package dev.webauthn.documentation.examples

import dev.webauthn.model.ValidationResult
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class DocumentationBehaviorTest {
    @Test
    fun requestOptionsExampleRejectsAnOriginInsteadOfAnRpId() {
        val result = buildSignInOptions(
            challengeBytes = ByteArray(16) { 7 },
            rpIdFromRequest = "https://example.com",
            storedCredentialId = "AQID",
        )

        assertIs<ValidationResult.Invalid>(result)
    }

    @Test
    fun requestOptionsExampleBuildsValidatedOptions() {
        val result = buildSignInOptions(
            challengeBytes = ByteArray(16) { 7 },
            rpIdFromRequest = "example.com",
            storedCredentialId = "AQID",
        )

        val options = assertIs<ValidationResult.Valid<PublicKeyCredentialRequestOptions>>(result).value
        assertEquals("example.com", options.rpId?.value)
        assertEquals(1, options.allowCredentials.size)
    }

    @Test
    fun runtimeExampleMapsOrdinaryFailures() = runTest {
        val result = loadAndTransform(
            fetchData = { error("offline") },
            transform = { it.length },
            mapFailure = { -1 },
        )

        assertEquals(-1, result)
    }

    @Test
    fun runtimeExamplePreservesCancellation() = runTest {
        assertFailsWith<CancellationException> {
            loadAndTransform(
                fetchData = { throw CancellationException("cancel") },
                transform = { it.length },
                mapFailure = { -1 },
            )
        }
    }
}
