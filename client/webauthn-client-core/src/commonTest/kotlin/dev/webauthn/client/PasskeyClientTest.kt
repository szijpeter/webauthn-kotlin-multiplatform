package dev.webauthn.client

import kotlin.test.Test
import kotlin.test.assertEquals

class PasskeyClientTest {
    @Test
    fun failureCarriesMessage() {
        val result: PasskeyResult<Unit> = PasskeyResult.Failure(PasskeyClientError.InvalidOptions("Bad options"))
        val failure = result as PasskeyResult.Failure
        assertEquals("Bad options", failure.error.message)
    }
}
