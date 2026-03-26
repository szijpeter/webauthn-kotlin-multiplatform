package dev.webauthn.runtime

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class CoroutineCancellationTest {
    @Test
    fun suspendCatchingNonCancellation_returnsSuccess_onNormalCompletion() = runTest {
        val result = suspendCatchingNonCancellation { "success" }

        assertEquals("success", result.getOrNull())
    }

    @Test
    fun suspendCatchingNonCancellation_rethrowsCancellation() = runTest {
        assertFailsWith<CancellationException> {
            suspendCatchingNonCancellation<String> { throw CancellationException("cancelled") }
        }
    }

    @Test
    fun suspendCatchingNonCancellation_returnsFailure_forNonCancellationErrors() = runTest {
        val result = suspendCatchingNonCancellation<String> { throw IllegalStateException("boom") }

        assertIs<IllegalStateException>(result.exceptionOrNull())
    }
}
