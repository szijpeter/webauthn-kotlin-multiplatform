package dev.webauthn.runtime

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.test.runTest
import kotlin.coroutines.resume
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

    // --- runSuspendCatching ---

    @Test
    fun runSuspendCatching_returnsSuccess_onNormalCompletion() = runTest {
        val result = runSuspendCatching { "hello" }

        assertEquals("hello", result.getOrNull())
    }

    @Test
    fun runSuspendCatching_preservesCorrectness_withActualSuspension() = runTest {
        val result = runSuspendCatching {
            suspendCancellableCoroutine { cont -> cont.resume("after suspension") }
        }

        assertEquals("after suspension", result.getOrNull())
    }

    @Test
    fun runSuspendCatching_rethrowsCancellationException() = runTest {
        assertFailsWith<CancellationException> {
            runSuspendCatching<String> { throw CancellationException("cancelled") }
        }
    }

    @Test
    fun runSuspendCatching_wrapsNonCancellationException() = runTest {
        val result = runSuspendCatching<String> { throw IllegalArgumentException("bad") }

        assertIs<IllegalArgumentException>(result.exceptionOrNull())
        assertEquals("bad", result.exceptionOrNull()?.message)
    }

    // --- mapSuspendCatching ---

    @Test
    fun mapSuspendCatching_transformsSuccessfulResult() = runTest {
        val result = runSuspendCatching { 42 }
            .mapSuspendCatching { it.toString() }

        assertEquals("42", result.getOrNull())
    }

    @Test
    fun mapSuspendCatching_preservesCorrectness_withActualSuspension() = runTest {
        val result = Result.success("input")
            .mapSuspendCatching {
                suspendCancellableCoroutine { cont -> cont.resume(it.length) }
            }

        assertEquals(5, result.getOrNull())
    }

    @Test
    fun mapSuspendCatching_rethrowsCancellationFromTransform() = runTest {
        assertFailsWith<CancellationException> {
            runSuspendCatching { "value" }
                .mapSuspendCatching<String, Int> { throw CancellationException("cancelled in transform") }
        }
    }

    @Test
    fun mapSuspendCatching_passesThrough_existingFailure() = runTest {
        val original = IllegalStateException("original")
        val result = Result.failure<String>(original)
            .mapSuspendCatching { it.length }

        assertIs<IllegalStateException>(result.exceptionOrNull())
        assertEquals("original", result.exceptionOrNull()?.message)
    }

    @Test
    fun mapSuspendCatching_wrapsNonCancellationTransformException() = runTest {
        val result = runSuspendCatching { "value" }
            .mapSuspendCatching<String, Int> { throw ArithmeticException("overflow") }

        assertIs<ArithmeticException>(result.exceptionOrNull())
        assertEquals("overflow", result.exceptionOrNull()?.message)
    }

    @Test
    fun recoverSuspendCatching_recoversFromFailure() = runTest {
        val result = runSuspendCatching<String> { throw IllegalStateException("failed") }
            .recoverSuspendCatching { "recovered" }

        assertEquals("recovered", result.getOrThrow())
    }

    @Test
    fun recoverSuspendCatching_preservesCorrectness_withActualSuspension() = runTest {
        val result = Result.failure<String>(IllegalStateException("failed"))
            .recoverSuspendCatching {
                suspendCancellableCoroutine { cont -> cont.resume("recovered after suspension") }
            }

        assertEquals("recovered after suspension", result.getOrNull())
    }

    @Test
    fun recoverSuspendCatching_rethrowsCancellationException() = runTest {
        assertFailsWith<CancellationException> {
            Result.failure<String>(IllegalStateException("failed"))
                .recoverSuspendCatching { throw CancellationException("cancelled in recover") }
        }
    }

    @Test
    fun recoverSuspendCatching_wrapsNonCancellationException() = runTest {
        val result = Result.failure<String>(IllegalStateException("failed"))
            .recoverSuspendCatching { throw ArithmeticException("another error") }

        assertIs<ArithmeticException>(result.exceptionOrNull())
    }

    @Test
    fun recoverSuspendCatching_passesThrough_existingSuccess() = runTest {
        val result = Result.success("already good")
            .recoverSuspendCatching { "recovered" }

        assertEquals("already good", result.getOrThrow())
    }
}
