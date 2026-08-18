package dev.webauthn.samples.composepasskey

import dev.webauthn.samples.composepasskey.data.network.httpLogLevel
import io.ktor.client.plugins.logging.LogLevel
import kotlin.test.Test
import kotlin.test.assertEquals

class HttpClientProviderTest {
    @Test
    fun omits_http_bodies_by_default() {
        assertEquals(LogLevel.INFO, httpLogLevel(unsafeBodyLogging = false))
    }

    @Test
    fun allows_explicit_unsafe_http_body_logging() {
        assertEquals(LogLevel.BODY, httpLogLevel(unsafeBodyLogging = true))
    }
}
