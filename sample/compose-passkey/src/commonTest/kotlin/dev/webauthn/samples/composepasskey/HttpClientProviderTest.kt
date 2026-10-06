package dev.webauthn.samples.composepasskey

import dev.webauthn.samples.composepasskey.data.network.httpLogLevel
import dev.webauthn.samples.composepasskey.data.network.configureDemoHttpClient
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.post
import io.ktor.client.request.header
import io.ktor.client.request.setBody
import kotlinx.coroutines.test.runTest
import kotlin.test.assertFalse
import io.ktor.client.plugins.logging.LogLevel
import kotlin.test.Test
import kotlin.test.assertEquals

class HttpClientProviderTest {
    @Test
    fun default_metadata_excludes_url_credentials_queries_headers_and_bodies() = runTest {
        val logs = mutableListOf<String>()
        val client = HttpClient(MockEngine { respond("private-response") }) {
            configureDemoHttpClient(logs::add)
        }
        try {
            client.post("https://name:private-password@example.test/private-path?token=private-query") {
                header("Authorization", "Bearer private-header")
                setBody("private-request")
            }
            val surfaced = logs.joinToString("\n")
            for (value in listOf("private-password", "private-path", "private-query", "private-header", "private-request", "private-response")) {
                assertFalse(surfaced.contains(value), value)
            }
            assertEquals(listOf("request method=POST host=example.test", "response status=200"), logs)
        } finally {
            client.close()
        }
    }

    @Test
    fun omits_http_bodies_by_default() {
        assertEquals(LogLevel.NONE, httpLogLevel(unsafeBodyLogging = false))
    }

    @Test
    fun allows_explicit_unsafe_http_body_logging() {
        assertEquals(LogLevel.BODY, httpLogLevel(unsafeBodyLogging = true))
    }
}
