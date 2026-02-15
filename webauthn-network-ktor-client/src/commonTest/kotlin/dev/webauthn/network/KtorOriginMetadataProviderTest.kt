package dev.webauthn.network

import dev.webauthn.model.Origin
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class KtorOriginMetadataProviderTest {

    @Test
    fun fetchesRelatedOrigins() = runTest {
        val mockEngine = MockEngine { request ->
            if (request.url.encodedPath == "/.well-known/webauthn") {
                respond(
                    content = """{"origins": ["https://app.example.com", "https://other.example.com"]}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                )
            } else {
                respond(content = "", status = HttpStatusCode.NotFound)
            }
        }

        val client = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json()
            }
        }

        val provider = KtorOriginMetadataProvider(client)
        val origins = provider.getRelatedOrigins(Origin.parseOrThrow("https://example.com"))

        assertEquals(2, origins.size)
        assertTrue(origins.contains(Origin.parseOrThrow("https://app.example.com")))
        assertTrue(origins.contains(Origin.parseOrThrow("https://other.example.com")))
    }

    @Test
    fun handlesNotFound() = runTest {
        val mockEngine = MockEngine { _ ->
            respond(content = "", status = HttpStatusCode.NotFound)
        }

        val client = HttpClient(mockEngine) {
            install(ContentNegotiation) { json() }
        }

        val provider = KtorOriginMetadataProvider(client)
        val origins = provider.getRelatedOrigins(Origin.parseOrThrow("https://example.com"))

        assertTrue(origins.isEmpty())
    }
}
