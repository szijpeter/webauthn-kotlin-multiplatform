package dev.webauthn.attestation.mds

import dev.webauthn.model.Aaguid
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.http.HttpHeaders
import io.ktor.http.headersOf
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class FidoMdsTrustSourceTest {
    @Test
    fun findTrustAnchorsMatchesHyphenatedAaguidEntries() = runBlocking {
        val engine = MockEngine {
            respond(
                content = """
                    {
                      "no": 1,
                      "nextUpdate": "2026-03-09",
                      "entries": [
                        {
                          "aaguid": "00112233-4455-6677-8899-aabbccddeeff",
                          "attestationRootCertificates": [
                            "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----"
                          ]
                        }
                      ]
                    }
                """.trimIndent(),
                headers = headersOf(HttpHeaders.ContentType, "application/json"),
            )
        }
        val client = HttpClient(engine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }
        val source = FidoMdsTrustSource(
            httpClient = client,
            metadataUrl = "https://example.test/mds",
            nowEpochSeconds = { 0L },
        )

        source.refreshIfStale(maxAgeSeconds = 0)

        val result = source.findTrustAnchors(
            Aaguid.fromBytes(
                byteArrayOf(
                    0x00,
                    0x11,
                    0x22,
                    0x33,
                    0x44,
                    0x55,
                    0x66,
                    0x77,
                    0x88.toByte(),
                    0x99.toByte(),
                    0xAA.toByte(),
                    0xBB.toByte(),
                    0xCC.toByte(),
                    0xDD.toByte(),
                    0xEE.toByte(),
                    0xFF.toByte(),
                ),
            ),
        )

        assertEquals(1, result.size)
        assertContentEquals(byteArrayOf(0x01, 0x02, 0x03), result.single().bytes())
        client.close()
    }
}
