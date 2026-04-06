package dev.webauthn.samples.passkeycli

import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialParametersDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.RpEntityDto
import dev.webauthn.serialization.UserEntityDto
import java.net.URI
import java.net.URLDecoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class BrowserHandoffAdapterTest {
    @Test
    fun createCredential_roundTripsViaLocalCallbackServer() = runTest {
        val json = Json { ignoreUnknownKeys = true }
        val expectedResponse = validRegistrationResponseDto()
        val launcher = SimulatedBrowserLauncher(
            onOpen = { uri ->
                val callback = uri.queryParam("callback")
                val token = uri.queryParam("token")
                val command = uri.queryParam("command")
                assertEquals("register", command)

                val optionsResponse = httpGet("$callback/options?token=$token")
                val optionsEnvelope = json.parseToJsonElement(optionsResponse).jsonObject
                assertEquals("true", optionsEnvelope.getValue("ok").jsonPrimitive.content)
                assertEquals("register", optionsEnvelope.getValue("command").jsonPrimitive.content)

                val completionPayload = json.encodeToString(
                    buildJsonObject {
                        put("ok", true)
                        put("response", json.encodeToJsonElement(RegistrationResponseDto.serializer(), expectedResponse))
                    },
                )
                httpPost("$callback/complete?token=$token", completionPayload)
            },
        )
        val adapter = BrowserHandoffAdapter(
            endpointBase = "http://localhost:8080",
            browserLauncher = launcher,
            callbackTimeoutMs = 5_000,
            stdout = StringBuilder(),
            json = json,
        )

        val actual = adapter.createCredential(
            origin = "http://localhost:8080",
            options = validCreationOptionsDto(),
        )

        assertEquals(expectedResponse.id, actual.id)
    }

    @Test
    fun getAssertion_whenBrowserReportsError_throwsIllegalState() = runTest {
        val json = Json { ignoreUnknownKeys = true }
        val launcher = SimulatedBrowserLauncher(
            onOpen = { uri ->
                val callback = uri.queryParam("callback")
                val token = uri.queryParam("token")
                val completionPayload = """{"ok":false,"error":"browser cancelled"}"""
                httpPost("$callback/complete?token=$token", completionPayload)
            },
        )
        val adapter = BrowserHandoffAdapter(
            endpointBase = "http://localhost:8080",
            browserLauncher = launcher,
            callbackTimeoutMs = 5_000,
            stdout = StringBuilder(),
            json = json,
        )

        val error = assertFailsWith<IllegalStateException> {
            adapter.getAssertion(
                origin = "http://localhost:8080",
                options = validRequestOptionsDto(),
            )
        }

        assertTrue(error.message?.contains("browser cancelled") == true)
    }

    @Test
    fun createCredential_whenBrowserNeverCallsBack_timesOut() = runTest {
        val adapter = BrowserHandoffAdapter(
            endpointBase = "http://localhost:8080",
            browserLauncher = BrowserLauncher { true },
            callbackTimeoutMs = 25,
            stdout = StringBuilder(),
        )

        val error = assertFailsWith<IllegalStateException> {
            adapter.createCredential(
                origin = "http://localhost:8080",
                options = validCreationOptionsDto(),
            )
        }

        assertTrue(error.message?.contains("Timed out waiting for browser handoff callback") == true)
    }
}

private class SimulatedBrowserLauncher(
    private val onOpen: (URI) -> Unit,
) : BrowserLauncher {
    override fun open(uri: URI): Boolean {
        onOpen(uri)
        return true
    }
}

private fun URI.queryParam(key: String): String {
    val rawQuery = rawQuery ?: return ""
    return rawQuery
        .split("&")
        .map { segment -> segment.split("=", limit = 2) }
        .firstOrNull { pair -> pair.firstOrNull() == key }
        ?.getOrNull(1)
        ?.let { URLDecoder.decode(it, StandardCharsets.UTF_8) }
        .orEmpty()
}

private fun httpGet(url: String): String {
    val request = HttpRequest.newBuilder()
        .uri(URI(url))
        .GET()
        .build()
    return HttpClient.newHttpClient()
        .send(request, HttpResponse.BodyHandlers.ofString())
        .body()
}

private fun httpPost(url: String, body: String) {
    val request = HttpRequest.newBuilder()
        .uri(URI(url))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build()
    HttpClient.newHttpClient()
        .send(request, HttpResponse.BodyHandlers.ofString())
}

private fun validCreationOptionsDto(): PublicKeyCredentialCreationOptionsDto {
    return PublicKeyCredentialCreationOptionsDto(
        rp = RpEntityDto(id = "localhost", name = "localhost"),
        user = UserEntityDto(
            id = "AQID",
            name = "alice",
            displayName = "Alice",
        ),
        challenge = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        pubKeyCredParams = listOf(PublicKeyCredentialParametersDto(type = "public-key", alg = -7)),
    )
}

private fun validRequestOptionsDto(): PublicKeyCredentialRequestOptionsDto {
    return PublicKeyCredentialRequestOptionsDto(
        challenge = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        rpId = "localhost",
    )
}

private fun validRegistrationResponseDto(): RegistrationResponseDto {
    val json = Json { ignoreUnknownKeys = true }
    return json.decodeFromString(
        RegistrationResponseDto.serializer(),
        """
        {
          "id": "MzMzMzMzMzMzMzMzMzMzMw",
          "rawId": "MzMzMzMzMzMzMzMzMzMzMw",
          "response": {
            "clientDataJSON": "BAUG",
            "attestationObject": "o2NmbXRkbm9uZWhhdXRoRGF0YVhKRERERERERERERERERERERERERERERERERERERERERERBAAAACVVVVVVVVVVVVVVVVVVVVVUAEDMzMzMzMzMzMzMzMzMzMzOhAQJnYXR0U3RtdKA"
          }
        }
        """.trimIndent(),
    )
}
