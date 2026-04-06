package dev.webauthn.samples.passkeycli

import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialParametersDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.RpEntityDto
import dev.webauthn.serialization.UserEntityDto
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PythonFido2AdapterTest {
    @Test
    fun createCredential_buildsBridgePayloadAndParsesResponse() = runTest {
        val json = Json { ignoreUnknownKeys = true }
        val expectedResponse = validRegistrationResponseDto()
        val responseElement = json.encodeToJsonElement(RegistrationResponseDto.serializer(), expectedResponse)
        val fakeExecutor = FakeCommandExecutor(
            CommandExecutionResult(
                exitCode = 0,
                stdout = json.encodeToString(
                    PythonBridgeEnvelope.serializer(),
                    PythonBridgeEnvelope(ok = true, response = responseElement),
                ),
                stderr = "",
            ),
        )
        val adapter = PythonFido2Adapter(
            commandExecutor = fakeExecutor,
            pythonBinary = "python3",
            bridgeScriptPath = "bridge.py",
            json = json,
        )
        val options = PublicKeyCredentialCreationOptionsDto(
            rp = RpEntityDto(id = "localhost", name = "localhost"),
            user = UserEntityDto(
                id = "AQID",
                name = "alice",
                displayName = "Alice",
            ),
            challenge = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            pubKeyCredParams = listOf(
                PublicKeyCredentialParametersDto(type = "public-key", alg = -7),
            ),
        )

        val actual = adapter.createCredential(
            origin = "https://localhost",
            options = options,
        )

        assertEquals(expectedResponse.id, actual.id)
        assertEquals(listOf("python3", "bridge.py"), fakeExecutor.lastCommand)
        val request = json.decodeFromString(PythonBridgeRequest.serializer(), fakeExecutor.lastStdin.orEmpty())
        assertEquals("register", request.command)
        assertEquals("https://localhost", request.origin)
        assertTrue(request.options is JsonObject)
    }

    @Test
    fun createCredential_failsWhenBridgeExitsNonZero() = runTest {
        val fakeExecutor = FakeCommandExecutor(
            CommandExecutionResult(
                exitCode = 1,
                stdout = "",
                stderr = "python-fido2 missing",
            ),
        )
        val adapter = PythonFido2Adapter(
            commandExecutor = fakeExecutor,
            pythonBinary = "python3",
            bridgeScriptPath = "bridge.py",
        )
        val options = PublicKeyCredentialCreationOptionsDto(
            rp = RpEntityDto(id = "localhost", name = "localhost"),
            user = UserEntityDto(id = "AQID", name = "alice", displayName = "Alice"),
            challenge = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            pubKeyCredParams = listOf(PublicKeyCredentialParametersDto(type = "public-key", alg = -7)),
        )

        val error = assertFailsWith<IllegalStateException> {
            adapter.createCredential(origin = "https://localhost", options = options)
        }

        assertTrue(error.message?.contains("python-fido2 missing") == true)
    }

    @Test
    fun createCredential_failsWhenBridgeReturnsErrorEnvelopeOnStdout() = runTest {
        val json = Json { ignoreUnknownKeys = true }
        val fakeExecutor = FakeCommandExecutor(
            CommandExecutionResult(
                exitCode = 1,
                stdout = json.encodeToString(
                    PythonBridgeEnvelope.serializer(),
                    PythonBridgeEnvelope(ok = false, error = "bridge exploded"),
                ),
                stderr = "",
            ),
        )
        val adapter = PythonFido2Adapter(
            commandExecutor = fakeExecutor,
            pythonBinary = "python3",
            bridgeScriptPath = "bridge.py",
            json = json,
        )
        val options = PublicKeyCredentialCreationOptionsDto(
            rp = RpEntityDto(id = "localhost", name = "localhost"),
            user = UserEntityDto(id = "AQID", name = "alice", displayName = "Alice"),
            challenge = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            pubKeyCredParams = listOf(PublicKeyCredentialParametersDto(type = "public-key", alg = -7)),
        )

        val error = assertFailsWith<IllegalStateException> {
            adapter.createCredential(origin = "https://localhost", options = options)
        }

        assertTrue(error.message?.contains("bridge exploded") == true)
    }
}

private class FakeCommandExecutor(
    private val result: CommandExecutionResult,
) : CommandExecutor {
    var lastCommand: List<String>? = null
    var lastStdin: String? = null

    override suspend fun execute(command: List<String>, stdin: String?): CommandExecutionResult {
        lastCommand = command
        lastStdin = stdin
        return result
    }
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
