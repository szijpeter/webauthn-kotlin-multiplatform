package dev.webauthn.samples.passkeycli

import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.RegistrationResponseDto
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.encodeToJsonElement

internal class PythonFido2Adapter(
    private val commandExecutor: CommandExecutor,
    private val pythonBinary: String,
    private val bridgeScriptPath: String,
    private val json: Json = Json { ignoreUnknownKeys = true },
) : AuthenticatorAdapter {
    override suspend fun createCredential(
        origin: String,
        options: PublicKeyCredentialCreationOptionsDto,
    ): RegistrationResponseDto {
        val request = PythonBridgeRequest(
            command = "register",
            origin = origin,
            options = json.encodeToJsonElement(PublicKeyCredentialCreationOptionsDto.serializer(), options),
        )
        val response = invokeBridge(request)
        return json.decodeFromJsonElement(RegistrationResponseDto.serializer(), response)
    }

    override suspend fun getAssertion(
        origin: String,
        options: PublicKeyCredentialRequestOptionsDto,
    ): AuthenticationResponseDto {
        val request = PythonBridgeRequest(
            command = "authenticate",
            origin = origin,
            options = json.encodeToJsonElement(PublicKeyCredentialRequestOptionsDto.serializer(), options),
        )
        val response = invokeBridge(request)
        return json.decodeFromJsonElement(AuthenticationResponseDto.serializer(), response)
    }

    private suspend fun invokeBridge(request: PythonBridgeRequest): JsonElement {
        val payload = json.encodeToString(PythonBridgeRequest.serializer(), request)
        val result = commandExecutor.execute(
            command = listOf(pythonBinary, bridgeScriptPath),
            stdin = payload,
        )
        val envelope = decodeEnvelopeOrNull(result.stdout)

        if (result.exitCode != 0) {
            if (envelope != null) {
                fail("Python bridge returned error: ${envelope.error ?: "unknown failure"}")
            }
            val details = result.stderr.ifBlank { result.stdout }.ifBlank { "<no output>" }
            fail(
                "Python bridge failed (exit=${result.exitCode}): $details",
            )
        }
        if (envelope == null) {
            fail("Python bridge returned empty stdout.")
        }

        if (!envelope.ok || envelope.response == null) {
            fail(
                "Python bridge returned error: ${envelope.error ?: "unknown failure"}",
            )
        }
        return envelope.response
    }

    private fun fail(message: String): Nothing {
        throw IllegalStateException(message)
    }

    private fun decodeEnvelopeOrNull(stdout: String): PythonBridgeEnvelope? {
        if (stdout.isBlank()) {
            return null
        }
        return runCatching {
            json.decodeFromString(PythonBridgeEnvelope.serializer(), stdout)
        }.getOrElse { error ->
            val abbreviated = stdout.take(BRIDGE_OUTPUT_SNIPPET_LIMIT)
            fail(
                "Python bridge returned invalid JSON envelope: ${error.message}. Output: $abbreviated",
            )
        }
    }
}

@Serializable
internal data class PythonBridgeRequest(
    val command: String,
    val origin: String,
    val options: JsonElement,
)

@Serializable
internal data class PythonBridgeEnvelope(
    val ok: Boolean,
    val response: JsonElement? = null,
    val error: String? = null,
)

private const val BRIDGE_OUTPUT_SNIPPET_LIMIT: Int = 200
