package dev.webauthn.samples.clientinterop

import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.ValidationResult
import dev.webauthn.network.AuthenticationFinishPayload
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationFinishPayload
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.network.WebAuthnBackendProfile
import dev.webauthn.network.WebAuthnInteropKtorClient
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.AuthenticationResponsePayloadDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.RegistrationResponsePayloadDto
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.runBlocking
import kotlin.system.exitProcess

public fun main(): Unit = runBlocking {
    val endpointBase = System.getenv("WEBAUTHN_DEMO_ENDPOINT") ?: "http://127.0.0.1:8787"
    val rpId = System.getenv("WEBAUTHN_DEMO_RP_ID") ?: "localhost"
    val origin = System.getenv("WEBAUTHN_DEMO_ORIGIN") ?: "https://localhost"
    val userId = System.getenv("WEBAUTHN_DEMO_USER_ID") ?: "demo-user-1"
    val userName = System.getenv("WEBAUTHN_DEMO_USER_NAME") ?: "demo@local"
    val credentialId = Base64UrlBytes.fromBytes("demo-credential-1".encodeToByteArray()).encoded()

    val httpClient = HttpClient(CIO) {
        install(ContentNegotiation) {
            json()
        }
    }

    try {
        val interop = WebAuthnInteropKtorClient(
            httpClient = httpClient,
            endpointBase = endpointBase,
            profile = WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC,
        )

        val registrationOptions = interop.startRegistration(
            RegistrationStartPayload(
                rpId = rpId,
                rpName = "WebAuthn Kotlin MPP Demo",
                origin = origin,
                userName = userName,
                userDisplayName = userName,
                userHandle = userId,
            ),
        ).requireValid("startRegistration")

        val registrationChallenge = registrationOptions.challenge.value.encoded()
        val registrationResponse = RegistrationResponseDto(
            id = credentialId,
            rawId = credentialId,
            response = RegistrationResponsePayloadDto(
                clientDataJson = clientDataBase64Url(
                    type = "webauthn.create",
                    challenge = registrationChallenge,
                    origin = origin,
                ),
                attestationObject = Base64UrlBytes.fromBytes(byteArrayOf(1, 2, 3)).encoded(),
            ),
        )

        val registrationOk = interop.finishRegistration(
            RegistrationFinishPayload(
                response = registrationResponse,
                clientDataType = "webauthn.create",
                challenge = registrationChallenge,
                origin = origin,
            ),
        )
        check(registrationOk) { "finishRegistration failed" }

        val authenticationOptions = interop.startAuthentication(
            AuthenticationStartPayload(
                rpId = rpId,
                origin = origin,
                userName = userId,
            ),
        ).requireValid("startAuthentication")

        val authenticationChallenge = authenticationOptions.challenge.value.encoded()
        val authenticationResponse = AuthenticationResponseDto(
            id = credentialId,
            rawId = credentialId,
            response = AuthenticationResponsePayloadDto(
                clientDataJson = clientDataBase64Url(
                    type = "webauthn.get",
                    challenge = authenticationChallenge,
                    origin = origin,
                ),
                authenticatorData = Base64UrlBytes.fromBytes(ByteArray(37) { 5 }).encoded(),
                signature = Base64UrlBytes.fromBytes(byteArrayOf(9, 9, 9)).encoded(),
            ),
        )

        val authenticationOk = interop.finishAuthentication(
            AuthenticationFinishPayload(
                response = authenticationResponse,
                clientDataType = "webauthn.get",
                challenge = authenticationChallenge,
                origin = origin,
            ),
        )
        check(authenticationOk) { "finishAuthentication failed" }

        println("Demo flow succeeded against $endpointBase")
        println("Registration challenge: $registrationChallenge")
        println("Authentication challenge: $authenticationChallenge")
    } catch (error: Throwable) {
        System.err.println("Demo flow failed: ${error.message}")
        error.printStackTrace()
        exitProcess(1)
    } finally {
        httpClient.close()
    }
}

private fun clientDataBase64Url(type: String, challenge: String, origin: String): String {
    val json = """{"type":"$type","challenge":"$challenge","origin":"$origin"}"""
    return Base64UrlBytes.fromBytes(json.encodeToByteArray()).encoded()
}

private fun <T> ValidationResult<T>.requireValid(step: String): T {
    return when (this) {
        is ValidationResult.Valid -> value
        is ValidationResult.Invalid -> error("$step validation failed: ${errors.joinToString { "${it.field}: ${it.message}" }}")
    }
}
