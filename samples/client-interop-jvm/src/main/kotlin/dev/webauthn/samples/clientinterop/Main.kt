package dev.webauthn.samples.clientinterop

import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.ValidationResult
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.KtorPasskeyServerClient
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.AuthenticationResponsePayloadDto
import dev.webauthn.serialization.RegistrationResponseDto
import dev.webauthn.serialization.RegistrationResponsePayloadDto
import dev.webauthn.serialization.WebAuthnDtoMapper
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
        val serverClient = KtorPasskeyServerClient(
            httpClient = httpClient,
            endpointBase = endpointBase,
            backendContract = TempServerBackendContract(),
        )
        val registrationParams = RegistrationStartPayload(
            rpId = rpId,
            rpName = "WebAuthn Kotlin MPP Demo",
            origin = origin,
            userName = userName,
            userDisplayName = userName,
            userHandle = userId,
        )

        val registrationOptions = serverClient.getRegisterOptions(registrationParams)
            .requireValid("startRegistration")

        val registrationChallenge = registrationOptions.challenge.value.encoded()
        val registrationResponse = WebAuthnDtoMapper.toModel(
            RegistrationResponseDto(
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
            ),
        ).requireValid("registration response mapping")

        val registrationOk = serverClient.finishRegister(
            params = registrationParams,
            response = registrationResponse,
            challengeAsBase64Url = registrationChallenge,
        )
        check(registrationOk) { "finishRegistration failed" }

        val authenticationParams = AuthenticationStartPayload(
            rpId = rpId,
            origin = origin,
            userName = userId,
        )
        val authenticationOptions = serverClient.getSignInOptions(authenticationParams)
            .requireValid("startAuthentication")

        val authenticationChallenge = authenticationOptions.challenge.value.encoded()
        val authenticationResponse = WebAuthnDtoMapper.toModel(
            AuthenticationResponseDto(
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
            ),
        ).requireValid("authentication response mapping")

        val authenticationOk = serverClient.finishSignIn(
            params = authenticationParams,
            response = authenticationResponse,
            challengeAsBase64Url = authenticationChallenge,
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
