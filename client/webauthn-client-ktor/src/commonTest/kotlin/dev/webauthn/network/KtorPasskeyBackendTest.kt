package dev.webauthn.network

import dev.webauthn.client.CeremonyStart
import dev.webauthn.model.Base64UrlBytes
import dev.webauthn.model.Challenge
import dev.webauthn.model.CredentialId
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialType
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.RpId
import dev.webauthn.model.UserHandle
import dev.webauthn.model.ValidationResult
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class KtorPasskeyBackendTest {
    @Test
    fun registration_state_from_start_is_forwarded_to_finish_encoder() = runTest {
        val codec = RecordingCodec()
        val backend = backend(codec)
        val started = backend.registrationBackend().start("registration")
        backend.registrationBackend().finish(started.state, rawRegistration())
        assertEquals("registration-token", codec.registrationState)
        assertEquals("raw-registration", codec.registrationResponse)
    }

    @Test
    fun authentication_state_from_start_is_forwarded_to_finish_encoder() = runTest {
        val codec = RecordingCodec()
        val backend = backend(codec)
        val started = backend.authenticationBackend().start("authentication")
        backend.authenticationBackend().finish(started.state, rawAuthentication())
        assertEquals("authentication-token", codec.authenticationState)
        assertEquals("raw-authentication", codec.authenticationResponse)
    }

    private fun backend(codec: RecordingCodec) = KtorPasskeyBackend(
        httpClient = HttpClient(MockEngine { respond("{}", HttpStatusCode.OK, headersOf(HttpHeaders.ContentType, "application/json")) }),
        endpointBase = "https://example.test",
        codec = codec,
    )
}

private class RecordingCodec : KtorPasskeyContractCodec<String, String, String, String, String, String> {
    var registrationState: String? = null
    var authenticationState: String? = null
    var registrationResponse: String? = null
    var authenticationResponse: String? = null

    override fun encodeRegistrationStart(input: String) = input
    override fun decodeRegistrationStart(body: String) = ValidationResult.Valid(CeremonyStart("registration-token", creationOptions()))
    override fun encodeRegistrationFinish(state: String, response: RawRegistrationResponse): String {
        registrationState = state
        registrationResponse = "raw-registration"
        return "finish-registration"
    }
    override fun decodeRegistrationFinish(body: String) = "registration-output"
    override fun encodeAuthenticationStart(input: String) = input
    override fun decodeAuthenticationStart(body: String) = ValidationResult.Valid(CeremonyStart("authentication-token", requestOptions()))
    override fun encodeAuthenticationFinish(state: String, response: RawAuthenticationResponse): String {
        authenticationState = state
        authenticationResponse = "raw-authentication"
        return "finish-authentication"
    }
    override fun decodeAuthenticationFinish(body: String) = "authentication-output"
    override fun decodeError(body: String): String? = null
}

private fun creationOptions() = PublicKeyCredentialCreationOptions(
    rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.com"), "Example"),
    user = PublicKeyCredentialUserEntity(UserHandle.fromBytes(byteArrayOf(1)), "user", "User"),
    challenge = Challenge.fromBytes(ByteArray(32) { 1 }),
    pubKeyCredParams = listOf(PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7)),
)

private fun requestOptions() = PublicKeyCredentialRequestOptions(
    challenge = Challenge.fromBytes(ByteArray(32) { 2 }),
    rpId = RpId.parseOrThrow("example.com"),
)

private fun rawRegistration() = RawRegistrationResponse(
    credentialId = CredentialId.fromBytes(byteArrayOf(1)),
    clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(2)),
    attestationObject = Base64UrlBytes.fromBytes(byteArrayOf(3)),
)

private fun rawAuthentication() = RawAuthenticationResponse(
    credentialId = CredentialId.fromBytes(byteArrayOf(1)),
    clientDataJson = Base64UrlBytes.fromBytes(byteArrayOf(2)),
    authenticatorData = Base64UrlBytes.fromBytes(byteArrayOf(3)),
    signature = Base64UrlBytes.fromBytes(byteArrayOf(4)),
)
