package smoke.client

import dev.webauthn.client.CeremonyStart
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
import dev.webauthn.network.KtorPasskeyBackend
import dev.webauthn.network.KtorPasskeyContractCodec
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

class NeutralKtorSmokeTest {
    @Test
    fun consumer_selected_mock_engine_preserves_opaque_state() = runTest {
        val codec = SmokeCodec()
        val backend = KtorPasskeyBackend<String, String, String, String, String, String>(
            httpClient = HttpClient(MockEngine { respond("{}", HttpStatusCode.OK) }),
            endpointBase = "https://example.test",
            codec = codec,
        )

        val start = backend.registrationBackend().start("input")
        backend.registrationBackend().finish(start.state, rawRegistration())

        assertEquals("opaque-continuation", codec.finishedState)
    }
}

private class SmokeCodec : KtorPasskeyContractCodec<String, String, String, String, String, String> {
    var finishedState: String? = null

    override fun encodeRegistrationStart(input: String) = input
    override fun decodeRegistrationStart(body: String) =
        ValidationResult.Valid(CeremonyStart("opaque-continuation", creationOptions()))
    override fun encodeRegistrationFinish(state: String, response: RawRegistrationResponse): String {
        finishedState = state
        return "{}"
    }
    override fun decodeRegistrationFinish(body: String) = "ok"
    override fun encodeAuthenticationStart(input: String) = input
    override fun decodeAuthenticationStart(body: String) =
        ValidationResult.Valid(CeremonyStart("opaque-continuation", requestOptions()))
    override fun encodeAuthenticationFinish(state: String, response: RawAuthenticationResponse) = "{}"
    override fun decodeAuthenticationFinish(body: String) = "ok"
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
    clientDataJson = dev.webauthn.model.Base64UrlBytes.fromBytes(byteArrayOf(2)),
    attestationObject = dev.webauthn.model.Base64UrlBytes.fromBytes(byteArrayOf(3)),
)
