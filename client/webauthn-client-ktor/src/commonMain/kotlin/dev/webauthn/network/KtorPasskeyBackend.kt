package dev.webauthn.network

import dev.webauthn.client.AuthenticationBackend
import dev.webauthn.client.CeremonyStart
import dev.webauthn.client.RegistrationBackend
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.ValidationResult
import io.ktor.client.HttpClient
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.isSuccess

/**
 * Codec-neutral Ktor transport that exposes typed [RegistrationBackend] and
 * [AuthenticationBackend] instances.
 */
public class KtorPasskeyBackend<
    RegistrationInput,
    AuthenticationInput,
    RegistrationOutput,
    AuthenticationOutput,
>(
    private val httpClient: HttpClient,
    endpointBase: String,
    private val codec:
        KtorPasskeyContractCodec<RegistrationInput, AuthenticationInput, RegistrationOutput, AuthenticationOutput>,
    private val routes: KtorPasskeyRoutes = KtorPasskeyRoutes(),
) {
    private val endpointBase: String = endpointBase.trimEnd('/')

    public fun registrationBackend(): RegistrationBackend<RegistrationInput, Unit, RegistrationOutput> =
        object : RegistrationBackend<RegistrationInput, Unit, RegistrationOutput> {
            override suspend fun start(
                input: RegistrationInput,
            ): CeremonyStart<Unit, PublicKeyCredentialCreationOptions> = CeremonyStart(
                state = Unit,
                options = postForOptions(
                    path = routes.registerOptionsPath,
                    payload = codec.encodeRegistrationStart(input),
                    operation = "Registration start",
                    decode = codec::decodeRegistrationStart,
                ).toFlowValue(),
            )

            override suspend fun finish(state: Unit, response: RawRegistrationResponse): RegistrationOutput =
                postForResult(
                    path = routes.registerFinishPath,
                    payload = codec.encodeRegistrationFinish(response),
                    operation = "Registration finish",
                    decode = codec::decodeRegistrationFinish,
                )
        }

    public fun authenticationBackend(): AuthenticationBackend<AuthenticationInput, Unit, AuthenticationOutput> =
        object : AuthenticationBackend<AuthenticationInput, Unit, AuthenticationOutput> {
            override suspend fun start(
                input: AuthenticationInput,
            ): CeremonyStart<Unit, PublicKeyCredentialRequestOptions> = CeremonyStart(
                state = Unit,
                options = postForOptions(
                    path = routes.signInOptionsPath,
                    payload = codec.encodeAuthenticationStart(input),
                    operation = "Authentication start",
                    decode = codec::decodeAuthenticationStart,
                ).toFlowValue(),
            )

            override suspend fun finish(state: Unit, response: RawAuthenticationResponse): AuthenticationOutput =
                postForResult(
                    path = routes.signInFinishPath,
                    payload = codec.encodeAuthenticationFinish(response),
                    operation = "Authentication finish",
                    decode = codec::decodeAuthenticationFinish,
                )
        }

    private fun endpointFor(path: String): String {
        val normalizedPath = if (path.startsWith('/')) path else "/$path"
        return "$endpointBase$normalizedPath"
    }

    private suspend fun <Output> postForOptions(
        path: String,
        payload: String,
        operation: String,
        decode: (String) -> ValidationResult<Output>,
    ): ValidationResult<Output> = decode(post(path, payload, operation))

    private suspend fun <Output> postForResult(
        path: String,
        payload: String,
        operation: String,
        decode: (String) -> Output,
    ): Output = decode(post(path, payload, operation))

    private suspend fun post(path: String, payload: String, operation: String): String {
        val response = httpClient.post(endpointFor(path)) {
            header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(payload)
        }
        val responseText = response.bodyAsText()
        throwIfHttpError(response, responseText, operation, codec::decodeError)
        return responseText
    }
}

private fun <T> ValidationResult<T>.toFlowValue(): T = when (this) {
    is ValidationResult.Valid -> value
    is ValidationResult.Invalid -> throw IllegalArgumentException(errors.joinToString("; ") { it.message })
}

private fun throwIfHttpError(
    response: HttpResponse,
    responseText: String,
    operation: String,
    decodeError: (String) -> String?,
) {
    if (response.status.isSuccess()) return
    val details = decodeError(responseText) ?: "<redacted non-empty body length=${responseText.length}>"
    error("$operation failed with HTTP ${response.status.value}: $details")
}
