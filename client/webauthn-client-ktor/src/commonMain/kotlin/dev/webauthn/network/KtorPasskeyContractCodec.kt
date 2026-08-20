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
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.isSuccess

/** Route configuration for a codec-neutral Ktor passkey backend. */
public data class KtorPasskeyRoutes(
    public val registerOptionsPath: String = "/webauthn/registration/start",
    public val registerFinishPath: String = "/webauthn/registration/finish",
    public val signInOptionsPath: String = "/webauthn/authentication/start",
    public val signInFinishPath: String = "/webauthn/authentication/finish",
)

/**
 * Serialization contract for a Ktor-backed passkey backend.
 *
 * The transport has no serialization implementation dependency. The state returned from each
 * start decoder is passed unchanged to the corresponding finish encoder.
 */
public interface KtorPasskeyContractCodec<
    RegistrationInput,
    RegistrationState,
    RegistrationOutput,
    AuthenticationInput,
    AuthenticationState,
    AuthenticationOutput,
> {
    public fun encodeRegistrationStart(input: RegistrationInput): String

    public fun decodeRegistrationStart(
        body: String,
    ): ValidationResult<CeremonyStart<RegistrationState, PublicKeyCredentialCreationOptions>>

    public fun encodeRegistrationFinish(
        state: RegistrationState,
        response: RawRegistrationResponse,
    ): String

    public fun decodeRegistrationFinish(body: String): RegistrationOutput

    public fun encodeAuthenticationStart(input: AuthenticationInput): String

    public fun decodeAuthenticationStart(
        body: String,
    ): ValidationResult<CeremonyStart<AuthenticationState, PublicKeyCredentialRequestOptions>>

    public fun encodeAuthenticationFinish(
        state: AuthenticationState,
        response: RawAuthenticationResponse,
    ): String

    public fun decodeAuthenticationFinish(body: String): AuthenticationOutput

    /** Returns a safe backend error message when available, otherwise `null`. */
    public fun decodeError(body: String): String?
}

/** Codec-neutral Ktor transport exposing generic opaque-state ceremony backends. */
public class KtorPasskeyBackend<
    RegistrationInput,
    RegistrationState,
    RegistrationOutput,
    AuthenticationInput,
    AuthenticationState,
    AuthenticationOutput,
>(
    private val httpClient: HttpClient,
    endpointBase: String,
    private val codec: KtorPasskeyContractCodec<
        RegistrationInput,
        RegistrationState,
        RegistrationOutput,
        AuthenticationInput,
        AuthenticationState,
        AuthenticationOutput,
    >,
    private val routes: KtorPasskeyRoutes = KtorPasskeyRoutes(),
) {
    private val endpointBase = endpointBase.trimEnd('/')

    public fun registrationBackend(): RegistrationBackend<RegistrationInput, RegistrationState, RegistrationOutput> =
        object : RegistrationBackend<RegistrationInput, RegistrationState, RegistrationOutput> {
        override suspend fun start(input: RegistrationInput) = postForOptions(
            path = routes.registerOptionsPath,
            payload = codec.encodeRegistrationStart(input),
            operation = "Registration start",
            decode = codec::decodeRegistrationStart,
        ).toFlowValue()

        override suspend fun finish(
            state: RegistrationState,
            response: RawRegistrationResponse,
        ): RegistrationOutput =
            postForResult(
                path = routes.registerFinishPath,
                payload = codec.encodeRegistrationFinish(state, response),
                operation = "Registration finish",
                decode = codec::decodeRegistrationFinish,
            )
        }

    public fun authenticationBackend():
        AuthenticationBackend<AuthenticationInput, AuthenticationState, AuthenticationOutput> =
        object : AuthenticationBackend<AuthenticationInput, AuthenticationState, AuthenticationOutput> {
        override suspend fun start(input: AuthenticationInput) = postForOptions(
            path = routes.signInOptionsPath,
            payload = codec.encodeAuthenticationStart(input),
            operation = "Authentication start",
            decode = codec::decodeAuthenticationStart,
        ).toFlowValue()

        override suspend fun finish(
            state: AuthenticationState,
            response: RawAuthenticationResponse,
        ): AuthenticationOutput =
            postForResult(
                path = routes.signInFinishPath,
                payload = codec.encodeAuthenticationFinish(state, response),
                operation = "Authentication finish",
                decode = codec::decodeAuthenticationFinish,
            )
        }

    private fun endpointFor(path: String): String = "$endpointBase/${path.trimStart('/')}"

    private suspend fun <T> postForOptions(
        path: String,
        payload: String,
        operation: String,
        decode: (String) -> ValidationResult<T>,
    ): ValidationResult<T> = decode(post(path, payload, operation))

    private suspend fun <T> postForResult(
        path: String,
        payload: String,
        operation: String,
        decode: (String) -> T,
    ): T = decode(post(path, payload, operation))

    private suspend fun post(path: String, payload: String, operation: String): String {
        val response = httpClient.post(endpointFor(path)) {
            header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
            setBody(payload)
        }
        val body = response.bodyAsText()
        if (!response.status.isSuccess()) {
            val details = codec.decodeError(body)
                ?: if (body.isEmpty()) "<empty body>" else "<redacted body length=${body.length}>"
            error("$operation failed with HTTP ${response.status.value}: $details")
        }
        return body
    }
}

private fun <T> ValidationResult<T>.toFlowValue(): T = when (this) {
    is ValidationResult.Valid -> value
    is ValidationResult.Invalid -> throw IllegalArgumentException(
        errors.joinToString("; ") { it.field + ": " + it.message },
    )
}
