package dev.webauthn.samples.passkeycli

import dev.webauthn.model.RawAuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RawRegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.client.AuthenticationBackend
import dev.webauthn.client.RegistrationBackend
import dev.webauthn.network.kotlinx.DefaultPasskeyFinishResult
import dev.webauthn.network.kotlinx.AuthenticationStartPayload
import dev.webauthn.network.kotlinx.RegistrationStartPayload
import dev.webauthn.runtime.runSuspendCatching
import dev.webauthn.serialization.WebAuthnDtoMapper

internal class PasskeyCeremonyRunner(
    private val authenticatorAdapter: AuthenticatorAdapter,
    private val registrationBackend: RegistrationBackend<RegistrationStartPayload, Unit, DefaultPasskeyFinishResult>,
    private val authenticationBackend:
        AuthenticationBackend<AuthenticationStartPayload, Unit, DefaultPasskeyFinishResult>,
    private val stdout: Appendable = System.out,
    private val stderr: Appendable = System.err,
) {
    suspend fun runRegister(command: CliInvocation.Register): Int {
        val startPayload = RegistrationStartPayload(
            rpId = command.common.rpId,
            // For this sample POC we mirror rpId; rpName can be promoted to a distinct CLI input when needed.
            rpName = command.common.rpId,
            origin = command.common.origin,
            userName = command.userName,
            userDisplayName = command.userDisplayName,
            userHandle = command.userHandle,
        )

        val options = resolveRegisterOptions(startPayload) ?: return EXIT_OPTIONS_FAILURE
        val response = resolveRegistrationResponse(command.common.origin, options) ?: return EXIT_ADAPTER_FAILURE
        return finishRegistration(response)
    }

    suspend fun runAuthenticate(command: CliInvocation.Authenticate): Int {
        val startPayload = AuthenticationStartPayload(
            rpId = command.common.rpId,
            origin = command.common.origin,
            userName = command.userName,
        )

        val options = resolveAuthenticationOptions(startPayload) ?: return EXIT_OPTIONS_FAILURE
        val response = resolveAuthenticationResponse(command.common.origin, options) ?: return EXIT_ADAPTER_FAILURE
        return finishAuthentication(response)
    }

    private suspend fun resolveRegisterOptions(
        payload: RegistrationStartPayload,
    ): PublicKeyCredentialCreationOptions? {
        val result = runSuspendCatching { registrationBackend.start(payload).options }
            .getOrElse { error ->
                stderr.appendLine("Failed to fetch registration options: ${error.displayMessage()}")
                return null
            }
        return result
    }

    private suspend fun resolveAuthenticationOptions(
        payload: AuthenticationStartPayload,
    ): PublicKeyCredentialRequestOptions? {
        val result = runSuspendCatching { authenticationBackend.start(payload).options }
            .getOrElse { error ->
                stderr.appendLine("Failed to fetch authentication options: ${error.displayMessage()}")
                return null
            }
        return result
    }

    private suspend fun resolveRegistrationResponse(
        origin: String,
        options: PublicKeyCredentialCreationOptions,
    ): RawRegistrationResponse? {
        val optionsDto = WebAuthnDtoMapper.fromModel(options)
        val responseDto = runSuspendCatching { authenticatorAdapter.createCredential(origin, optionsDto) }
            .getOrElse { error ->
                stderr.appendLine("Authenticator registration failed: ${error.displayMessage()}")
                return null
            }
        return when (val parsed = WebAuthnDtoMapper.toRawModel(responseDto)) {
            is ValidationResult.Valid -> parsed.value
            is ValidationResult.Invalid -> {
                stderr.appendLine("Native registration response failed validation: ${parsed.formatErrors()}")
                null
            }
        }
    }

    private suspend fun resolveAuthenticationResponse(
        origin: String,
        options: PublicKeyCredentialRequestOptions,
    ): RawAuthenticationResponse? {
        val optionsDto = WebAuthnDtoMapper.fromModel(options)
        val responseDto = runSuspendCatching { authenticatorAdapter.getAssertion(origin, optionsDto) }
            .getOrElse { error ->
                stderr.appendLine("Authenticator authentication failed: ${error.displayMessage()}")
                return null
            }
        return when (val parsed = WebAuthnDtoMapper.toRawModel(responseDto)) {
            is ValidationResult.Valid -> parsed.value
            is ValidationResult.Invalid -> {
                stderr.appendLine("Native authentication response failed validation: ${parsed.formatErrors()}")
                null
            }
        }
    }

    private suspend fun finishRegistration(response: RawRegistrationResponse): Int {
        val finish = runSuspendCatching {
            registrationBackend.finish(Unit, response)
        }.getOrElse { error ->
            stderr.appendLine("Registration finish call failed: ${error.displayMessage()}")
            return EXIT_FINISH_FAILURE
        }

        return when (finish) {
            DefaultPasskeyFinishResult.Verified -> {
                stdout.appendLine("Registration verified for credentialId=${response.credentialId.value.encoded()}")
                EXIT_SUCCESS
            }
            is DefaultPasskeyFinishResult.Rejected -> {
                stderr.appendLine("Registration was rejected by server: ${finish.message ?: "no reason provided"}")
                EXIT_REJECTED
            }
        }
    }

    private suspend fun finishAuthentication(response: RawAuthenticationResponse): Int {
        val finish = runSuspendCatching {
            authenticationBackend.finish(Unit, response)
        }.getOrElse { error ->
            stderr.appendLine("Authentication finish call failed: ${error.displayMessage()}")
            return EXIT_FINISH_FAILURE
        }

        return when (finish) {
            DefaultPasskeyFinishResult.Verified -> {
                stdout.appendLine("Authentication verified for credentialId=${response.credentialId.value.encoded()}")
                EXIT_SUCCESS
            }
            is DefaultPasskeyFinishResult.Rejected -> {
                stderr.appendLine("Authentication was rejected by server: ${finish.message ?: "no reason provided"}")
                EXIT_REJECTED
            }
        }
    }
}

private fun Throwable.displayMessage(): String {
    return message?.takeIf { it.isNotBlank() }
        ?: this::class.simpleName
        ?: "unknown error"
}

private fun ValidationResult.Invalid.formatErrors(): String =
    errors.joinToString(separator = "; ") { error -> "${error.field}: ${error.message}" }

private const val EXIT_SUCCESS: Int = 0
private const val EXIT_OPTIONS_FAILURE: Int = 2
private const val EXIT_ADAPTER_FAILURE: Int = 3
private const val EXIT_FINISH_FAILURE: Int = 4
private const val EXIT_REJECTED: Int = 5
