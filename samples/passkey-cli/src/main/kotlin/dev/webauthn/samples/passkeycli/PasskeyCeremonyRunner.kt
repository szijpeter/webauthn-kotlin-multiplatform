package dev.webauthn.samples.passkeycli

import dev.webauthn.client.PasskeyFinishResult
import dev.webauthn.client.PasskeyServerClient
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.serialization.WebAuthnDtoMapper

internal class PasskeyCeremonyRunner(
    private val authenticatorAdapter: AuthenticatorAdapter,
    private val serverClient: PasskeyServerClient<RegistrationStartPayload, AuthenticationStartPayload>,
    private val stdout: Appendable = System.out,
    private val stderr: Appendable = System.err,
) {
    suspend fun runRegister(command: CliInvocation.Register): Int {
        val startPayload = RegistrationStartPayload(
            rpId = command.common.rpId,
            rpName = command.common.rpId,
            origin = command.common.origin,
            userName = command.userName,
            userDisplayName = command.userDisplayName,
            userHandle = command.userHandle,
        )

        val options = resolveRegisterOptions(startPayload) ?: return EXIT_OPTIONS_FAILURE
        val response = resolveRegistrationResponse(command.common.origin, options) ?: return EXIT_ADAPTER_FAILURE
        return finishRegistration(startPayload, options, response)
    }

    suspend fun runAuthenticate(command: CliInvocation.Authenticate): Int {
        val startPayload = AuthenticationStartPayload(
            rpId = command.common.rpId,
            origin = command.common.origin,
            userName = command.userName,
            userHandle = command.userHandle,
        )

        val options = resolveAuthenticationOptions(startPayload) ?: return EXIT_OPTIONS_FAILURE
        val response = resolveAuthenticationResponse(command.common.origin, options) ?: return EXIT_ADAPTER_FAILURE
        return finishAuthentication(startPayload, options, response)
    }

    private suspend fun resolveRegisterOptions(
        payload: RegistrationStartPayload,
    ): PublicKeyCredentialCreationOptions? {
        val result = runCatching { serverClient.getRegisterOptions(payload) }
            .getOrElse { error ->
                stderr.appendLine("Failed to fetch registration options: ${error.message}")
                return null
            }
        return when (result) {
            is ValidationResult.Valid -> result.value
            is ValidationResult.Invalid -> {
                stderr.appendLine("Registration options failed validation: ${result.formatErrors()}")
                null
            }
        }
    }

    private suspend fun resolveAuthenticationOptions(
        payload: AuthenticationStartPayload,
    ): PublicKeyCredentialRequestOptions? {
        val result = runCatching { serverClient.getSignInOptions(payload) }
            .getOrElse { error ->
                stderr.appendLine("Failed to fetch authentication options: ${error.message}")
                return null
            }
        return when (result) {
            is ValidationResult.Valid -> result.value
            is ValidationResult.Invalid -> {
                stderr.appendLine("Authentication options failed validation: ${result.formatErrors()}")
                null
            }
        }
    }

    private suspend fun resolveRegistrationResponse(
        origin: String,
        options: PublicKeyCredentialCreationOptions,
    ): RegistrationResponse? {
        val optionsDto = WebAuthnDtoMapper.fromModel(options)
        val responseDto = runCatching { authenticatorAdapter.createCredential(origin, optionsDto) }
            .getOrElse { error ->
                stderr.appendLine("Native authenticator registration failed: ${error.message}")
                return null
            }
        return when (val parsed = WebAuthnDtoMapper.toModel(responseDto)) {
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
    ): AuthenticationResponse? {
        val optionsDto = WebAuthnDtoMapper.fromModel(options)
        val responseDto = runCatching { authenticatorAdapter.getAssertion(origin, optionsDto) }
            .getOrElse { error ->
                stderr.appendLine("Native authenticator authentication failed: ${error.message}")
                return null
            }
        return when (val parsed = WebAuthnDtoMapper.toModel(responseDto)) {
            is ValidationResult.Valid -> parsed.value
            is ValidationResult.Invalid -> {
                stderr.appendLine("Native authentication response failed validation: ${parsed.formatErrors()}")
                null
            }
        }
    }

    private suspend fun finishRegistration(
        payload: RegistrationStartPayload,
        options: PublicKeyCredentialCreationOptions,
        response: RegistrationResponse,
    ): Int {
        val challenge = options.challenge.value.encoded()
        val finish = runCatching {
            serverClient.finishRegister(
                params = payload,
                response = response,
                challengeAsBase64Url = challenge,
            )
        }.getOrElse { error ->
            stderr.appendLine("Registration finish call failed: ${error.message}")
            return EXIT_FINISH_FAILURE
        }

        return when (finish) {
            PasskeyFinishResult.Verified -> {
                stdout.appendLine("Registration verified for credentialId=${response.credentialId.value.encoded()}")
                EXIT_SUCCESS
            }
            is PasskeyFinishResult.Rejected -> {
                stderr.appendLine("Registration was rejected by server: ${finish.message}")
                EXIT_REJECTED
            }
        }
    }

    private suspend fun finishAuthentication(
        payload: AuthenticationStartPayload,
        options: PublicKeyCredentialRequestOptions,
        response: AuthenticationResponse,
    ): Int {
        val challenge = options.challenge.value.encoded()
        val finish = runCatching {
            serverClient.finishSignIn(
                params = payload,
                response = response,
                challengeAsBase64Url = challenge,
            )
        }.getOrElse { error ->
            stderr.appendLine("Authentication finish call failed: ${error.message}")
            return EXIT_FINISH_FAILURE
        }

        return when (finish) {
            PasskeyFinishResult.Verified -> {
                stdout.appendLine("Authentication verified for credentialId=${response.credentialId.value.encoded()}")
                EXIT_SUCCESS
            }
            is PasskeyFinishResult.Rejected -> {
                stderr.appendLine("Authentication was rejected by server: ${finish.message}")
                EXIT_REJECTED
            }
        }
    }
}

private fun ValidationResult.Invalid.formatErrors(): String {
    return errors.joinToString(separator = "; ") { error ->
        "${error.field}: ${error.message}"
    }
}

private const val EXIT_SUCCESS: Int = 0
private const val EXIT_OPTIONS_FAILURE: Int = 2
private const val EXIT_ADAPTER_FAILURE: Int = 3
private const val EXIT_FINISH_FAILURE: Int = 4
private const val EXIT_REJECTED: Int = 5
