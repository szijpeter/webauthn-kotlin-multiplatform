package dev.webauthn.client.android

import android.content.Context
import androidx.credentials.CredentialManager
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.NoCredentialException
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.AuthenticationResponse
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse

public class AndroidPasskeyClient(
    private val context: Context,
    private val credentialManager: CredentialManager = CredentialManager.create(context),
) : PasskeyClient {

    override suspend fun createCredential(options: PublicKeyCredentialCreationOptions): PasskeyResult<RegistrationResponse> {
        if (options.pubKeyCredParams.isEmpty()) {
            return PasskeyResult.Failure(PasskeyClientError.InvalidOptions("pubKeyCredParams must not be empty"))
        }

        return try {
            // TODO: Serialize options to JSON
            // Minimal valid JSON to pass constructor validation
            val requestJson = """{"rp":{"name":"n","id":"example.com"},"user":{"name":"u","id":"AQ","displayName":"d"},"challenge":"AQ","pubKeyCredParams":[{"type":"public-key","alg":-7}]}"""
            val request = androidx.credentials.CreatePublicKeyCredentialRequest(requestJson)
            val response = credentialManager.createCredential(context, request)
            
            // TODO: Parse response
            throw IllegalStateException("Response parsing not implemented")
        } catch (e: CreateCredentialException) {
            PasskeyResult.Failure(e.toPasskeyClientError())
        } catch (e: Throwable) {
            PasskeyResult.Failure(e.toPasskeyClientError())
        }
    }

    override suspend fun getAssertion(options: PublicKeyCredentialRequestOptions): PasskeyResult<AuthenticationResponse> {
        if (options.allowCredentials.isEmpty()) {
            return PasskeyResult.Failure(PasskeyClientError.InvalidOptions("allowCredentials must not be empty"))
        }

        return try {
            // TODO: Serialize options to JSON
            // Minimal valid JSON to pass constructor validation
            val requestJson = """{"challenge":"AQ","allowCredentials":[{"type":"public-key","id":"AQ"}]}"""
            val request = androidx.credentials.GetPublicKeyCredentialOption(requestJson)
            val getCredRequest = androidx.credentials.GetCredentialRequest(listOf(request))
            val response = credentialManager.getCredential(context, getCredRequest)

            // TODO: Parse response
            throw IllegalStateException("Response parsing not implemented")
        } catch (e: GetCredentialException) {
            PasskeyResult.Failure(e.toPasskeyClientError())
        } catch (e: Throwable) {
            PasskeyResult.Failure(e.toPasskeyClientError())
        }
    }

    private fun Throwable.toPasskeyClientError(): PasskeyClientError = when (this) {
        is CreateCredentialCancellationException,
        is GetCredentialCancellationException -> PasskeyClientError.UserCancelled()
        is NoCredentialException -> PasskeyClientError.Platform("No credentials found")
        else -> PasskeyClientError.Platform(this.message ?: "Unknown platform error", this)
    }
}
