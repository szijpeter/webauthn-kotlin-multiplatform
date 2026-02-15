package dev.webauthn.client.android

import android.content.Context
import androidx.credentials.CredentialManager
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.GetCredentialRequest
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.exceptions.CreateCredentialInterruptedException
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.PublicKeyCredentialRpEntity
import dev.webauthn.model.PublicKeyCredentialUserEntity
import dev.webauthn.model.RpId
import dev.webauthn.model.Challenge
import dev.webauthn.model.UserHandle
import dev.webauthn.model.PublicKeyCredentialParameters
import dev.webauthn.model.PublicKeyCredentialType
import kotlinx.coroutines.runBlocking
import io.mockk.mockk
import io.mockk.coEvery
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class AndroidPasskeyClientTest {

    @Test
    fun createCredential_returns_InvalidOptions_when_pubKeyCredParams_is_empty() = runBlocking {
        val client = AndroidPasskeyClient(mockk(relaxed = true), mockk(relaxed = true))
        val options = PublicKeyCredentialCreationOptions(
            rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.com"), "name"),
            user = PublicKeyCredentialUserEntity(UserHandle.fromBytes(byteArrayOf(1)), "name", "display"),
            challenge = Challenge.fromBytes(ByteArray(32) { 0 }),
            pubKeyCredParams = emptyList()
        )
        val result = client.createCredential(options)
        assertTrue(result is PasskeyResult.Failure)
        assertTrue((result as PasskeyResult.Failure).error is PasskeyClientError.InvalidOptions)
    }

    @Test
    fun createCredential_returns_UserCancelled_on_cancellation_exception() = runBlocking {
        val mockCredentialManager = mockk<CredentialManager>(relaxed = true)
        val client = AndroidPasskeyClient(mockk(relaxed = true), mockCredentialManager)
        
        coEvery { mockCredentialManager.createCredential(any<Context>(), any<CreatePublicKeyCredentialRequest>()) } throws CreateCredentialCancellationException("Cancelled")

        val options = PublicKeyCredentialCreationOptions(
            rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.com"), "name"),
            user = PublicKeyCredentialUserEntity(UserHandle.fromBytes(byteArrayOf(1)), "name", "display"),
            challenge = Challenge.fromBytes(ByteArray(32) { 0 }),
            pubKeyCredParams = listOf(PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7))
        )

        val result = client.createCredential(options)
        assertTrue("Result should be Failure but was $result", result is PasskeyResult.Failure)
        val failure = result as PasskeyResult.Failure
        assertTrue("Error should be UserCancelled but was ${failure.error}", failure.error is PasskeyClientError.UserCancelled)
    }

    @Test
    fun createCredential_returns_Platform_error_on_other_exception() = runBlocking {
        val mockCredentialManager = mockk<CredentialManager>(relaxed = true)
        val client = AndroidPasskeyClient(mockk(relaxed = true), mockCredentialManager)
        
        coEvery { mockCredentialManager.createCredential(any<Context>(), any<CreatePublicKeyCredentialRequest>()) } throws CreateCredentialInterruptedException("Interrupted")

        val options = PublicKeyCredentialCreationOptions(
            rp = PublicKeyCredentialRpEntity(RpId.parseOrThrow("example.com"), "name"),
            user = PublicKeyCredentialUserEntity(UserHandle.fromBytes(byteArrayOf(1)), "name", "display"),
            challenge = Challenge.fromBytes(ByteArray(32) { 0 }),
            pubKeyCredParams = listOf(PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7))
        )

        val result = client.createCredential(options)
        assertTrue(result is PasskeyResult.Failure)
        val failure = result as PasskeyResult.Failure
        assertTrue(failure.error is PasskeyClientError.Platform)
        assertTrue(failure.error.message.contains("Interrupted"))
    }

    @Test
    fun getAssertion_allows_empty_allowCredentials() = runBlocking {
        val mockCredentialManager = mockk<CredentialManager>(relaxed = true)
        val client = AndroidPasskeyClient(mockk(relaxed = true), mockCredentialManager)
        coEvery { mockCredentialManager.getCredential(any<Context>(), any<GetCredentialRequest>()) } throws GetCredentialCancellationException("Cancelled")

        val options = PublicKeyCredentialRequestOptions(
            challenge = Challenge.fromBytes(ByteArray(32) { 0 }),
            rpId = RpId.parseOrThrow("example.com"),
            allowCredentials = emptyList(),
        )
        val result = client.getAssertion(options)
        assertTrue(result is PasskeyResult.Failure)
        assertTrue((result as PasskeyResult.Failure).error is PasskeyClientError.UserCancelled)
    }

    @Test
    fun getAssertion_returns_UserCancelled_on_cancellation_exception() = runBlocking {
        val mockCredentialManager = mockk<CredentialManager>(relaxed = true)
        val client = AndroidPasskeyClient(mockk(relaxed = true), mockCredentialManager)
        
        coEvery { mockCredentialManager.getCredential(any<Context>(), any<GetCredentialRequest>()) } throws GetCredentialCancellationException("Cancelled")

        val options = PublicKeyCredentialRequestOptions(
            challenge = Challenge.fromBytes(ByteArray(32) { 0 }),
            rpId = RpId.parseOrThrow("example.com"),
            allowCredentials = listOf(
                dev.webauthn.model.PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, dev.webauthn.model.CredentialId.fromBytes(byteArrayOf(1)))
            )
        )

        val result = client.getAssertion(options)
        assertTrue(result is PasskeyResult.Failure)
        val failure = result as PasskeyResult.Failure
        assertTrue(failure.error is PasskeyClientError.UserCancelled)
    }
    
    @Test
    fun getAssertion_returns_Platform_error_on_NoCredentialException() = runBlocking {
        val mockCredentialManager = mockk<CredentialManager>(relaxed = true)
        val client = AndroidPasskeyClient(mockk(relaxed = true), mockCredentialManager)
        
        coEvery { mockCredentialManager.getCredential(any<Context>(), any<GetCredentialRequest>()) } throws NoCredentialException("No creds")

        val options = PublicKeyCredentialRequestOptions(
            challenge = Challenge.fromBytes(ByteArray(32) { 0 }),
            rpId = RpId.parseOrThrow("example.com"),
            allowCredentials = listOf(
                dev.webauthn.model.PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, dev.webauthn.model.CredentialId.fromBytes(byteArrayOf(1)))
            )
        )

        val result = client.getAssertion(options)
        assertTrue(result is PasskeyResult.Failure)
        val failure = result as PasskeyResult.Failure
        assertTrue(failure.error is PasskeyClientError.Platform)
        assertEquals("No credentials found", failure.error.message)
    }
}
