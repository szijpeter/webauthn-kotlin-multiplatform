package dev.webauthn.client.ios

import dev.webauthn.client.PasskeyClientError
import platform.AuthenticationServices.ASAuthorizationErrorCanceled
import platform.AuthenticationServices.ASAuthorizationErrorDomain
import platform.AuthenticationServices.ASAuthorizationErrorNotHandled
import platform.AuthenticationServices.ASAuthorizationErrorFailed
import platform.Foundation.NSError

internal class NSErrorException(val error: NSError) : RuntimeException(error.localizedDescription)

internal fun NSError.toPasskeyClientError(): PasskeyClientError {
    if (this.domain == ASAuthorizationErrorDomain) {
        when (this.code) {
            ASAuthorizationErrorCanceled -> return PasskeyClientError.UserCancelled()
            ASAuthorizationErrorNotHandled -> return PasskeyClientError.Platform("Request not handled", NSErrorException(this))
            ASAuthorizationErrorFailed -> return PasskeyClientError.Platform("Authorization failed", NSErrorException(this))
            else -> return PasskeyClientError.Platform(this.localizedDescription, NSErrorException(this))
        }
    }
    return PasskeyClientError.Platform(this.localizedDescription, NSErrorException(this))
}
