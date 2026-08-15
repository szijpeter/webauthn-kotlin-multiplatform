package dev.webauthn.client.ios

import platform.UIKit.UIApplication
import platform.UIKit.UIWindow

/**
 * Provides the current iOS presentation anchor used by AuthenticationServices.
 */
internal fun interface PasskeyPresentationAnchorProvider {
    fun currentAnchorOrNull(): UIWindow?
}

/** Fixed-anchor provider for apps that can keep a stable presentation window. */
internal class StaticPasskeyPresentationAnchorProvider(
    private val window: UIWindow,
) : PasskeyPresentationAnchorProvider {
    override fun currentAnchorOrNull(): UIWindow = window
}

/**
 * Mutable provider for retained runtimes where the foreground window may change.
 */
internal class MutablePasskeyPresentationAnchorProvider(
    initial: UIWindow? = null,
) : PasskeyPresentationAnchorProvider {
    private var anchor: UIWindow? = initial

    override fun currentAnchorOrNull(): UIWindow? = anchor

    fun update(window: UIWindow?) {
        anchor = window
    }
}

internal object UIKitPasskeyPresentationAnchorProvider : PasskeyPresentationAnchorProvider {
    override fun currentAnchorOrNull(): UIWindow? {
        return UIApplication.sharedApplication.keyWindow
    }
}
