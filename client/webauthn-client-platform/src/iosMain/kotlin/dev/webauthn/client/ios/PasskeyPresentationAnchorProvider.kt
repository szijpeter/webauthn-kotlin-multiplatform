package dev.webauthn.client.ios

import platform.UIKit.UIApplication
import platform.UIKit.UIWindow

/**
 * Provides the current iOS presentation anchor used by AuthenticationServices.
 */
public fun interface PasskeyPresentationAnchorProvider {
    /** Returns the window that AuthenticationServices should use to present its UI. */
    public fun currentAnchorOrNull(): UIWindow?
}

/** Fixed-anchor provider for apps that can keep a stable presentation window. */
public class StaticPasskeyPresentationAnchorProvider(
    private val window: UIWindow,
) : PasskeyPresentationAnchorProvider {
    override fun currentAnchorOrNull(): UIWindow = window
}

/**
 * Mutable provider for retained runtimes where the foreground window may change.
 */
public class MutablePasskeyPresentationAnchorProvider(
    initial: UIWindow? = null,
) : PasskeyPresentationAnchorProvider {
    private var anchor: UIWindow? = initial

    override fun currentAnchorOrNull(): UIWindow? = anchor

    /** Updates the presentation window used by subsequent ceremonies. */
    public fun update(window: UIWindow?) {
        anchor = window
    }
}

internal object UIKitPasskeyPresentationAnchorProvider : PasskeyPresentationAnchorProvider {
    override fun currentAnchorOrNull(): UIWindow? {
        return UIApplication.sharedApplication.keyWindow
    }
}
