package dev.webauthn.client.defaults

import android.content.Context
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.android.AndroidPasskeyClient

/** Creates the recommended Android platform client while allowing component-level overrides. */
public fun defaultPasskeyClient(
    context: Context,
    configure: DefaultPasskeyClientConfiguration.() -> Unit = {},
): PasskeyClient {
    val configuration = DefaultPasskeyClientConfiguration().apply(configure)
    return AndroidPasskeyClient(context = context, codec = configuration.codec)
}
