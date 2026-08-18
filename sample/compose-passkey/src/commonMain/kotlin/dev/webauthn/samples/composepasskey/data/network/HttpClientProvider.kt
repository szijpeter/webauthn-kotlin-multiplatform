package dev.webauthn.samples.composepasskey.data.network

import androidx.compose.runtime.Composable
import io.ktor.client.HttpClient
import io.ktor.client.plugins.logging.LogLevel

@Composable
expect fun rememberPlatformHttpClient(onLogLine: (String) -> Unit): HttpClient

internal fun httpLogLevel(unsafeBodyLogging: Boolean): LogLevel {
    return if (unsafeBodyLogging) LogLevel.BODY else LogLevel.INFO
}
