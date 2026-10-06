package dev.webauthn.samples.composepasskey.data.network

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import dev.webauthn.samples.composepasskey.PasskeyDemoBuildConfig
import io.ktor.client.HttpClient
import io.ktor.client.engine.darwin.Darwin

@Composable
actual fun rememberPlatformHttpClient(onLogLine: (String) -> Unit): HttpClient {
    return remember(onLogLine) {
        HttpClient(Darwin) {
            configureDemoHttpClient(onLogLine, PasskeyDemoBuildConfig.UNSAFE_HTTP_BODY_LOGGING)
        }
    }
}
