package dev.webauthn.samples.composepasskey.data.network

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import dev.webauthn.samples.composepasskey.PasskeyDemoBuildConfig
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp

@Composable
actual fun rememberPlatformHttpClient(onLogLine: (String) -> Unit): HttpClient {
    return remember(onLogLine) {
        HttpClient(OkHttp) {
            configureDemoHttpClient(onLogLine, PasskeyDemoBuildConfig.UNSAFE_HTTP_BODY_LOGGING)
        }
    }
}
