package dev.webauthn.samples.composepasskey.data.network

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import dev.webauthn.samples.composepasskey.PasskeyDemoBuildConfig
import io.ktor.client.HttpClient
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.logging.Logger
import io.ktor.client.plugins.logging.Logging
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.Json

@Composable
actual fun rememberPlatformHttpClient(onLogLine: (String) -> Unit): HttpClient {
    return remember(onLogLine) {
        HttpClient(OkHttp) {
            install(ContentNegotiation) {
                json(
                    Json {
                        ignoreUnknownKeys = true
                        encodeDefaults = false
                    },
                )
            }
            install(Logging) {
                level = httpLogLevel(PasskeyDemoBuildConfig.UNSAFE_HTTP_BODY_LOGGING)
                logger = object : Logger {
                    override fun log(message: String) {
                        onLogLine(message)
                    }
                }
            }
        }
    }
}
