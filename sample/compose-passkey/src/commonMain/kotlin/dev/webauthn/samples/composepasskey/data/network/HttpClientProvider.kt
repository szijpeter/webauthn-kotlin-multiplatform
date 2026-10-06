package dev.webauthn.samples.composepasskey.data.network

import androidx.compose.runtime.Composable
import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.plugins.api.createClientPlugin
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.logging.Logger
import io.ktor.client.plugins.logging.Logging
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.Json
import io.ktor.client.plugins.logging.LogLevel

@Composable
expect fun rememberPlatformHttpClient(onLogLine: (String) -> Unit): HttpClient

internal fun httpLogLevel(unsafeBodyLogging: Boolean): LogLevel {
    return if (unsafeBodyLogging) LogLevel.BODY else LogLevel.NONE
}

internal fun HttpClientConfig<*>.configureDemoHttpClient(
    onLogLine: (String) -> Unit,
    unsafeBodyLogging: Boolean = false,
) {
    install(ContentNegotiation) {
        json(Json { ignoreUnknownKeys = true; encodeDefaults = false })
    }
    val metadata = createClientPlugin("DemoHttpMetadata") {
        onRequest { request, _ -> onLogLine("request method=${request.method.value} host=${request.url.host}") }
        onResponse { response -> onLogLine("response status=${response.status.value}") }
    }
    install(metadata)
    if (unsafeBodyLogging) {
        install(Logging) {
            level = httpLogLevel(unsafeBodyLogging)
            logger = object : Logger {
                override fun log(message: String) = onLogLine(message)
            }
        }
    }
}
