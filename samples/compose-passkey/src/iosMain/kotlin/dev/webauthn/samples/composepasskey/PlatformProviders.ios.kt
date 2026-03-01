package dev.webauthn.samples.composepasskey

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.ios.IosPasskeyClient
import io.ktor.client.HttpClient
import io.ktor.client.engine.darwin.Darwin
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.logging.LogLevel
import io.ktor.client.plugins.logging.Logger
import io.ktor.client.plugins.logging.Logging
import io.ktor.serialization.kotlinx.json.json
import kotlinx.serialization.json.Json
import platform.Foundation.NSLog

@Composable
public actual fun rememberPlatformPasskeyClient(): PasskeyClient {
    return remember { IosPasskeyClient() }
}

@Composable
public actual fun rememberPlatformHttpClient(): HttpClient {
    return remember {
        HttpClient(Darwin) {
            install(ContentNegotiation) {
                json(
                    Json {
                        ignoreUnknownKeys = true
                        encodeDefaults = false
                    },
                )
            }
            install(Logging) {
                level = LogLevel.INFO
                logger = object : Logger {
                    override fun log(message: String) {
                        DefaultPasskeyDemoDiagnostics.trace(
                            event = "http.engine",
                            fields = mapOf("line" to sanitizeNetworkLogLine(message)),
                        )
                    }
                }
            }
        }
    }
}

public actual fun platformDefaultEndpointBase(): String = "http://127.0.0.1:8787"

public actual fun platformDebugLog(tag: String, message: String, throwable: Throwable?) {
    val throwableMessage = throwable?.let { " cause=${it.message ?: it::class.simpleName}" }.orEmpty()
    NSLog("$tag: $message$throwableMessage")
}
