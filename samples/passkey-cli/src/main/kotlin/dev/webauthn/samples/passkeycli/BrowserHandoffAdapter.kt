package dev.webauthn.samples.passkeycli

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpHandler
import com.sun.net.httpserver.HttpServer
import dev.webauthn.serialization.AuthenticationResponseDto
import dev.webauthn.serialization.PublicKeyCredentialCreationOptionsDto
import dev.webauthn.serialization.PublicKeyCredentialRequestOptionsDto
import dev.webauthn.serialization.RegistrationResponseDto
import java.awt.Desktop
import java.net.InetSocketAddress
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.Base64
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.encodeToJsonElement

internal class BrowserHandoffAdapter(
    private val endpointBase: String,
    private val browserLauncher: BrowserLauncher = DesktopBrowserLauncher(),
    private val callbackTimeoutMs: Long = BROWSER_CALLBACK_TIMEOUT_MS,
    private val stdout: Appendable = System.out,
    private val json: Json = Json { ignoreUnknownKeys = true },
) : AuthenticatorAdapter {
    override suspend fun createCredential(
        origin: String,
        options: PublicKeyCredentialCreationOptionsDto,
    ): RegistrationResponseDto {
        val optionsJson = json.encodeToJsonElement(PublicKeyCredentialCreationOptionsDto.serializer(), options)
        val response = invokeBrowser(command = "register", origin = origin, options = optionsJson)
        return json.decodeFromJsonElement(RegistrationResponseDto.serializer(), response)
    }

    override suspend fun getAssertion(
        origin: String,
        options: PublicKeyCredentialRequestOptionsDto,
    ): AuthenticationResponseDto {
        val optionsJson = json.encodeToJsonElement(PublicKeyCredentialRequestOptionsDto.serializer(), options)
        val response = invokeBrowser(command = "authenticate", origin = origin, options = optionsJson)
        return json.decodeFromJsonElement(AuthenticationResponseDto.serializer(), response)
    }

    private suspend fun invokeBrowser(
        command: String,
        origin: String,
        options: JsonElement,
    ): JsonElement {
        val token = randomToken()
        val callbackServer = BrowserCallbackServer(
            token = token,
            origin = origin,
            command = command,
            options = options,
            json = json,
        ).start()

        val browserUrl = buildBrowserUrl(
            endpointBase = endpointBase,
            callbackBase = callbackServer.callbackBase,
            token = token,
            command = command,
        )
        stdout.appendLine("Opening browser for platform passkey flow: $browserUrl")
        if (!browserLauncher.open(URI(browserUrl))) {
            callbackServer.close()
            fail(
                "Unable to open system browser. " +
                    "Open this URL manually to continue: $browserUrl",
            )
        }

        try {
            val completion = try {
                withTimeout(callbackTimeoutMs) {
                    callbackServer.completion.await()
                }
            } catch (_: TimeoutCancellationException) {
                fail(
                    "Timed out waiting for browser handoff callback. " +
                        "Retry the command and complete the browser prompt.",
                )
            }
            if (!completion.ok) {
                fail("Browser handoff returned error: ${completion.error ?: "unknown failure"}")
            }
            return completion.response ?: fail("Browser handoff returned an empty credential payload.")
        } finally {
            callbackServer.close()
        }
    }

    private fun randomToken(): String {
        val bytes = ByteArray(BROWSER_TOKEN_BYTES)
        SecureRandom().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    private fun fail(message: String): Nothing {
        throw IllegalStateException(message)
    }
}

internal fun interface BrowserLauncher {
    fun open(uri: URI): Boolean
}

internal class DesktopBrowserLauncher : BrowserLauncher {
    override fun open(uri: URI): Boolean {
        if (!Desktop.isDesktopSupported()) {
            return false
        }
        val desktop = Desktop.getDesktop()
        if (!desktop.isSupported(Desktop.Action.BROWSE)) {
            return false
        }
        desktop.browse(uri)
        return true
    }
}

private class BrowserCallbackServer(
    private val token: String,
    private val origin: String,
    private val command: String,
    private val options: JsonElement,
    private val json: Json,
) {
    fun start(): RunningBrowserCallbackServer {
        val completion = CompletableDeferred<BrowserCompletionEnvelope>()
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/options", OptionsHandler(token, command, origin, options, json))
        server.createContext("/complete", CompletionHandler(token, completion, json))
        server.start()
        val callbackBase = "http://127.0.0.1:${server.address.port}"
        return RunningBrowserCallbackServer(
            callbackBase = callbackBase,
            completion = completion,
            close = {
                if (!completion.isCompleted) {
                    completion.complete(
                        BrowserCompletionEnvelope(
                            ok = false,
                            error = "Browser callback server stopped before completion.",
                        ),
                    )
                }
                server.stop(0)
            },
        )
    }
}

private data class RunningBrowserCallbackServer(
    val callbackBase: String,
    val completion: CompletableDeferred<BrowserCompletionEnvelope>,
    val close: () -> Unit,
)

private class OptionsHandler(
    private val expectedToken: String,
    private val command: String,
    private val origin: String,
    private val options: JsonElement,
    private val json: Json,
) : HttpHandler {
    override fun handle(exchange: HttpExchange) {
        if (!exchange.authorizeToken(expectedToken)) {
            exchange.respondJson(
                statusCode = 403,
                payload = json.encodeToString(
                    BrowserOptionsEnvelope.serializer(),
                    BrowserOptionsEnvelope(ok = false, error = "invalid token"),
                ),
            )
            return
        }
        if (!exchange.requestMethod.equals("GET", ignoreCase = true)) {
            exchange.respondJson(
                statusCode = 405,
                payload = json.encodeToString(
                    BrowserOptionsEnvelope.serializer(),
                    BrowserOptionsEnvelope(ok = false, error = "method not allowed"),
                ),
            )
            return
        }
        val payload = json.encodeToString(
            BrowserOptionsEnvelope.serializer(),
            BrowserOptionsEnvelope(
                ok = true,
                command = command,
                origin = origin,
                options = options,
            ),
        )
        exchange.respondJson(statusCode = 200, payload = payload)
    }
}

private class CompletionHandler(
    private val expectedToken: String,
    private val completion: CompletableDeferred<BrowserCompletionEnvelope>,
    private val json: Json,
) : HttpHandler {
    override fun handle(exchange: HttpExchange) {
        if (exchange.requestMethod.equals("OPTIONS", ignoreCase = true)) {
            exchange.respondNoContent()
            return
        }
        if (!exchange.authorizeToken(expectedToken)) {
            exchange.respondJson(
                statusCode = 403,
                payload = json.encodeToString(
                    BrowserCompletionEnvelope.serializer(),
                    BrowserCompletionEnvelope(ok = false, error = "invalid token"),
                ),
            )
            return
        }
        if (!exchange.requestMethod.equals("POST", ignoreCase = true)) {
            exchange.respondJson(
                statusCode = 405,
                payload = json.encodeToString(
                    BrowserCompletionEnvelope.serializer(),
                    BrowserCompletionEnvelope(ok = false, error = "method not allowed"),
                ),
            )
            return
        }
        val body = exchange.requestBody.bufferedReader(StandardCharsets.UTF_8).use { it.readText() }
        val envelope = runCatching {
            json.decodeFromString(BrowserCompletionEnvelope.serializer(), body)
        }.getOrElse { error ->
            val failure = BrowserCompletionEnvelope(
                ok = false,
                error = "invalid completion payload: ${error.message}",
            )
            if (!completion.isCompleted) {
                completion.complete(failure)
            }
            exchange.respondJson(
                statusCode = 400,
                payload = json.encodeToString(BrowserCompletionEnvelope.serializer(), failure),
            )
            return
        }
        if (!completion.isCompleted) {
            completion.complete(envelope)
        }
        exchange.respondJson(
            statusCode = 200,
            payload = json.encodeToString(
                BrowserCompletionEnvelope.serializer(),
                BrowserCompletionEnvelope(ok = true),
            ),
        )
    }
}

@Serializable
private data class BrowserOptionsEnvelope(
    val ok: Boolean,
    val command: String? = null,
    val origin: String? = null,
    val options: JsonElement? = null,
    val error: String? = null,
)

@Serializable
private data class BrowserCompletionEnvelope(
    val ok: Boolean,
    val response: JsonElement? = null,
    val error: String? = null,
)

private fun buildBrowserUrl(
    endpointBase: String,
    callbackBase: String,
    token: String,
    command: String,
): String {
    val normalizedEndpoint = endpointBase.trimEnd('/')
    val encodedCallback = URLEncoder.encode(callbackBase, StandardCharsets.UTF_8)
    val encodedToken = URLEncoder.encode(token, StandardCharsets.UTF_8)
    val encodedCommand = URLEncoder.encode(command, StandardCharsets.UTF_8)
    return "$normalizedEndpoint/webauthn/cli/browser?callback=$encodedCallback&token=$encodedToken&command=$encodedCommand"
}

private fun HttpExchange.authorizeToken(expectedToken: String): Boolean {
    val queryToken = requestURI.rawQuery.paramValue("token")
    return queryToken == expectedToken
}

private fun String?.paramValue(name: String): String? {
    if (this.isNullOrBlank()) {
        return null
    }
    return split("&")
        .mapNotNull { entry ->
            val segments = entry.split("=", limit = 2)
            if (segments.firstOrNull() != name) {
                return@mapNotNull null
            }
            URLDecoder.decode(segments.getOrElse(1) { "" }, StandardCharsets.UTF_8)
        }.firstOrNull()
}

private fun HttpExchange.respondNoContent() {
    responseHeaders.add("Access-Control-Allow-Origin", "*")
    responseHeaders.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    responseHeaders.add("Access-Control-Allow-Headers", "Content-Type")
    sendResponseHeaders(204, -1)
    close()
}

private fun HttpExchange.respondJson(
    statusCode: Int,
    payload: String,
) {
    val responseBytes = payload.toByteArray(StandardCharsets.UTF_8)
    responseHeaders.add("Content-Type", "application/json")
    responseHeaders.add("Cache-Control", "no-store")
    responseHeaders.add("Access-Control-Allow-Origin", "*")
    responseHeaders.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    responseHeaders.add("Access-Control-Allow-Headers", "Content-Type")
    sendResponseHeaders(statusCode, responseBytes.size.toLong())
    responseBody.use { stream ->
        stream.write(responseBytes)
    }
}

private const val BROWSER_TOKEN_BYTES: Int = 24
private const val BROWSER_CALLBACK_TIMEOUT_MS: Long = 180_000
