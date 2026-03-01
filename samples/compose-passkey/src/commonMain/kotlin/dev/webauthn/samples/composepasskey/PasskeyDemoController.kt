package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyClient
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyResult
import dev.webauthn.model.ValidationResult
import dev.webauthn.network.AuthenticationFinishPayload
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationFinishPayload
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.network.WebAuthnBackendProfile
import dev.webauthn.network.WebAuthnInteropKtorClient
import dev.webauthn.serialization.WebAuthnDtoMapper
import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.http.isSuccess
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

public data class PasskeyDemoConfig(
    public val endpointBase: String = platformDefaultEndpointBase(),
    public val rpId: String = "localhost",
    public val origin: String = "https://localhost",
    public val userHandle: String = "demo-user-1",
    public val userName: String = "demo@local",
)

public enum class StatusTone {
    IDLE,
    WORKING,
    SUCCESS,
    WARNING,
    ERROR,
}

public data class PasskeyDemoLogEntry(
    public val id: Long,
    public val timestamp: String,
    public val tone: StatusTone,
    public val message: String,
)

public data class PasskeyDemoUiState(
    public val config: PasskeyDemoConfig = PasskeyDemoConfig(),
    public val capabilities: PasskeyCapabilities = PasskeyCapabilities(),
    public val statusTone: StatusTone = StatusTone.IDLE,
    public val statusHeadline: String = "Ready",
    public val statusDetail: String? = null,
    public val isBusy: Boolean = false,
    public val logs: List<PasskeyDemoLogEntry> = emptyList(),
)

public sealed interface PasskeyDemoIntent {
    public data class EndpointBaseChanged(public val value: String) : PasskeyDemoIntent
    public data class RpIdChanged(public val value: String) : PasskeyDemoIntent
    public data class OriginChanged(public val value: String) : PasskeyDemoIntent
    public data class UserHandleChanged(public val value: String) : PasskeyDemoIntent
    public data class UserNameChanged(public val value: String) : PasskeyDemoIntent
    public data object RefreshCapabilities : PasskeyDemoIntent
    public data object CheckHealth : PasskeyDemoIntent
    public data object Register : PasskeyDemoIntent
    public data object SignIn : PasskeyDemoIntent
}

public enum class PasskeyDemoErrorCategory(public val label: String) {
    VALIDATION("Validation"),
    INVALID_OPTIONS("Invalid Options"),
    USER_CANCELLED("User Cancelled"),
    PLATFORM("Platform"),
    TRANSPORT("Transport"),
    UNKNOWN("Unknown"),
}

public sealed interface PasskeyDemoActionResult {
    public data class Success(public val message: String) : PasskeyDemoActionResult

    public data class Failure(
        public val category: PasskeyDemoErrorCategory,
        public val message: String,
    ) : PasskeyDemoActionResult
}

public interface PasskeyDemoGateway {
    public suspend fun checkHealth(config: PasskeyDemoConfig): PasskeyDemoActionResult

    public suspend fun register(config: PasskeyDemoConfig): PasskeyDemoActionResult

    public suspend fun authenticate(config: PasskeyDemoConfig): PasskeyDemoActionResult

    public suspend fun capabilities(): PasskeyCapabilities
}

public class DefaultPasskeyDemoGateway(
    private val passkeyClient: PasskeyClient,
    private val httpClient: HttpClient,
    private val diagnostics: PasskeyDemoDiagnostics = DefaultPasskeyDemoDiagnostics,
) : PasskeyDemoGateway {
    private var nextOperationId: Long = 1L

    override suspend fun checkHealth(config: PasskeyDemoConfig): PasskeyDemoActionResult {
        val operationId = nextOperationId("health")
        diagnostics.trace(
            event = "health.start",
            fields = mapOf(
                "operationId" to operationId,
                "endpoint" to config.endpointBase,
            ),
        )

        return runCatching {
            val response = httpClient.get("${config.endpointBase.normalizedEndpoint()}/health")
            if (response.status.isSuccess()) {
                diagnostics.trace(
                    event = "health.success",
                    fields = mapOf(
                        "operationId" to operationId,
                        "status" to response.status.value.toString(),
                    ),
                )
                PasskeyDemoActionResult.Success("Temp server is healthy (${response.status.value}).")
            } else {
                PasskeyDemoActionResult.Failure(
                    category = PasskeyDemoErrorCategory.TRANSPORT,
                    message = "Health check failed with HTTP ${response.status.value}.",
                )
            }
        }.getOrElse { error ->
            diagnostics.error(
                event = "health.failure",
                message = error.message ?: "Health check failed",
                throwable = error,
                fields = mapOf(
                    "operationId" to operationId,
                    "endpoint" to config.endpointBase,
                ),
            )
            PasskeyDemoActionResult.Failure(
                category = PasskeyDemoErrorCategory.TRANSPORT,
                message = error.message ?: "Unable to reach temp server.",
            )
        }
    }

    override suspend fun register(config: PasskeyDemoConfig): PasskeyDemoActionResult {
        val operationId = nextOperationId("register")
        diagnostics.trace(
            event = "register.start",
            fields = mapOf(
                "operationId" to operationId,
                "endpoint" to config.endpointBase,
                "rpId" to config.rpId,
                "userName" to config.userName,
            ),
        )

        return runCatching {
            val interop = interopClient(config)
            val registrationStart = interop.startRegistration(
                RegistrationStartPayload(
                    rpId = config.rpId,
                    rpName = "WebAuthn Kotlin MPP Temp Server",
                    origin = config.origin,
                    userName = config.userName,
                    userDisplayName = config.userName,
                    userHandle = config.userHandle,
                ),
            )

            val options = registrationStart.requireValid()
            if (options == null) {
                val failure = registrationStart.toValidationFailure("startRegistration")
                diagnostics.trace(
                    event = "register.validation_failure",
                    fields = mapOf(
                        "operationId" to operationId,
                        "message" to failure.message,
                    ),
                )
                failure
            } else {
                diagnostics.trace(
                    event = "register.passkey.create_credential",
                    fields = mapOf("operationId" to operationId),
                )
                when (val result = passkeyClient.createCredential(options)) {
                    is PasskeyResult.Success -> {
                        diagnostics.trace(
                            event = "register.finish_verify.start",
                            fields = mapOf("operationId" to operationId),
                        )
                        val verified = interop.finishRegistration(
                            RegistrationFinishPayload(
                                response = WebAuthnDtoMapper.fromModel(result.value),
                                clientDataType = "webauthn.create",
                                challenge = options.challenge.value.encoded(),
                                origin = config.origin,
                            ),
                        )
                        if (verified) {
                            diagnostics.trace(
                                event = "register.success",
                                fields = mapOf("operationId" to operationId),
                            )
                            PasskeyDemoActionResult.Success("Registration complete for ${config.userName}.")
                        } else {
                            PasskeyDemoActionResult.Failure(
                                category = PasskeyDemoErrorCategory.TRANSPORT,
                                message = "Server rejected registration verification.",
                            )
                        }
                    }

                    is PasskeyResult.Failure -> {
                        val failure = result.error.toFailure(prefix = "Registration")
                        diagnostics.trace(
                            event = "register.platform_failure",
                            fields = mapOf(
                                "operationId" to operationId,
                                "category" to failure.category.label,
                                "message" to failure.message,
                            ),
                        )
                        failure
                    }
                }
            }
        }.getOrElse { throwable ->
            diagnostics.error(
                event = "register.failure",
                message = throwable.message ?: "Registration failed",
                throwable = throwable,
                fields = mapOf("operationId" to operationId),
            )
            throwable.toUnexpectedFailure(prefix = "Registration")
        }
    }

    override suspend fun authenticate(config: PasskeyDemoConfig): PasskeyDemoActionResult {
        val operationId = nextOperationId("authenticate")
        diagnostics.trace(
            event = "auth.start",
            fields = mapOf(
                "operationId" to operationId,
                "endpoint" to config.endpointBase,
                "rpId" to config.rpId,
                "userHandle" to config.userHandle,
            ),
        )

        return runCatching {
            val interop = interopClient(config)
            val authenticationStart = interop.startAuthentication(
                AuthenticationStartPayload(
                    rpId = config.rpId,
                    origin = config.origin,
                    userName = config.userHandle,
                ),
            )

            val options = authenticationStart.requireValid()
            if (options == null) {
                val failure = authenticationStart.toValidationFailure("startAuthentication")
                diagnostics.trace(
                    event = "auth.validation_failure",
                    fields = mapOf(
                        "operationId" to operationId,
                        "message" to failure.message,
                    ),
                )
                failure
            } else {
                diagnostics.trace(
                    event = "auth.passkey.get_assertion",
                    fields = mapOf("operationId" to operationId),
                )
                when (val result = passkeyClient.getAssertion(options)) {
                    is PasskeyResult.Success -> {
                        diagnostics.trace(
                            event = "auth.finish_verify.start",
                            fields = mapOf("operationId" to operationId),
                        )
                        val verified = interop.finishAuthentication(
                            AuthenticationFinishPayload(
                                response = WebAuthnDtoMapper.fromModel(result.value),
                                clientDataType = "webauthn.get",
                                challenge = options.challenge.value.encoded(),
                                origin = config.origin,
                            ),
                        )
                        if (verified) {
                            diagnostics.trace(
                                event = "auth.success",
                                fields = mapOf("operationId" to operationId),
                            )
                            PasskeyDemoActionResult.Success("Sign-in complete for ${config.userHandle}.")
                        } else {
                            PasskeyDemoActionResult.Failure(
                                category = PasskeyDemoErrorCategory.TRANSPORT,
                                message = "Server rejected authentication verification.",
                            )
                        }
                    }

                    is PasskeyResult.Failure -> {
                        val failure = result.error.toFailure(prefix = "Authentication")
                        diagnostics.trace(
                            event = "auth.platform_failure",
                            fields = mapOf(
                                "operationId" to operationId,
                                "category" to failure.category.label,
                                "message" to failure.message,
                            ),
                        )
                        failure
                    }
                }
            }
        }.getOrElse { throwable ->
            diagnostics.error(
                event = "auth.failure",
                message = throwable.message ?: "Authentication failed",
                throwable = throwable,
                fields = mapOf("operationId" to operationId),
            )
            throwable.toUnexpectedFailure(prefix = "Authentication")
        }
    }

    override suspend fun capabilities(): PasskeyCapabilities {
        return passkeyClient.capabilities()
    }

    private fun interopClient(config: PasskeyDemoConfig): WebAuthnInteropKtorClient {
        return WebAuthnInteropKtorClient(
            httpClient = httpClient,
            endpointBase = config.endpointBase.normalizedEndpoint(),
            profile = WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC,
        )
    }

    private fun nextOperationId(action: String): String {
        val id = "$action-${nextOperationId++}"
        return id
    }
}

public class PasskeyDemoController(
    private val gateway: PasskeyDemoGateway,
    private val diagnostics: PasskeyDemoDiagnostics = DefaultPasskeyDemoDiagnostics,
    private val timestampProvider: (() -> String)? = null,
    private val maxLogEntries: Int = 40,
) {
    private val mutex = Mutex()
    private val mutableState = MutableStateFlow(PasskeyDemoUiState())
    private var nextLogId: Long = 1L
    private var fallbackTick: Long = 0L
    private var nextOperationId: Long = 1L

    public val state: StateFlow<PasskeyDemoUiState> = mutableState.asStateFlow()

    public suspend fun bootstrap() {
        dispatch(PasskeyDemoIntent.RefreshCapabilities)
    }

    public suspend fun dispatch(intent: PasskeyDemoIntent) {
        when (intent) {
            is PasskeyDemoIntent.EndpointBaseChanged -> updateConfig { copy(endpointBase = intent.value) }
            is PasskeyDemoIntent.RpIdChanged -> updateConfig { copy(rpId = intent.value) }
            is PasskeyDemoIntent.OriginChanged -> updateConfig { copy(origin = intent.value) }
            is PasskeyDemoIntent.UserHandleChanged -> updateConfig { copy(userHandle = intent.value) }
            is PasskeyDemoIntent.UserNameChanged -> updateConfig { copy(userName = intent.value) }
            PasskeyDemoIntent.RefreshCapabilities -> refreshCapabilities()
            PasskeyDemoIntent.CheckHealth -> runAction("Health Check") { config -> gateway.checkHealth(config) }
            PasskeyDemoIntent.Register -> runAction("Register") { config -> gateway.register(config) }
            PasskeyDemoIntent.SignIn -> runAction("Sign In") { config -> gateway.authenticate(config) }
        }
    }

    private fun updateConfig(transform: PasskeyDemoConfig.() -> PasskeyDemoConfig) {
        mutableState.update { state ->
            state.copy(
                config = state.config.transform(),
            )
        }
    }

    private suspend fun refreshCapabilities() {
        mutex.withLock {
            diagnostics.trace(event = "capabilities.load.start")
            val capabilities = runCatching { gateway.capabilities() }.getOrElse { error ->
                diagnostics.error(
                    event = "capabilities.load.fallback",
                    message = "Capabilities unavailable, using safe defaults.",
                    throwable = error,
                )
                appendLog(StatusTone.WARNING, "Capabilities unavailable, using safe defaults.")
                PasskeyCapabilities()
            }
            mutableState.update { state -> state.copy(capabilities = capabilities) }
            val message = "Capabilities loaded: PRF=${capabilities.supportsPrf}, LargeBlobRead=${capabilities.supportsLargeBlobRead}, LargeBlobWrite=${capabilities.supportsLargeBlobWrite}, SecurityKey=${capabilities.supportsSecurityKey}"
            diagnostics.trace(
                event = "capabilities.load.success",
                fields = mapOf(
                    "supportsPrf" to capabilities.supportsPrf.toString(),
                    "supportsLargeBlobRead" to capabilities.supportsLargeBlobRead.toString(),
                    "supportsLargeBlobWrite" to capabilities.supportsLargeBlobWrite.toString(),
                    "supportsSecurityKey" to capabilities.supportsSecurityKey.toString(),
                ),
            )
            appendLog(tone = StatusTone.IDLE, message = message)
        }
    }

    private suspend fun runAction(
        actionName: String,
        block: suspend (PasskeyDemoConfig) -> PasskeyDemoActionResult,
    ) {
        mutex.withLock {
            val operationId = nextOperationId(actionName)
            val config = mutableState.value.config.sanitized()
            mutableState.update {
                it.copy(
                    config = config,
                    isBusy = true,
                    statusTone = StatusTone.WORKING,
                    statusHeadline = "$actionName in progress...",
                    statusDetail = null,
                )
            }
            appendLog(StatusTone.WORKING, "$actionName started")
            diagnostics.trace(
                event = "action.start",
                fields = mapOf(
                    "operationId" to operationId,
                    "action" to actionName,
                ),
            )

            val result = runCatching { block(config) }
                .getOrElse { throwable ->
                    diagnostics.error(
                        event = "action.failure.unexpected",
                        message = "$actionName threw unexpected exception",
                        throwable = throwable,
                        fields = mapOf("operationId" to operationId),
                    )
                    throwable.toUnexpectedFailure(prefix = actionName)
                }

            when (result) {
                is PasskeyDemoActionResult.Success -> {
                    mutableState.update {
                        it.copy(
                            isBusy = false,
                            statusTone = StatusTone.SUCCESS,
                            statusHeadline = result.message,
                            statusDetail = null,
                        )
                    }
                    appendLog(StatusTone.SUCCESS, result.message)
                    diagnostics.trace(
                        event = "action.success",
                        fields = mapOf(
                            "operationId" to operationId,
                            "action" to actionName,
                        ),
                    )
                }

                is PasskeyDemoActionResult.Failure -> {
                    val tone = when (result.category) {
                        PasskeyDemoErrorCategory.USER_CANCELLED -> StatusTone.WARNING
                        else -> StatusTone.ERROR
                    }
                    val normalizedMessage = result.message.withProviderDependencyHint()
                    val detailedMessage = "[${result.category.label}] $normalizedMessage"
                    mutableState.update {
                        it.copy(
                            isBusy = false,
                            statusTone = tone,
                            statusHeadline = result.category.label,
                            statusDetail = detailedMessage,
                        )
                    }
                    appendLog(tone, detailedMessage)
                    diagnostics.trace(
                        event = "action.failure",
                        fields = mapOf(
                            "operationId" to operationId,
                            "action" to actionName,
                            "category" to result.category.label,
                            "message" to detailedMessage,
                        ),
                    )
                }
            }
        }
    }

    private fun nextOperationId(actionName: String): String {
        val normalizedAction = actionName.lowercase().replace(" ", "-")
        return "$normalizedAction-${nextOperationId++}"
    }

    private fun appendLog(tone: StatusTone, message: String) {
        val entry = PasskeyDemoLogEntry(
            id = nextLogId++,
            timestamp = timestampProvider?.invoke() ?: "t+${++fallbackTick}s",
            tone = tone,
            message = message,
        )
        mutableState.update { state ->
            val updated = listOf(entry) + state.logs
            state.copy(logs = updated.take(maxLogEntries))
        }
    }
}

private fun String.normalizedEndpoint(): String {
    val trimmed = trim()
    return trimmed.trimEnd('/')
}

private fun PasskeyDemoConfig.sanitized(): PasskeyDemoConfig {
    return copy(
        endpointBase = endpointBase.normalizedEndpoint(),
        rpId = rpId.trim(),
        origin = origin.trim(),
        userHandle = userHandle.trim(),
        userName = userName.trim(),
    )
}

private fun ValidationResult<*>.toValidationFailure(step: String): PasskeyDemoActionResult.Failure {
    val details = when (this) {
        is ValidationResult.Valid<*> -> "Unexpected valid result"
        is ValidationResult.Invalid -> errors.joinToString("; ") { "${it.field}: ${it.message}" }
    }
    return PasskeyDemoActionResult.Failure(
        category = PasskeyDemoErrorCategory.VALIDATION,
        message = "$step validation failed: $details",
    )
}

private fun <T> ValidationResult<T>.requireValid(): T? {
    return when (this) {
        is ValidationResult.Valid -> value
        is ValidationResult.Invalid -> null
    }
}

private fun Throwable.toUnexpectedFailure(prefix: String): PasskeyDemoActionResult.Failure {
    val reason = message?.takeIf { it.isNotBlank() } ?: "Unexpected error"
    val category = reason.toThrowableCategory()
    return PasskeyDemoActionResult.Failure(
        category = category,
        message = "$prefix failed: ${reason.withProviderDependencyHint()}",
    )
}

private fun String.toThrowableCategory(): PasskeyDemoErrorCategory {
    val lowered = lowercase()
    return when {
        lowered.contains("provider") ||
            lowered.contains("createcredential") ||
            lowered.contains("getcredential") ||
            lowered.contains("passkey") -> PasskeyDemoErrorCategory.PLATFORM

        lowered.contains("http") ||
            lowered.contains("network") ||
            lowered.contains("timeout") ||
            lowered.contains("connection") ||
            lowered.contains("resolve host") ||
            lowered.contains("cleartext") -> PasskeyDemoErrorCategory.TRANSPORT

        else -> PasskeyDemoErrorCategory.UNKNOWN
    }
}

private fun String.withProviderDependencyHint(): String {
    val lowered = lowercase()
    return if (lowered.contains("no provider dependencies found")) {
        "$this. Add androidx.credentials:credentials-play-services-auth and use a Google Play-enabled emulator/device."
    } else {
        this
    }
}

private fun PasskeyClientError.toFailure(prefix: String): PasskeyDemoActionResult.Failure {
    val category = when (this) {
        is PasskeyClientError.InvalidOptions -> PasskeyDemoErrorCategory.INVALID_OPTIONS
        is PasskeyClientError.UserCancelled -> PasskeyDemoErrorCategory.USER_CANCELLED
        is PasskeyClientError.Platform -> PasskeyDemoErrorCategory.PLATFORM
        is PasskeyClientError.Transport -> PasskeyDemoErrorCategory.TRANSPORT
    }
    return PasskeyDemoActionResult.Failure(
        category = category,
        message = "$prefix failed: ${message.withProviderDependencyHint()}",
    )
}
