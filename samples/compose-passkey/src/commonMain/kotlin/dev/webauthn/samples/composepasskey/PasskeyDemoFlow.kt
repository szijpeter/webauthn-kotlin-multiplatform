package dev.webauthn.samples.composepasskey

import dev.webauthn.client.PasskeyAction
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyController
import dev.webauthn.client.PasskeyControllerState
import dev.webauthn.client.PasskeyPhase
import dev.webauthn.model.PublicKeyCredentialCreationOptions
import dev.webauthn.model.PublicKeyCredentialRequestOptions
import dev.webauthn.model.RegistrationResponse
import dev.webauthn.model.ValidationResult
import dev.webauthn.network.AuthenticationFinishPayload
import dev.webauthn.network.AuthenticationStartPayload
import dev.webauthn.network.RegistrationFinishPayload
import dev.webauthn.network.RegistrationStartPayload
import dev.webauthn.network.WebAuthnBackendProfile
import dev.webauthn.network.WebAuthnInteropKtorClient
import dev.webauthn.serialization.WebAuthnDtoMapper
import io.ktor.client.HttpClient

public data class PasskeyDemoConfig(
    public val endpointBase: String = PasskeyDemoBuildConfig.ENDPOINT_BASE,
    public val rpId: String = resolveDefaultRpId(
        endpointBase = PasskeyDemoBuildConfig.ENDPOINT_BASE,
        configuredRpId = PasskeyDemoBuildConfig.RP_ID,
    ),
    public val origin: String = resolveDefaultOrigin(
        rpId = rpId,
        configuredOrigin = PasskeyDemoBuildConfig.ORIGIN,
    ),
    public val userHandle: String = PasskeyDemoBuildConfig.USER_ID,
    public val userName: String = PasskeyDemoBuildConfig.USER_NAME,
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

internal data class PasskeyDemoStatus(
    val tone: StatusTone,
    val headline: String,
    val detail: String? = null,
)

internal interface PasskeyDemoBackend {
    suspend fun startRegistration(config: PasskeyDemoConfig): ValidationResult<PublicKeyCredentialCreationOptions>

    suspend fun finishRegistration(
        config: PasskeyDemoConfig,
        response: RegistrationResponse,
        challenge: String,
    ): Boolean

    suspend fun startAuthentication(config: PasskeyDemoConfig): ValidationResult<PublicKeyCredentialRequestOptions>

    suspend fun finishAuthentication(
        config: PasskeyDemoConfig,
        response: dev.webauthn.model.AuthenticationResponse,
        challenge: String,
    ): Boolean
}

internal class InteropPasskeyDemoBackend(
    private val interop: WebAuthnInteropKtorClient,
) : PasskeyDemoBackend {
    override suspend fun startRegistration(config: PasskeyDemoConfig): ValidationResult<PublicKeyCredentialCreationOptions> {
        return interop.startRegistration(
            RegistrationStartPayload(
                rpId = config.rpId,
                rpName = "WebAuthn Kotlin MPP Temp Server",
                origin = config.origin,
                userName = config.userName,
                userDisplayName = config.userName,
                userHandle = config.userHandle,
            ),
        )
    }

    override suspend fun finishRegistration(
        config: PasskeyDemoConfig,
        response: RegistrationResponse,
        challenge: String,
    ): Boolean {
        return interop.finishRegistration(
            RegistrationFinishPayload(
                response = WebAuthnDtoMapper.fromModel(response),
                clientDataType = "webauthn.create",
                challenge = challenge,
                origin = config.origin,
            ),
        )
    }

    override suspend fun startAuthentication(config: PasskeyDemoConfig): ValidationResult<PublicKeyCredentialRequestOptions> {
        return interop.startAuthentication(
            AuthenticationStartPayload(
                rpId = config.rpId,
                origin = config.origin,
                userName = config.userName,
                userHandle = config.userHandle,
            ),
        )
    }

    override suspend fun finishAuthentication(
        config: PasskeyDemoConfig,
        response: dev.webauthn.model.AuthenticationResponse,
        challenge: String,
    ): Boolean {
        return interop.finishAuthentication(
            AuthenticationFinishPayload(
                response = WebAuthnDtoMapper.fromModel(response),
                clientDataType = "webauthn.get",
                challenge = challenge,
                origin = config.origin,
            ),
        )
    }
}

internal fun createPasskeyDemoBackend(
    httpClient: HttpClient,
    config: PasskeyDemoConfig,
): PasskeyDemoBackend {
    return InteropPasskeyDemoBackend(
        interop = WebAuthnInteropKtorClient(
            httpClient = httpClient,
            endpointBase = config.endpointBase.normalizedEndpoint(),
            profile = WebAuthnBackendProfile.PASSKEY_ENCRYPTION_POC,
        ),
    )
}

internal suspend fun runRegisterCeremony(
    config: PasskeyDemoConfig,
    controller: PasskeyController,
    backend: PasskeyDemoBackend,
    diagnostics: PasskeyDemoDiagnostics = DefaultPasskeyDemoDiagnostics,
) {
    diagnostics.trace(
        event = "register.start",
        fields = mapOf(
            "endpoint" to config.endpointBase,
            "rpId" to config.rpId,
            "userName" to config.userName,
        ),
    )

    controller.register(
        getOptions = {
            runCatching { backend.startRegistration(config) }
                .onFailure { diagnostics.error("register.options.failure", it.message ?: "startRegistration failed", it) }
                .getOrThrow()
        },
        finish = { response, challenge ->
            val result = runCatching { backend.finishRegistration(config, response, challenge) }
                .onFailure { diagnostics.error("register.verify.failure", it.message ?: "finishRegistration failed", it) }
                .getOrThrow()
            if (result) {
                diagnostics.trace(event = "register.success")
            }
            result
        }
    )
}

internal suspend fun runSignInCeremony(
    config: PasskeyDemoConfig,
    controller: PasskeyController,
    backend: PasskeyDemoBackend,
    diagnostics: PasskeyDemoDiagnostics = DefaultPasskeyDemoDiagnostics,
) {
    diagnostics.trace(
        event = "auth.start",
        fields = mapOf(
            "endpoint" to config.endpointBase,
            "rpId" to config.rpId,
            "userHandle" to config.userHandle,
        ),
    )

    controller.signIn(
        getOptions = {
            runCatching { backend.startAuthentication(config) }
                .onFailure { diagnostics.error("auth.options.failure", it.message ?: "startAuthentication failed", it) }
                .getOrThrow()
        },
        finish = { response, challenge ->
            val result = runCatching { backend.finishAuthentication(config, response, challenge) }
                .onFailure { diagnostics.error("auth.verify.failure", it.message ?: "finishAuthentication failed", it) }
                .getOrThrow()
            if (result) {
                diagnostics.trace(event = "auth.success")
            }
            result
        }
    )
}

internal fun areCeremonyActionsEnabled(uiState: PasskeyControllerState): Boolean {
    return uiState !is PasskeyControllerState.InProgress
}

internal fun PasskeyControllerState.toStatusPresentation(): PasskeyDemoStatus {
    return when (this) {
        PasskeyControllerState.Idle -> PasskeyDemoStatus(
            tone = StatusTone.IDLE,
            headline = "Ready",
            detail = "Run Register or Sign In to exercise the E2E flow.",
        )

        is PasskeyControllerState.InProgress -> PasskeyDemoStatus(
            tone = StatusTone.WORKING,
            headline = when (action) {
                PasskeyAction.REGISTER -> "Register in progress"
                PasskeyAction.SIGN_IN -> "Sign In in progress"
            },
            detail = when (phase) {
                PasskeyPhase.STARTING -> "Preparing ceremony options from the backend."
                PasskeyPhase.PLATFORM_PROMPT -> "Waiting for passkey prompt interaction."
                PasskeyPhase.FINISHING -> "Finishing verification with the backend."
            },
        )

        is PasskeyControllerState.Success -> PasskeyDemoStatus(
            tone = StatusTone.SUCCESS,
            headline = when (action) {
                PasskeyAction.REGISTER -> "Register complete"
                PasskeyAction.SIGN_IN -> "Sign In complete"
            },
        )

        is PasskeyControllerState.Failure -> {
            val category = error.toCategory()
            PasskeyDemoStatus(
                tone = when (category) {
                    PasskeyDemoErrorCategory.USER_CANCELLED -> StatusTone.WARNING
                    else -> StatusTone.ERROR
                },
                headline = category.label,
                detail = "[${category.label}] ${error.message.withProviderDependencyHint()}",
            )
        }
    }
}

internal fun timelineEntryForTransition(
    previous: PasskeyControllerState,
    current: PasskeyControllerState,
    id: Long,
    timestamp: String,
): PasskeyDemoLogEntry? {
    return when (previous) {
        !is PasskeyControllerState.InProgress if current is PasskeyControllerState.InProgress -> {
            PasskeyDemoLogEntry(
                id = id,
                timestamp = timestamp,
                tone = StatusTone.WORKING,
                message = "${current.action.label()} started.",
            )
        }

        is PasskeyControllerState.InProgress if current is PasskeyControllerState.Success -> {
            PasskeyDemoLogEntry(
                id = id,
                timestamp = timestamp,
                tone = StatusTone.SUCCESS,
                message = "${current.action.label()} completed.",
            )
        }

        is PasskeyControllerState.InProgress if current is PasskeyControllerState.Failure -> {
            val category = current.error.toCategory()
            PasskeyDemoLogEntry(
                id = id,
                timestamp = timestamp,
                tone = if (category == PasskeyDemoErrorCategory.USER_CANCELLED) StatusTone.WARNING else StatusTone.ERROR,
                message = "[${category.label}] ${current.error.message.withProviderDependencyHint()}",
            )
        }

        else -> null
    }
}

private enum class PasskeyDemoErrorCategory(public val label: String) {
    INVALID_OPTIONS("Invalid Options"),
    USER_CANCELLED("User Cancelled"),
    PLATFORM("Platform"),
    TRANSPORT("Transport"),
}

private fun PasskeyClientError.toCategory(): PasskeyDemoErrorCategory {
    return when (this) {
        is PasskeyClientError.InvalidOptions -> PasskeyDemoErrorCategory.INVALID_OPTIONS
        is PasskeyClientError.UserCancelled -> PasskeyDemoErrorCategory.USER_CANCELLED
        is PasskeyClientError.Platform -> PasskeyDemoErrorCategory.PLATFORM
        is PasskeyClientError.Transport -> PasskeyDemoErrorCategory.TRANSPORT
    }
}

private fun PasskeyAction.label(): String {
    return when (this) {
        PasskeyAction.REGISTER -> "Register"
        PasskeyAction.SIGN_IN -> "Sign In"
    }
}

private fun String.normalizedEndpoint(): String {
    return trim().trimEnd('/')
}

private fun resolveDefaultRpId(endpointBase: String, configuredRpId: String): String {
    val candidate = configuredRpId.trim()
    val endpointHost = endpointBase.endpointHost()
    val shouldReplaceLocalhost =
        candidate.equals("localhost", ignoreCase = true) &&
            endpointHost != null &&
            endpointHost != "localhost" &&
            endpointHost != "127.0.0.1"
    return when {
        candidate.isNotEmpty() && !shouldReplaceLocalhost -> candidate
        endpointHost != null -> endpointHost
        candidate.isNotEmpty() -> candidate
        else -> "localhost"
    }
}

private fun resolveDefaultOrigin(rpId: String, configuredOrigin: String): String {
    val candidate = configuredOrigin.trim()
    if (
        candidate.isNotEmpty() &&
        !candidate.equals("https://localhost", ignoreCase = true)
    ) {
        return candidate
    }

    val normalizedRpId = rpId.trim()
    val derived = if (normalizedRpId.isNotEmpty()) "https://$normalizedRpId" else null
    return derived ?: candidate.ifEmpty { "https://localhost" }
}

private fun String.endpointHost(): String? {
    val trimmed = trim()
    if (trimmed.isEmpty()) return null

    val noScheme = trimmed.substringAfter("://", trimmed)
    val authority = noScheme
        .substringBefore('/')
        .substringBefore('?')
        .substringBefore('#')
    if (authority.isEmpty()) return null

    return authority.substringBefore(':').ifBlank { null }
}

private fun Throwable.toUnexpectedClientError(prefix: String): PasskeyClientError {
    val reason = message?.takeIf { it.isNotBlank() } ?: "Unexpected error"
    val message = "$prefix failed: ${reason.withProviderDependencyHint()}"
    val lowered = reason.lowercase()
    return when {
        lowered.contains("http") ||
            lowered.contains("network") ||
            lowered.contains("timeout") ||
            lowered.contains("connection") ||
            lowered.contains("resolve host") ||
            lowered.contains("cleartext") -> PasskeyClientError.Transport(message = message, cause = this)

        else -> PasskeyClientError.Platform(message = message, cause = this)
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
