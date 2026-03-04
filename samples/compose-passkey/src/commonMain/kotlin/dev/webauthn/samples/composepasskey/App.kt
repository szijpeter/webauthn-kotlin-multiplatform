package dev.webauthn.samples.composepasskey

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.compose.rememberPasskeyClient
import dev.webauthn.client.compose.rememberPasskeyController
import dev.webauthn.network.KtorPasskeyServerClient
import dev.webauthn.samples.composepasskey.model.PasskeyDemoLogEntry
import dev.webauthn.samples.composepasskey.model.StatusTone
import dev.webauthn.samples.composepasskey.ui.components.ActionsCard
import dev.webauthn.samples.composepasskey.ui.components.CapabilitiesCard
import dev.webauthn.samples.composepasskey.ui.components.Header
import dev.webauthn.samples.composepasskey.ui.components.TimelineCard
import dev.webauthn.samples.composepasskey.ui.theme.EditorialPalette
import dev.webauthn.samples.composepasskey.ui.theme.EditorialTypography
import kotlinx.coroutines.launch

private const val MAX_LOG_ENTRIES: Int = 40

@Composable
public fun App() {
    val httpClient = rememberPlatformHttpClient()
    val config = remember { PasskeyDemoConfig() }
    val serverClient = remember(httpClient, config.endpointBase) {
        KtorPasskeyServerClient(
            httpClient = httpClient,
            endpointBase = config.endpointBase.normalizedEndpoint(),
            backendContract = TempServerBackendContract(),
        )
    }

    val passkeyClient = rememberPasskeyClient()
    val passkeyController = rememberPasskeyController(
        serverClient = serverClient,
        passkeyClient = passkeyClient,
    )

    val diagnostics = remember { DefaultPasskeyDemoDiagnostics }
    val scope = rememberCoroutineScope()

    var capabilities by remember { mutableStateOf(PasskeyCapabilities()) }
    var logs by remember { mutableStateOf(emptyList<PasskeyDemoLogEntry>()) }
    var nextLogId by remember { mutableStateOf(1L) }
    var fallbackTick by remember { mutableStateOf(0L) }
    val uiState by passkeyController.uiState.collectAsState()
    var previousUiState by remember { mutableStateOf(passkeyController.uiState.value) }

    fun nextTimestamp(): String {
        fallbackTick += 1
        return "t+$fallbackTick" + "s"
    }

    fun appendLog(tone: StatusTone, message: String) {
        val entry = PasskeyDemoLogEntry(
            id = nextLogId,
            timestamp = nextTimestamp(),
            tone = tone,
            message = message,
        )
        nextLogId += 1
        logs = (listOf(entry) + logs).take(MAX_LOG_ENTRIES)
    }

    DisposableEffect(httpClient) {
        onDispose { httpClient.close() }
    }

    LaunchedEffect(passkeyClient) {
        runCatching { passkeyClient.capabilities() }
            .onSuccess { loaded ->
                capabilities = loaded
                appendLog(
                    tone = StatusTone.IDLE,
                    message = "Capabilities loaded: PRF=${loaded.supportsPrf}, LargeBlobRead=${loaded.supportsLargeBlobRead}, LargeBlobWrite=${loaded.supportsLargeBlobWrite}, SecurityKey=${loaded.supportsSecurityKey}",
                )
            }
            .onFailure { throwable ->
                capabilities = PasskeyCapabilities()
                diagnostics.error(
                    event = "capabilities.load.failure",
                    message = throwable.message ?: "Capabilities unavailable; using defaults",
                    throwable = throwable,
                )
                appendLog(
                    tone = StatusTone.WARNING,
                    message = "Capabilities unavailable, using safe defaults.",
                )
            }
    }

    LaunchedEffect(uiState) {
        val transitionEntry = timelineEntryForTransition(
            previous = previousUiState,
            current = uiState,
            id = nextLogId,
            timestamp = "pending",
        )
        if (transitionEntry != null) {
            nextLogId += 1
            logs = (listOf(transitionEntry.copy(timestamp = nextTimestamp())) + logs).take(MAX_LOG_ENTRIES)
        }
        previousUiState = uiState
    }

    val status = uiState.toStatusPresentation()
    val actionsEnabled = areCeremonyActionsEnabled(uiState)

    MaterialTheme(
        colorScheme = EditorialPalette,
        typography = EditorialTypography,
    ) {
        Surface(modifier = Modifier.fillMaxSize()) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 20.dp, vertical = 18.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp),
            ) {
                Header(status = status)

                CapabilitiesCard(
                    capabilities = capabilities,
                )

                ActionsCard(
                    actionsEnabled = actionsEnabled,
                    onRegister = {
                        scope.launch {
                            diagnostics.trace(
                                event = "register.start",
                                fields = mapOf(
                                    "endpoint" to config.endpointBase,
                                    "rpId" to config.rpId,
                                    "userName" to config.userName,
                                ),
                            )
                            passkeyController.register(config.toRegistrationStartPayload())
                        }
                    },
                    onSignIn = {
                        scope.launch {
                            diagnostics.trace(
                                event = "auth.start",
                                fields = mapOf(
                                    "endpoint" to config.endpointBase,
                                    "rpId" to config.rpId,
                                    "userHandle" to config.userHandle,
                                ),
                            )
                            passkeyController.signIn(config.toAuthenticationStartPayload())
                        }
                    },
                )

                TimelineCard(logs = logs)
                Spacer(modifier = Modifier.height(20.dp))
            }
        }
    }
}
