@file:Suppress("LongMethod", "MagicNumber", "MaxLineLength")

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
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.runtime.runSuspendCatching
import dev.webauthn.client.PasskeyControllerState
import dev.webauthn.client.compose.rememberPasskeyClient
import dev.webauthn.client.compose.rememberPasskeyController
import dev.webauthn.network.KtorPasskeyServerClient
import dev.webauthn.samples.composepasskey.model.DebugLogLevel
import dev.webauthn.samples.composepasskey.ui.components.ActionsCard
import dev.webauthn.samples.composepasskey.ui.components.CapabilitiesCard
import dev.webauthn.samples.composepasskey.ui.components.DebugLogCard
import dev.webauthn.samples.composepasskey.ui.components.Header
import dev.webauthn.samples.composepasskey.ui.components.PrfCryptoCard
import dev.webauthn.samples.composepasskey.ui.theme.EditorialPalette
import dev.webauthn.samples.composepasskey.ui.theme.EditorialTypography
import kotlinx.coroutines.launch

@Composable
public fun App() {
    val scope = rememberCoroutineScope()
    val debugLogs = remember { DebugLogStore() }
    val httpLogSink: (String) -> Unit = remember(scope, debugLogs) {
        { line ->
            scope.launch {
                debugLogs.d(source = "http", message = line)
            }
        }
    }
    val httpClient = rememberPlatformHttpClient(onLogLine = httpLogSink)
    val config = remember { PasskeyDemoConfig() }
    val serverClient = remember(httpClient, config.endpointBase) {
        KtorPasskeyServerClient(
            httpClient = httpClient,
            endpointBase = config.endpointBase.normalizedEndpoint(),
        )
    }

    val passkeyClient = rememberPasskeyClient()
    val passkeyController = rememberPasskeyController(
        serverClient = serverClient,
        passkeyClient = passkeyClient,
    )
    val prfSaltStore = remember { InMemoryPrfSaltStore() }
    val prfCryptoDemo = remember(passkeyClient, serverClient, prfSaltStore) {
        PrfCryptoDemoController(
            passkeyClient = passkeyClient,
            serverClient = serverClient,
            saltStore = prfSaltStore,
        )
    }

    val capabilities = remember { mutableStateOf(PasskeyCapabilities()) }
    val uiState by passkeyController.uiState.collectAsState()
    val previousUiState = remember { mutableStateOf(passkeyController.uiState.value) }
    val prfBusy = remember { mutableStateOf(false) }
    val prfPlaintext = remember { mutableStateOf("Top secret from passkey PRF") }
    val prfStatusMessage = remember { mutableStateOf("Run Sign In + PRF to derive an in-memory AES session key.") }
    val prfDecryptedText = remember { mutableStateOf<String?>(null) }

    DisposableEffect(httpClient) {
        debugLogs.i(source = "app", message = "App composition entered")
        onDispose {
            prfCryptoDemo.clearSession()
            httpClient.close()
        }
    }

    LaunchedEffect(Unit) {
        debugLogs.i(source = "app", message = "First render complete")
        debugLogs.i(
            source = "app",
            message = "Config endpoint=${config.endpointBase} rpId=${config.rpId} origin=${config.origin} user=${config.userName}",
        )
        platformRuntimeHint()?.let { hint ->
            debugLogs.w(source = "platform", message = hint)
        }
    }

    LaunchedEffect(passkeyClient) {
        debugLogs.i(source = "capabilities", message = "Loading capability hints")
        runSuspendCatching<PasskeyCapabilities>(passkeyClient::capabilities)
            .onSuccess { loaded ->
                capabilities.value = loaded
                debugLogs.i(
                    source = "capabilities",
                    message = "Loaded PRF=${loaded.supportsPrf} largeBlobRead=${loaded.supportsLargeBlobRead} largeBlobWrite=${loaded.supportsLargeBlobWrite} securityKey=${loaded.supportsSecurityKey}",
                )
            }
            .onFailure { throwable ->
                capabilities.value = PasskeyCapabilities()
                debugLogs.e(
                    source = "capabilities",
                    message = "Failed to load capabilities: ${throwable.message ?: "using defaults"}",
                    throwable = throwable,
                )
            }
    }

    LaunchedEffect(uiState) {
        val transition = controllerTransitionLog(
            previous = previousUiState.value,
            current = uiState,
        )
        if (transition != null) {
            when (transition.level) {
                DebugLogLevel.DEBUG -> debugLogs.d(source = "controller", message = transition.message)
                DebugLogLevel.INFO -> debugLogs.i(source = "controller", message = transition.message)
                DebugLogLevel.WARN -> debugLogs.w(source = "controller", message = transition.message)
                DebugLogLevel.ERROR -> debugLogs.e(source = "controller", message = transition.message)
            }
        }
        previousUiState.value = uiState
    }

    val status = uiState.toStatusPresentation()
    val actionsEnabled = areCeremonyActionsEnabled(uiState) && !prfBusy.value

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
                    capabilities = capabilities.value,
                )

                ActionsCard(
                    actionsEnabled = actionsEnabled,
                    onRegister = {
                        scope.launch {
                            debugLogs.i(
                                source = "action",
                                message = "Register tapped endpoint=${config.endpointBase} rpId=${config.rpId} user=${config.userName}",
                            )
                            passkeyController.register(config.toRegistrationStartPayload())
                        }
                    },
                    onSignIn = {
                        scope.launch {
                            debugLogs.i(
                                source = "action",
                                message = "Sign In tapped endpoint=${config.endpointBase} rpId=${config.rpId} userHandle=${config.userHandle}",
                            )
                            passkeyController.signIn(config.toAuthenticationStartPayload())
                        }
                    },
                )

                PrfCryptoCard(
                    supportsPrf = capabilities.value.supportsPrf,
                    actionsEnabled = actionsEnabled,
                    sessionState = prfCryptoDemo.sessionState,
                    plaintext = prfPlaintext.value,
                    decryptedText = prfDecryptedText.value,
                    statusMessage = prfStatusMessage.value,
                    onPlaintextChange = { prfPlaintext.value = it },
                    onSignInWithPrf = {
                        scope.launch {
                            prfBusy.value = true
                            try {
                                debugLogs.i(source = "prf", message = "Sign In + PRF tapped for ${config.userName}")
                                val result = prfCryptoDemo.signInWithPrf(
                                    config = config,
                                    supportsPrf = capabilities.value.supportsPrf,
                                )
                                when (result) {
                                    is PrfDemoResult.Success -> {
                                        prfStatusMessage.value = result.message
                                        prfDecryptedText.value = null
                                        debugLogs.i(source = "prf", message = result.message)
                                    }

                                    is PrfDemoResult.Failure -> {
                                        prfStatusMessage.value = result.message
                                        prfDecryptedText.value = null
                                        debugLogs.w(source = "prf", message = result.message)
                                    }
                                }
                            } finally {
                                prfBusy.value = false
                            }
                        }
                    },
                    onEncrypt = {
                        scope.launch {
                            prfBusy.value = true
                            try {
                                val result = prfCryptoDemo.encrypt(prfPlaintext.value)
                                when (result) {
                                    is PrfDemoResult.Success -> {
                                        prfStatusMessage.value = result.message
                                        prfDecryptedText.value = null
                                        debugLogs.i(source = "prf", message = result.message)
                                    }

                                    is PrfDemoResult.Failure -> {
                                        prfStatusMessage.value = result.message
                                        debugLogs.w(source = "prf", message = result.message)
                                    }
                                }
                            } finally {
                                prfBusy.value = false
                            }
                        }
                    },
                    onDecrypt = {
                        scope.launch {
                            prfBusy.value = true
                            try {
                                val result = prfCryptoDemo.decrypt()
                                when (result) {
                                    is PrfDemoResult.Success -> {
                                        prfStatusMessage.value = result.message
                                        prfDecryptedText.value = result.plaintext
                                        debugLogs.i(source = "prf", message = result.message)
                                    }

                                    is PrfDemoResult.Failure -> {
                                        prfStatusMessage.value = result.message
                                        debugLogs.w(source = "prf", message = result.message)
                                    }
                                }
                            } finally {
                                prfBusy.value = false
                            }
                        }
                    },
                    onClearSession = {
                        val result = prfCryptoDemo.clearSession()
                        when (result) {
                            is PrfDemoResult.Success -> {
                                prfStatusMessage.value = result.message
                                prfDecryptedText.value = null
                                debugLogs.i(source = "prf", message = result.message)
                            }

                            is PrfDemoResult.Failure -> {
                                prfStatusMessage.value = result.message
                                debugLogs.w(source = "prf", message = result.message)
                            }
                        }
                    },
                )

                DebugLogCard(entries = debugLogs.entries)
                Spacer(modifier = Modifier.height(20.dp))
            }
        }
    }
}
