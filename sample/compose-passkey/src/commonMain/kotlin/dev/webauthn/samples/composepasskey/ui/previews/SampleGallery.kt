package dev.webauthn.samples.composepasskey.ui.previews

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import com.mohamedrejeb.calf.ui.sheet.rememberAdaptiveSheetState
import dev.webauthn.client.CapabilitySupport
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.PasskeyCapability
import dev.webauthn.client.PasskeyClientError
import dev.webauthn.client.PasskeyPhase
import dev.webauthn.client.PlatformCapability
import dev.webauthn.model.WebAuthnExtension
import dev.webauthn.samples.composepasskey.domain.model.DebugLogEntry
import dev.webauthn.samples.composepasskey.domain.model.DebugLogLevel
import dev.webauthn.samples.composepasskey.domain.model.PasskeyDemoStatus
import dev.webauthn.samples.composepasskey.domain.passkey.DemoCeremonyError
import dev.webauthn.samples.composepasskey.domain.passkey.DemoCeremonyState
import dev.webauthn.samples.composepasskey.domain.passkey.DemoPasskeyAction
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.domain.passkey.toDemoStatus
import dev.webauthn.samples.composepasskey.domain.prf.PrfCryptoDemoSessionState
import dev.webauthn.samples.composepasskey.ui.components.DebugLogSheet
import dev.webauthn.samples.composepasskey.ui.screens.auth.AuthScreen
import dev.webauthn.samples.composepasskey.ui.screens.main.MainScreen
import dev.webauthn.samples.composepasskey.ui.screens.main.MainUiState
import dev.webauthn.samples.composepasskey.ui.theme.PasskeyDemoTheme
import kotlin.time.Instant

// Rendering fixtures only. No DI, network, passkey client, session store, or crypto session.
internal val GalleryConfig = PasskeyDemoConfig(
    endpointBase = "https://passkeys.example.test",
    rpId = "passkeys.example.test",
    origin = "https://passkeys.example.test",
    userHandle = "gallery-user",
    userName = "Avery Example",
)

internal val GalleryLogs = listOf(
    DebugLogEntry(1, Instant.parse("2026-09-04T09:41:00Z"), DebugLogLevel.INFO, "action", "Sign In tapped"),
    DebugLogEntry(2, Instant.parse("2026-09-04T09:41:01Z"), DebugLogLevel.INFO, "flow", "Sign In platform_prompt"),
    DebugLogEntry(
        3,
        Instant.parse("2026-09-04T09:41:02Z"),
        DebugLogLevel.INFO,
        "http",
        "POST /webauthn/authentication/finish: 200 OK",
    ),
    DebugLogEntry(4, Instant.parse("2026-09-04T09:41:02Z"), DebugLogLevel.INFO, "flow", "Sign In success"),
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SampleGallery(scenario: String = "auth", darkTheme: Boolean = isSystemInDarkTheme()) {
    var showLogs by remember { mutableStateOf(scenario == "logs") }
    var plaintext by rememberSaveable { mutableStateOf("The answer is 42") }
    PasskeyDemoTheme(darkTheme) {
        if (scenario in listOf("session", "encrypted", "unsupported", "prf-busy")) {
            MainScreen(
                state = galleryMainState(scenario).copy(plaintext = plaintext),
                config = GalleryConfig,
                onShowLogs = { showLogs = true },
                onSignInWithPrf = {}, onEncrypt = {}, onDecrypt = {}, onClearPrfSession = {},
                onPlaintextChange = { plaintext = it }, onLogout = {},
            )
        } else {
            AuthScreen(
                status = galleryStatus(scenario),
                actionsEnabled = scenario != "busy",
                canRegister = scenario != "success",
                config = GalleryConfig, onShowLogs = { showLogs = true }, onRegister = {}, onSignIn = {},
            )
        }
        if (showLogs) {
            DebugLogSheet(GalleryLogs.asReversed(), rememberAdaptiveSheetState(skipPartiallyExpanded = true)) {
                showLogs = false
            }
        }
    }
}

internal fun galleryMainState(scenario: String) = MainUiState(
    userName = GalleryConfig.userName,
    capabilities = PasskeyCapabilities(
        support = mapOf(
            PasskeyCapability.Extension(WebAuthnExtension.Prf) to if (scenario == "unsupported") {
                CapabilitySupport.UNSUPPORTED
            } else {
                CapabilitySupport.SUPPORTED
            },
            PasskeyCapability.Extension(WebAuthnExtension.LargeBlob) to CapabilitySupport.UNKNOWN,
            PasskeyCapability.Platform(PlatformCapability.SecurityKey) to CapabilitySupport.SUPPORTED,
        ),
    ),
    supportsPrf = scenario != "unsupported",
    busy = scenario == "prf-busy",
    sessionState = when (scenario) {
        "encrypted" -> PrfCryptoDemoSessionState.CiphertextReady
        "session" -> PrfCryptoDemoSessionState.SessionReady
        else -> PrfCryptoDemoSessionState.NoSession
    },
    decryptedText = if (scenario == "encrypted") "The answer is 42" else null,
    statusMessage = when (scenario) {
        "encrypted" -> "Decrypt succeeded."
        "session" -> "PRF session ready. Encrypt a message to try it out."
        "prf-busy" -> "Complete the passkey prompt to unlock your encryption key."
        else -> "Run Sign In + PRF to derive an in-memory AES session key."
    },
)

internal fun galleryStatus(scenario: String): PasskeyDemoStatus = when (scenario) {
    "busy" -> DemoCeremonyState.InProgress(DemoPasskeyAction.SIGN_IN, PasskeyPhase.PLATFORM_PROMPT).toDemoStatus()
    "success" -> DemoCeremonyState.Success(DemoPasskeyAction.REGISTER).toDemoStatus()
    "cancelled" -> DemoCeremonyState.Failure(
        DemoPasskeyAction.SIGN_IN,
        DemoCeremonyError.Platform(
            PasskeyClientError.UserCancelled("Nothing was changed. Sign in again when you're ready."),
        ),
    ).toDemoStatus()
    "rejected" -> DemoCeremonyState.Failure(
        DemoPasskeyAction.SIGN_IN,
        DemoCeremonyError.Rejected("The server could not verify this passkey response. Try signing in again."),
    ).toDemoStatus()
    "error" -> DemoCeremonyState.Failure(
        DemoPasskeyAction.SIGN_IN,
        DemoCeremonyError.Backend("Check your connection and the configured endpoint, then try again."),
    ).toDemoStatus()
    else -> DemoCeremonyState.Idle.toDemoStatus()
}
