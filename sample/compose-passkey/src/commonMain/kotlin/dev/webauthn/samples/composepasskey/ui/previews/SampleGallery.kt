package dev.webauthn.samples.composepasskey.ui.previews

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.LayoutDirection
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

private const val GALLERY_STRESS_TEXT =
    "Avery Example [!! Lõñg ãccõüñt dîsplãy ñãmê fõr wräppîñg !!] שלום مرحبا"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SampleGallery(scenario: String = "auth", darkTheme: Boolean = isSystemInDarkTheme()) {
    val stressText = scenario == "long-text" || scenario == "rtl"
    val config = if (stressText) GalleryConfig.copy(userName = GALLERY_STRESS_TEXT) else GalleryConfig
    val density = LocalDensity.current
    val galleryDensity = if (scenario == "large-text") Density(density.density, fontScale = 2f) else density
    val direction = if (scenario == "rtl") LayoutDirection.Rtl else LocalLayoutDirection.current
    var showLogs by remember { mutableStateOf(scenario == "logs") }
    var plaintext by rememberSaveable { mutableStateOf(if (stressText) GALLERY_STRESS_TEXT else "The answer is 42") }
    PasskeyDemoTheme(darkTheme) {
        CompositionLocalProvider(LocalDensity provides galleryDensity, LocalLayoutDirection provides direction) {
            if (scenario in listOf("session", "encrypted", "unsupported", "prf-busy", "long-text", "rtl")) {
                MainScreen(
                    state = galleryMainState(scenario).copy(plaintext = plaintext, userName = config.userName),
                    config = config,
                    onShowLogs = { showLogs = true },
                    onSignInWithPrf = {}, onEncrypt = {}, onDecrypt = {}, onClearPrfSession = {},
                    onPlaintextChange = { plaintext = it }, onLogout = {},
                )
            } else {
                AuthScreen(
                    status = galleryStatus(scenario),
                    actionsEnabled = scenario != "busy",
                    canRegister = scenario != "success",
                    config = config, onShowLogs = { showLogs = true }, onRegister = {}, onSignIn = {},
                )
            }
            if (showLogs) {
                DebugLogSheet(GalleryLogs.asReversed(), rememberAdaptiveSheetState(skipPartiallyExpanded = true)) {
                    showLogs = false
                }
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
        "session", "long-text", "rtl" -> PrfCryptoDemoSessionState.SessionReady
        else -> PrfCryptoDemoSessionState.NoSession
    },
    decryptedText = if (scenario == "encrypted") "The answer is 42" else null,
    statusMessage = when (scenario) {
        "encrypted" -> "Decrypt succeeded."
        "session", "long-text", "rtl" -> "PRF session ready. Encrypt a message to try it out."
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
