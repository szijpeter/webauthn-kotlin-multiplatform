package dev.webauthn.samples.composepasskey

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import dev.webauthn.client.PasskeyCapabilities
import dev.webauthn.client.compose.rememberPasskeyClient
import dev.webauthn.client.compose.rememberPasskeyController
import kotlinx.coroutines.launch

private val EditorialPalette = lightColorScheme(
    primary = Color(0xFF1E4A68),
    onPrimary = Color(0xFFFFFFFF),
    secondary = Color(0xFF6D8A56),
    onSecondary = Color(0xFFFFFFFF),
    background = Color(0xFFF5F2EB),
    onBackground = Color(0xFF1F2327),
    surface = Color(0xFFFFFCF6),
    onSurface = Color(0xFF1F2327),
    surfaceVariant = Color(0xFFE8E2D8),
    onSurfaceVariant = Color(0xFF4D585F),
    error = Color(0xFFA3333D),
    onError = Color(0xFFFFFFFF),
)

private val EditorialTypography = Typography().run {
    copy(
        headlineLarge = headlineLarge.copy(
            fontFamily = FontFamily.Serif,
            fontWeight = FontWeight.SemiBold,
        ),
        headlineMedium = headlineMedium.copy(
            fontFamily = FontFamily.Serif,
            fontWeight = FontWeight.Medium,
        ),
        titleMedium = titleMedium.copy(fontWeight = FontWeight.SemiBold),
        bodySmall = bodySmall.copy(
            fontFamily = FontFamily.Monospace,
            fontSize = 12.sp,
        ),
    )
}

private const val MAX_LOG_ENTRIES: Int = 40

@Composable
public fun App() {
    val httpClient = rememberPlatformHttpClient()
    val config = remember { PasskeyDemoConfig() }
    val backend = remember(httpClient, config) { createPasskeyDemoBackend(httpClient, config) }
    
    val passkeyClient = rememberPasskeyClient()
    val passkeyController = rememberPasskeyController(
        serverClient = backend,
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
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .background(
                        Brush.verticalGradient(
                            colors = listOf(Color(0xFFF9F5EC), Color(0xFFEFE7DA)),
                        ),
                    ),
            ) {
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
                                runRegisterCeremony(
                                    config = config,
                                    controller = passkeyController,
                                    backend = backend,
                                    diagnostics = diagnostics,
                                )
                            }
                        },
                        onSignIn = {
                            scope.launch {
                                runSignInCeremony(
                                    config = config,
                                    controller = passkeyController,
                                    backend = backend,
                                    diagnostics = diagnostics,
                                )
                            }
                        },
                    )

                    TimelineCard(logs = logs)
                    Spacer(modifier = Modifier.height(20.dp))
                }
            }
        }
    }
}

@Composable
private fun Header(status: PasskeyDemoStatus) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    text = "WebAuthn Kotlin Demo",
                    style = MaterialTheme.typography.headlineLarge,
                    color = MaterialTheme.colorScheme.primary,
                )
            }
            StatusPill(status.tone, status.headline)
        }
    }
}

@Composable
private fun StatusPill(tone: StatusTone, text: String) {
    val targetColor = when (tone) {
        StatusTone.IDLE -> Color(0xFFC9D6E0)
        StatusTone.WORKING -> Color(0xFFE4C889)
        StatusTone.SUCCESS -> Color(0xFF97C38A)
        StatusTone.WARNING -> Color(0xFFDCA96F)
        StatusTone.ERROR -> Color(0xFFD2848C)
    }
    val backgroundColor by animateColorAsState(targetValue = targetColor, label = "status-color")

    Surface(
        modifier = Modifier.widthIn(max = 320.dp),
        shape = RoundedCornerShape(999.dp),
        color = backgroundColor,
    ) {
        AnimatedContent(targetState = text, label = "status-text") { label ->
            Text(
                text = label,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp),
                style = MaterialTheme.typography.bodySmall,
                color = Color(0xFF112433),
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

@Composable
private fun CapabilitiesCard(
    capabilities: PasskeyCapabilities,
) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text("Capabilities", style = MaterialTheme.typography.titleMedium)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                CapabilityChip("PRF", capabilities.supportsPrf)
                CapabilityChip("Large Blob Read", capabilities.supportsLargeBlobRead)
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                CapabilityChip("Large Blob Write", capabilities.supportsLargeBlobWrite)
                CapabilityChip("Security Key", capabilities.supportsSecurityKey)
            }
            Text(
                text = if (capabilities.platformVersionHints.isEmpty()) {
                    "No platform hints reported"
                } else {
                    capabilities.platformVersionHints.joinToString()
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun CapabilityChip(label: String, enabled: Boolean) {
    val color = if (enabled) Color(0xFF9BC08E) else Color(0xFFD4D9DD)
    Surface(
        shape = RoundedCornerShape(999.dp),
        color = color,
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(7.dp),
        ) {
            Box(
                modifier = Modifier
                    .size(7.dp)
                    .clip(CircleShape)
                    .background(if (enabled) Color(0xFF1B4D2C) else Color(0xFF5E6C77)),
            )
            Text(
                text = "$label: ${if (enabled) "yes" else "no"}",
                style = MaterialTheme.typography.bodySmall,
                color = Color(0xFF1B2C39),
            )
        }
    }
}

@Composable
private fun ActionsCard(
    actionsEnabled: Boolean,
    onRegister: () -> Unit,
    onSignIn: () -> Unit,
) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Button(
                onClick = onRegister,
                enabled = actionsEnabled,
                modifier = Modifier.weight(1f),
            ) {
                Text("Register")
            }
            FilledTonalButton(
                onClick = onSignIn,
                enabled = actionsEnabled,
                modifier = Modifier.weight(1f),
            ) {
                Text("Sign In")
            }
        }
    }
}

@Composable
private fun TimelineCard(logs: List<PasskeyDemoLogEntry>) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text("Timeline", style = MaterialTheme.typography.titleMedium)
            AnimatedContent(targetState = logs, label = "logs") { entries ->
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (entries.isEmpty()) {
                        Text(
                            text = "No events yet.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        entries.forEach { entry ->
                            val stripe = when (entry.tone) {
                                StatusTone.IDLE -> Color(0xFF94A3AF)
                                StatusTone.WORKING -> Color(0xFFCEA650)
                                StatusTone.SUCCESS -> Color(0xFF5A9E62)
                                StatusTone.WARNING -> Color(0xFFC4804A)
                                StatusTone.ERROR -> Color(0xFFB54F60)
                            }
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clip(RoundedCornerShape(10.dp))
                                    .background(MaterialTheme.colorScheme.surfaceVariant)
                                    .padding(10.dp),
                                horizontalArrangement = Arrangement.spacedBy(10.dp),
                                verticalAlignment = Alignment.Top,
                            ) {
                                Box(
                                    modifier = Modifier
                                        .size(width = 4.dp, height = 36.dp)
                                        .clip(RoundedCornerShape(4.dp))
                                        .background(stripe),
                                )
                                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                    Text(
                                        text = entry.timestamp,
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                    Text(
                                        text = entry.message,
                                        style = MaterialTheme.typography.bodyMedium,
                                        color = MaterialTheme.colorScheme.onSurface,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
