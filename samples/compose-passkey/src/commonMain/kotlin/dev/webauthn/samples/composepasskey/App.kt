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
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.Typography
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
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

@Composable
public fun App() {
    val passkeyClient = rememberPlatformPasskeyClient()
    val httpClient = rememberPlatformHttpClient()
    val diagnostics = remember { DefaultPasskeyDemoDiagnostics }
    DisposableEffect(httpClient) {
        onDispose { httpClient.close() }
    }

    val gateway = remember(passkeyClient, httpClient, diagnostics) {
        DefaultPasskeyDemoGateway(passkeyClient, httpClient, diagnostics)
    }
    val controller = remember(gateway, diagnostics) { PasskeyDemoController(gateway, diagnostics = diagnostics) }
    val state by controller.state.collectAsState()
    val scope = rememberCoroutineScope()

    LaunchedEffect(controller) {
        controller.bootstrap()
    }

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
                    Header(state = state)

                    EndpointCard(
                        state = state,
                        dispatch = { intent -> scope.launch { controller.dispatch(intent) } },
                    )

                    CapabilitiesCard(state = state)

                    ActionsCard(
                        busy = state.isBusy,
                        dispatch = { intent -> scope.launch { controller.dispatch(intent) } },
                    )

                    TimelineCard(logs = state.logs)
                    Spacer(modifier = Modifier.height(20.dp))
                }
            }
        }
    }
}

@Composable
private fun Header(state: PasskeyDemoUiState) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.Start,
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        text = "Client Readiness",
                        style = MaterialTheme.typography.headlineLarge,
                        color = MaterialTheme.colorScheme.primary,
                    )
                    Text(
                        text = "Compose Multiplatform sample against temp.server",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            StatusPill(state.statusTone, state.statusHeadline)
            state.statusDetail?.let { detail ->
                Surface(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(10.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant,
                ) {
                    Text(
                        text = detail,
                        modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 4,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            HorizontalDivider(color = MaterialTheme.colorScheme.surfaceVariant)
            Text(
                text = "Lean flow: check health, register passkey, then sign in.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
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
private fun EndpointCard(
    state: PasskeyDemoUiState,
    dispatch: (PasskeyDemoIntent) -> Unit,
) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text("Endpoint Configuration", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(
                modifier = Modifier.fillMaxWidth(),
                value = state.config.endpointBase,
                onValueChange = { dispatch(PasskeyDemoIntent.EndpointBaseChanged(it)) },
                label = { Text("endpointBase") },
                singleLine = true,
                enabled = !state.isBusy,
            )
            OutlinedTextField(
                modifier = Modifier.fillMaxWidth(),
                value = state.config.rpId,
                onValueChange = { dispatch(PasskeyDemoIntent.RpIdChanged(it)) },
                label = { Text("rpId") },
                singleLine = true,
                enabled = !state.isBusy,
            )
            OutlinedTextField(
                modifier = Modifier.fillMaxWidth(),
                value = state.config.origin,
                onValueChange = { dispatch(PasskeyDemoIntent.OriginChanged(it)) },
                label = { Text("origin") },
                singleLine = true,
                enabled = !state.isBusy,
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                OutlinedTextField(
                    modifier = Modifier.weight(1f),
                    value = state.config.userHandle,
                    onValueChange = { dispatch(PasskeyDemoIntent.UserHandleChanged(it)) },
                    label = { Text("userHandle") },
                    singleLine = true,
                    enabled = !state.isBusy,
                )
                OutlinedTextField(
                    modifier = Modifier.weight(1f),
                    value = state.config.userName,
                    onValueChange = { dispatch(PasskeyDemoIntent.UserNameChanged(it)) },
                    label = { Text("userName") },
                    singleLine = true,
                    enabled = !state.isBusy,
                )
            }
        }
    }
}

@Composable
private fun CapabilitiesCard(state: PasskeyDemoUiState) {
    ElevatedCard(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text("Runtime Capabilities", style = MaterialTheme.typography.titleMedium)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                CapabilityChip("PRF", state.capabilities.supportsPrf)
                CapabilityChip("Large Blob Read", state.capabilities.supportsLargeBlobRead)
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                CapabilityChip("Large Blob Write", state.capabilities.supportsLargeBlobWrite)
                CapabilityChip("Security Key", state.capabilities.supportsSecurityKey)
            }
            Text(
                text = if (state.capabilities.platformVersionHints.isEmpty()) {
                    "No platform hints reported"
                } else {
                    state.capabilities.platformVersionHints.joinToString()
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
    busy: Boolean,
    dispatch: (PasskeyDemoIntent) -> Unit,
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
                onClick = { dispatch(PasskeyDemoIntent.CheckHealth) },
                enabled = !busy,
                modifier = Modifier.weight(1f),
            ) {
                Text("Check Health")
            }
            FilledTonalButton(
                onClick = { dispatch(PasskeyDemoIntent.Register) },
                enabled = !busy,
                modifier = Modifier.weight(1f),
            ) {
                Text("Register")
            }
            FilledTonalButton(
                onClick = { dispatch(PasskeyDemoIntent.SignIn) },
                enabled = !busy,
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
                            text = "No actions yet. Run a check or ceremony.",
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
