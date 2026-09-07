package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import dev.webauthn.samples.composepasskey.ui.theme.DemoLayout

@Composable
internal fun Header(onShowLogs: (() -> Unit)? = null) {
    Row(
        modifier = Modifier.widthIn(max = DemoLayout.maxWidth).fillMaxWidth()
            .padding(horizontal = DemoLayout.contentPadding, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        PasskeyMark()
        Text("Passkey Lab", Modifier.weight(1f).semantics { heading() }, style = MaterialTheme.typography.titleMedium)
        if (onShowLogs != null) {
            TextButton(onClick = onShowLogs) { Text("Debug logs") }
        }
    }
}

@Composable
internal fun Intro(title: String, detail: String, eyebrow: String = "COMPOSE MULTIPLATFORM") {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(vertical = 8.dp)) {
        Text(eyebrow, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
        Text(title, style = MaterialTheme.typography.headlineLarge, modifier = Modifier.semantics { heading() })
        Text(detail, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
