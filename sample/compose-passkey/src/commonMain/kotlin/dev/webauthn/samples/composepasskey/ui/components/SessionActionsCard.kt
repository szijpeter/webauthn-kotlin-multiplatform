package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.Logout
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

@Composable
internal fun SessionActionsCard(busy: Boolean, onLogout: () -> Unit) {
    DemoCard {
        Text("Session", style = MaterialTheme.typography.titleMedium)
        Text(
            "Signing out clears the in-memory encryption key. Your passkey stays on your device.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        DemoButton(
            label = "Sign Out",
            icon = Icons.AutoMirrored.Rounded.Logout,
            style = DemoButtonStyle.DESTRUCTIVE,
            onClick = onLogout,
            enabled = !busy,
            modifier = Modifier.fillMaxWidth(),
        )
    }
}
