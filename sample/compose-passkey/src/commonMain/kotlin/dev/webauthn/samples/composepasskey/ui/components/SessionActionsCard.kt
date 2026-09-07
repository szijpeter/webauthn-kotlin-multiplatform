package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import dev.webauthn.samples.composepasskey.ui.theme.DemoLayout

@Composable
internal fun SessionActionsCard(busy: Boolean, onLogout: () -> Unit) {
    DemoCard {
        Text("Finish your session", style = MaterialTheme.typography.titleMedium)
        Text(
            "Signing out clears the in-memory encryption key. Your passkey stays on your device.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        OutlinedButton(
            onClick = onLogout,
            enabled = !busy,
            modifier = Modifier.fillMaxWidth().heightIn(min = DemoLayout.touchTarget),
        ) {
            Text("Sign Out")
        }
    }
}
