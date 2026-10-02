package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
internal fun RestoreCredentialCard(
    modifier: Modifier = Modifier,
    available: Boolean,
    actionsEnabled: Boolean,
    statusMessage: String,
    onCreateRestoreCredential: () -> Unit,
    onGetRestoreCredential: () -> Unit,
    onClearRestoreCredential: () -> Unit,
) {
    ElevatedCard(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.elevatedCardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Text("Restore Credentials", style = MaterialTheme.typography.titleMedium)
            Text(
                text = if (available) {
                    "Android restore keys use the same sample server verification path as passkeys."
                } else {
                    "Restore Credentials are not available on this platform."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Button(
                    onClick = onCreateRestoreCredential,
                    enabled = actionsEnabled && available,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Create")
                }
                FilledTonalButton(
                    onClick = onGetRestoreCredential,
                    enabled = actionsEnabled && available,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Test")
                }
            }
            FilledTonalButton(
                onClick = onClearRestoreCredential,
                enabled = actionsEnabled && available,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Clear Restore Key")
            }
            Text(
                text = statusMessage,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
