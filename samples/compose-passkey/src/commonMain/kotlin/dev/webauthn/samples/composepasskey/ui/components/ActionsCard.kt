package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.layout.Arrangement
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
fun ActionsCard(
    actionsEnabled: Boolean,
    showRegister: Boolean = true,
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
            if (showRegister) {
                Button(
                    onClick = onRegister,
                    enabled = actionsEnabled,
                    modifier = Modifier.weight(1f),
                ) {
                    Text("Register")
                }
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
