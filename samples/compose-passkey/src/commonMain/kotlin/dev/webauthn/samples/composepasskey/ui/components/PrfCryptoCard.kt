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
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.webauthn.samples.composepasskey.PrfCryptoDemoSessionState

@Composable
fun PrfCryptoCard(
    modifier: Modifier = Modifier,
    supportsPrf: Boolean,
    actionsEnabled: Boolean,
    sessionState: PrfCryptoDemoSessionState,
    plaintext: String,
    decryptedText: String?,
    statusMessage: String,
    onPlaintextChange: (String) -> Unit,
    onSignInWithPrf: () -> Unit,
    onEncrypt: () -> Unit,
    onDecrypt: () -> Unit,
    onClearSession: () -> Unit,
) {
    val hasSession = sessionState != PrfCryptoDemoSessionState.NoSession
    val hasCiphertext = sessionState == PrfCryptoDemoSessionState.CiphertextReady

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
            PrfCryptoHeader(supportsPrf = supportsPrf)
            PrfCryptoActions(
                actionsEnabled = actionsEnabled,
                supportsPrf = supportsPrf,
                hasSession = hasSession,
                onSignInWithPrf = onSignInWithPrf,
                onClearSession = onClearSession,
            )
            PrfCryptoInput(
                plaintext = plaintext,
                onPlaintextChange = onPlaintextChange,
                actionsEnabled = actionsEnabled,
                hasSession = hasSession,
                hasCiphertext = hasCiphertext,
                onEncrypt = onEncrypt,
                onDecrypt = onDecrypt,
            )
            PrfCryptoStatus(
                statusMessage = statusMessage,
                decryptedText = decryptedText,
            )
        }
    }
}

@Composable
private fun PrfCryptoHeader(supportsPrf: Boolean) {
    Text("PRF Crypto Demo", style = MaterialTheme.typography.titleMedium)
    Text(
        text = "Caller-owned salt is stored in sample-local memory. " +
            "If the passkey is removed, encrypted data becomes unrecoverable.",
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    Text(
        text = if (supportsPrf) {
            "Device reports PRF support."
        } else {
            "Device does not report PRF support."
        },
        style = MaterialTheme.typography.bodySmall,
        color = if (supportsPrf) {
            MaterialTheme.colorScheme.tertiary
        } else {
            MaterialTheme.colorScheme.error
        },
    )
}

@Composable
private fun PrfCryptoActions(
    actionsEnabled: Boolean,
    supportsPrf: Boolean,
    hasSession: Boolean,
    onSignInWithPrf: () -> Unit,
    onClearSession: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Button(
            onClick = onSignInWithPrf,
            enabled = actionsEnabled && supportsPrf,
            modifier = Modifier.weight(1f),
        ) {
            Text("Sign In + PRF")
        }
        FilledTonalButton(
            onClick = onClearSession,
            enabled = actionsEnabled && hasSession,
            modifier = Modifier.weight(1f),
        ) {
            Text("Clear Session")
        }
    }
}

@Composable
private fun PrfCryptoInput(
    plaintext: String,
    onPlaintextChange: (String) -> Unit,
    actionsEnabled: Boolean,
    hasSession: Boolean,
    hasCiphertext: Boolean,
    onEncrypt: () -> Unit,
    onDecrypt: () -> Unit,
) {
    OutlinedTextField(
        value = plaintext,
        onValueChange = onPlaintextChange,
        modifier = Modifier.fillMaxWidth(),
        label = { Text("Plaintext") },
        singleLine = true,
        enabled = actionsEnabled && hasSession,
    )

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Button(
            onClick = onEncrypt,
            enabled = actionsEnabled && hasSession,
            modifier = Modifier.weight(1f),
        ) {
            Text("Encrypt")
        }
        FilledTonalButton(
            onClick = onDecrypt,
            enabled = actionsEnabled && hasSession && hasCiphertext,
            modifier = Modifier.weight(1f),
        ) {
            Text("Decrypt")
        }
    }
}

@Composable
private fun PrfCryptoStatus(
    statusMessage: String,
    decryptedText: String?,
) {
    Text(
        text = statusMessage,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
    if (decryptedText != null) {
        Text(
            text = "Decrypted: $decryptedText",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}
