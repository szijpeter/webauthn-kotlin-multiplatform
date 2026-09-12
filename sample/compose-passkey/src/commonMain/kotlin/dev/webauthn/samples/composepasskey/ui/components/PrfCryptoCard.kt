package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.DeleteOutline
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import dev.webauthn.samples.composepasskey.domain.model.PasskeyDemoStatus
import dev.webauthn.samples.composepasskey.domain.model.StatusTone
import dev.webauthn.samples.composepasskey.domain.prf.PrfCryptoDemoSessionState
import dev.webauthn.samples.composepasskey.ui.theme.DemoLayout

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
    DemoCard(modifier) {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                "PRF encryption",
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.semantics { heading() },
            )
            Text(
                "Derive a temporary AES-GCM key using the PRF extension.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        StatusCard(
            PasskeyDemoStatus(
                tone = if (!actionsEnabled) StatusTone.WORKING else StatusTone.IDLE,
                headline = if (!actionsEnabled) "Processing" else sessionState.label(),
                detail = if (!supportsPrf && !hasSession) {
                    "PRF is unavailable on this platform or provider. You can still use ordinary passkey sign-in."
                } else {
                    statusMessage
                },
            ),
        )
        DemoButton(
            label = "Sign In + PRF",
            icon = Icons.Rounded.Key,
            style = DemoButtonStyle.PRIMARY,
            onClick = onSignInWithPrf,
            enabled = actionsEnabled && supportsPrf,
            modifier = Modifier.fillMaxWidth().heightIn(min = DemoLayout.touchTarget),
        )
        MessageField(
            value = plaintext,
            onValueChange = onPlaintextChange,
            enabled = actionsEnabled && hasSession,
            hasSession = hasSession,
        )
        EncryptionActions(
            encryptEnabled = actionsEnabled && hasSession,
            decryptEnabled = actionsEnabled && hasCiphertext,
            onEncrypt = onEncrypt,
            onDecrypt = onDecrypt,
        )
        if (decryptedText != null) {
            SelectionContainer {
                StatusCard(PasskeyDemoStatus(StatusTone.SUCCESS, "Decrypted message", decryptedText))
            }
        }
        TextButton(
            onClick = onClearSession,
            colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
            enabled = actionsEnabled && hasSession,
            modifier = Modifier.heightIn(min = DemoLayout.touchTarget),
        ) {
            ButtonLabel("Clear encryption session", Icons.Rounded.DeleteOutline)
        }
        Text(
            "This demo keeps the salt and key in memory. Removing your passkey makes its encrypted data unrecoverable.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun EncryptionActions(
    encryptEnabled: Boolean,
    decryptEnabled: Boolean,
    onEncrypt: () -> Unit,
    onDecrypt: () -> Unit,
) {
    FlowRow(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(12.dp, Alignment.CenterHorizontally),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        EncryptionButton(
            label = "Encrypt",
            onClick = onEncrypt,
            enabled = encryptEnabled,
        )
        EncryptionButton(
            label = "Decrypt",
            onClick = onDecrypt,
            enabled = decryptEnabled,
        )
    }
}

@Composable
private fun EncryptionButton(label: String, onClick: () -> Unit, enabled: Boolean) {
    TextButton(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.heightIn(min = 32.dp),
        contentPadding = PaddingValues(horizontal = 14.dp, vertical = 6.dp),
        colors = ButtonDefaults.textButtonColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer,
            contentColor = MaterialTheme.colorScheme.onPrimaryContainer,
            disabledContainerColor = MaterialTheme.colorScheme.surfaceVariant,
        ),
    ) {
        Text(label)
    }
}

private fun PrfCryptoDemoSessionState.label(): String = when (this) {
    PrfCryptoDemoSessionState.NoSession -> "No encryption session"
    PrfCryptoDemoSessionState.SessionReady -> "Session ready"
    PrfCryptoDemoSessionState.CiphertextReady -> "Encrypted message ready"
}
