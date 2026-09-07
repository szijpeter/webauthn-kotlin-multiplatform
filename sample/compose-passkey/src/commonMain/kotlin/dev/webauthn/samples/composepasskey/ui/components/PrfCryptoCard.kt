package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
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
                "Passkey-powered encryption",
                style = MaterialTheme.typography.titleLarge,
                modifier = Modifier.semantics { heading() },
            )
            Text(
                "Use the PRF extension to unlock a temporary AES-GCM key.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        StatusCard(
            PasskeyDemoStatus(
                tone = if (!actionsEnabled) StatusTone.WORKING else StatusTone.IDLE,
                headline = if (!actionsEnabled) "Working on your session" else sessionState.label(),
                detail = if (!supportsPrf && !hasSession) {
                    "PRF is unavailable on this platform or provider. You can still use ordinary passkey sign-in."
                } else {
                    statusMessage
                },
            ),
        )
        Button(
            onClick = onSignInWithPrf,
            enabled = actionsEnabled && supportsPrf,
            modifier = Modifier.fillMaxWidth().heightIn(min = DemoLayout.touchTarget),
        ) { Text("Sign In + PRF") }
        MessageField(
            value = plaintext,
            onValueChange = onPlaintextChange,
            enabled = actionsEnabled && hasSession,
            hasSession = hasSession,
        )
        FlowRow(horizontalArrangement = Arrangement.spacedBy(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick = onEncrypt,
                enabled = actionsEnabled && hasSession,
                modifier = Modifier.heightIn(min = DemoLayout.touchTarget),
            ) { Text("Encrypt") }
            OutlinedButton(
                onClick = onDecrypt,
                enabled = actionsEnabled && hasCiphertext,
                modifier = Modifier.heightIn(min = DemoLayout.touchTarget),
            ) { Text("Decrypt") }
        }
        if (decryptedText != null) {
            SelectionContainer {
                StatusCard(PasskeyDemoStatus(StatusTone.SUCCESS, "Decrypted message", decryptedText))
            }
        }
        TextButton(
            onClick = onClearSession,
            enabled = actionsEnabled && hasSession,
            modifier = Modifier.heightIn(min = DemoLayout.touchTarget),
        ) {
            Text("Clear encryption session")
        }
        Text(
            "This demo keeps the salt and key in memory. Removing your passkey makes its encrypted data unrecoverable.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

private fun PrfCryptoDemoSessionState.label(): String = when (this) {
    PrfCryptoDemoSessionState.NoSession -> "No encryption session"
    PrfCryptoDemoSessionState.SessionReady -> "Session ready"
    PrfCryptoDemoSessionState.CiphertextReady -> "Encrypted message ready"
}
