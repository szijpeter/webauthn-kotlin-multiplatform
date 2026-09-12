package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.Login
import androidx.compose.material.icons.rounded.PersonAdd
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics

@Composable
fun ActionsCard(actionsEnabled: Boolean, showRegister: Boolean = true, onRegister: () -> Unit, onSignIn: () -> Unit) {
    DemoCard {
        Text(
            "Passkey actions",
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.semantics { heading() },
        )
        Text(
            if (showRegister) {
                "Registration creates a passkey for the configured user."
            } else {
                "Sign in with an existing passkey."
            },
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (showRegister) {
            DemoButton(
                label = "Register",
                icon = Icons.Rounded.PersonAdd,
                onClick = onRegister,
                enabled = actionsEnabled,
                modifier = Modifier.fillMaxWidth(),
                style = DemoButtonStyle.PRIMARY,
            )
        }
        DemoButton(
            label = "Sign In",
            icon = Icons.AutoMirrored.Rounded.Login,
            onClick = onSignIn,
            enabled = actionsEnabled,
            modifier = Modifier.fillMaxWidth(),
            style = if (showRegister) DemoButtonStyle.TINTED else DemoButtonStyle.PRIMARY,
        )
    }
}
