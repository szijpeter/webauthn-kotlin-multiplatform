package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import dev.webauthn.samples.composepasskey.ui.theme.DemoLayout

@Composable
fun ActionsCard(actionsEnabled: Boolean, showRegister: Boolean = true, onRegister: () -> Unit, onSignIn: () -> Unit) {
    DemoCard {
        Text(
            "Welcome to Passkey Lab",
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.semantics { heading() },
        )
        Text(
            if (showRegister) {
                "New here? Register a passkey, then sign in to explore."
            } else {
                "Your passkey is ready. Sign in to continue."
            },
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (showRegister) {
            Button(
                onClick = onRegister,
                enabled = actionsEnabled,
                modifier = Modifier.fillMaxWidth().heightIn(min = DemoLayout.touchTarget),
            ) {
                Text("Register")
            }
            OutlinedButton(
                onClick = onSignIn,
                enabled = actionsEnabled,
                modifier = Modifier.fillMaxWidth().heightIn(min = DemoLayout.touchTarget),
            ) {
                Text("Sign In")
            }
        } else {
            Button(
                onClick = onSignIn,
                enabled = actionsEnabled,
                modifier = Modifier.fillMaxWidth().heightIn(min = DemoLayout.touchTarget),
            ) {
                Text("Sign In")
            }
        }
    }
}
