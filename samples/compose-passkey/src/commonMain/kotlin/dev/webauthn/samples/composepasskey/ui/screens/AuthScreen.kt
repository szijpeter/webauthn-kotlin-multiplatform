package dev.webauthn.samples.composepasskey.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import dev.webauthn.samples.composepasskey.model.PasskeyDemoStatus
import dev.webauthn.samples.composepasskey.ui.components.ActionsCard
import dev.webauthn.samples.composepasskey.ui.components.Header

@Composable
internal fun AuthScreen(
    status: PasskeyDemoStatus,
    actionsEnabled: Boolean,
    canRegister: Boolean,
    runtimeHint: String?,
    onShowLogs: () -> Unit,
    onRegister: () -> Unit,
    onSignIn: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 18.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Header(
            status = status,
            onShowLogs = onShowLogs,
        )

        if (status.detail != null) {
            Text(
                text = status.detail,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        if (runtimeHint != null) {
            Text(
                text = runtimeHint,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        ActionsCard(
            actionsEnabled = actionsEnabled,
            showRegister = canRegister,
            onRegister = onRegister,
            onSignIn = onSignIn,
        )

        Spacer(modifier = Modifier.height(20.dp))
    }
}
