package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ExpandLess
import androidx.compose.material.icons.rounded.ExpandMore
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import dev.webauthn.samples.composepasskey.domain.passkey.PasskeyDemoConfig
import dev.webauthn.samples.composepasskey.ui.theme.DemoLayout

@Composable
internal fun ConfigurationCard(config: PasskeyDemoConfig, initiallyExpanded: Boolean = false) {
    var expanded by rememberSaveable { mutableStateOf(initiallyExpanded) }
    DemoCard {
        TextButton(
            onClick = { expanded = !expanded },
            modifier = Modifier.fillMaxWidth().heightIn(min = DemoLayout.touchTarget)
                .semantics { stateDescription = if (expanded) "Expanded" else "Collapsed" },
        ) {
            ButtonLabel("Configuration", Icons.Rounded.Settings)
            Spacer(Modifier.weight(1f))
            Icon(
                if (expanded) Icons.Rounded.ExpandLess else Icons.Rounded.ExpandMore,
                contentDescription = null,
                modifier = Modifier.size(20.dp),
            )
        }
        if (expanded) {
            ConfigurationValue("Endpoint", config.endpointBase)
            ConfigurationValue("Relying party", config.rpId)
            ConfigurationValue("Origin", config.origin)
            ConfigurationValue("User", config.userName)
        }
    }
}

@Composable
private fun ConfigurationValue(label: String, value: String) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        SelectionContainer { Text(value, style = MaterialTheme.typography.bodyMedium) }
    }
}
