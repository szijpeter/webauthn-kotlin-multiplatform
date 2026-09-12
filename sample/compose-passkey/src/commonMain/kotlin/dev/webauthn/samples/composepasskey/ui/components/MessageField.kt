package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp

/** Uses the stable Foundation field; styling belongs to this sample's theme. */
@Composable
internal fun MessageField(value: String, onValueChange: (String) -> Unit, enabled: Boolean, hasSession: Boolean) {
    var focused by remember { mutableStateOf(false) }
    val focusManager = LocalFocusManager.current
    val colors = MaterialTheme.colorScheme
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Message to encrypt", style = MaterialTheme.typography.labelLarge, color = colors.onSurfaceVariant)
        Surface(
            color = colors.surfaceContainerLow,
            shape = MaterialTheme.shapes.small,
            border = BorderStroke(1.dp, if (focused) colors.primary else colors.outlineVariant),
        ) {
            BasicTextField(
                value = value,
                onValueChange = onValueChange,
                enabled = enabled,
                modifier = Modifier.fillMaxWidth().padding(16.dp)
                    .onFocusChanged { focused = it.isFocused }
                    .semantics { contentDescription = "Message to encrypt" },
                textStyle = MaterialTheme.typography.bodyLarge.copy(
                    color = if (enabled) colors.onSurface else colors.onSurfaceVariant,
                ),
                minLines = 2,
                maxLines = 5,
                cursorBrush = SolidColor(colors.primary),
                keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                keyboardActions = KeyboardActions(onDone = { focusManager.clearFocus() }),
            )
        }
        Text(
            if (hasSession) {
                "Your message stays in this sample session."
            } else {
                "Unlock a PRF session to start encrypting."
            },
            style = MaterialTheme.typography.bodySmall,
            color = colors.onSurfaceVariant,
        )
    }
}
