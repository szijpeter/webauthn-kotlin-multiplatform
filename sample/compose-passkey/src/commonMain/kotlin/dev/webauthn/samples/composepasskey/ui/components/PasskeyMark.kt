package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/** Decorative key mark; its adjacent heading supplies the accessible label. */
@Composable
internal fun PasskeyMark() {
    Icon(
        Icons.Rounded.Key,
        contentDescription = null,
        tint = MaterialTheme.colorScheme.primary,
        modifier = Modifier.size(28.dp),
    )
}
