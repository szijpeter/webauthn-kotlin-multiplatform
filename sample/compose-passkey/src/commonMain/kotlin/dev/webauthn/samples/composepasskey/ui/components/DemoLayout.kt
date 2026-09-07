package dev.webauthn.samples.composepasskey.ui.components

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Dp
import dev.webauthn.samples.composepasskey.ui.theme.DemoLayout

@Composable
internal fun DemoCard(modifier: Modifier = Modifier, content: @Composable ColumnScope.() -> Unit) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        color = MaterialTheme.colorScheme.surface,
        border = BorderStroke(Dp.Hairline, MaterialTheme.colorScheme.outlineVariant),
    ) {
        Column(
            modifier = Modifier.padding(DemoLayout.contentPadding),
            verticalArrangement = Arrangement.spacedBy(DemoLayout.spacing),
            content = content,
        )
    }
}

@Composable
internal fun DemoScreen(onShowLogs: () -> Unit, content: @Composable ColumnScope.() -> Unit) {
    Surface(color = MaterialTheme.colorScheme.background) {
        Column(Modifier.fillMaxSize().safeDrawingPadding().imePadding()) {
            Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                Header(onShowLogs = onShowLogs)
            }
            Column(
                modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Column(
                    modifier = Modifier.widthIn(max = DemoLayout.maxWidth).fillMaxWidth()
                        .padding(DemoLayout.contentPadding),
                    verticalArrangement = Arrangement.spacedBy(DemoLayout.spacing),
                    content = content,
                )
            }
        }
    }
}

@Composable
internal fun AdaptivePanels(primary: @Composable () -> Unit, secondary: @Composable () -> Unit) {
    val fontScale = LocalDensity.current.fontScale
    BoxWithConstraints(Modifier.fillMaxWidth()) {
        if (maxWidth >= DemoLayout.wideBreakpoint * fontScale) {
            Row(horizontalArrangement = Arrangement.spacedBy(DemoLayout.contentPadding)) {
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(DemoLayout.spacing)) {
                    primary()
                }
                Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(DemoLayout.spacing)) {
                    secondary()
                }
            }
        } else {
            Column(verticalArrangement = Arrangement.spacedBy(DemoLayout.spacing)) {
                primary()
                secondary()
            }
        }
    }
}
