package dev.webauthn.samples.composepasskey.app

import androidx.compose.runtime.Composable

@Composable
internal expect fun AppVisibilityEffect(
    onForeground: () -> Unit,
    onBackground: () -> Unit,
    onHostDisposed: () -> Unit,
)
