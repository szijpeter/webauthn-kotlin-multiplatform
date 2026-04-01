package dev.webauthn.samples.composepasskey.data.platform

import androidx.compose.runtime.Composable
import io.ktor.client.HttpClient

@Composable
expect fun rememberPlatformHttpClient(onLogLine: (String) -> Unit): HttpClient
