package dev.webauthn.samples.composepasskey

import androidx.compose.runtime.Composable
import io.ktor.client.HttpClient

@Composable
expect fun rememberPlatformHttpClient(onLogLine: (String) -> Unit): HttpClient

expect fun platformRuntimeHint(): String?
